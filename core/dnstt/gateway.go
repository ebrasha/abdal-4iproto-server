/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : gateway.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Operational DNS tunneling gateway for Abdal proprietary clients
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package dnstt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	mathrand "math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"Abdal_4iProto_Server/core/config"
	"Abdal_4iProto_Server/core/logging"
	"Abdal_4iProto_Server/core/security"

	"github.com/miekg/dns"
)

const (
	dnsttTypeOpen  = 0x01
	dnsttTypeData  = 0x02
	dnsttTypePoll  = 0x03
	dnsttTypeClose = 0x04

	dnsttStatusOK        = 0x00
	dnsttStatusNoSession = 0x01
	dnsttStatusAuthFail  = 0x02
	dnsttStatusError     = 0x03
	dnsttStatusClosed    = 0x04

	dnsttUpHeaderLen   = 17
	dnsttDownHeaderLen = 15

	dnsttMaxUpPayload     = 100
	dnsttMaxDownPayload   = 180
	dnsttMaxPendingChunks = 1024
	dnsttRetransmit       = 2 * time.Second
	dnsttEDNSUDPSize      = 1232
	dnsttAuthTagLen       = 8
)

type dnsttDownChunk struct {
	seq    uint32
	data   []byte
	sent   bool
	sentAt time.Time
}

type dnsttSession struct {
	id       uint32
	ip       string
	backend  int
	tcpConn  net.Conn
	created  time.Time
	lastSeen atomic.Int64

	mu         sync.Mutex
	upExpected uint32
	upBuffer   map[uint32][]byte
	downChunks []*dnsttDownChunk
	downNext   uint32
	closed     bool
}

type upMsg struct {
	typ     byte
	sid     uint32
	seq     uint32
	ack     uint32
	nonce   uint16
	payload []byte
}

// Gateway handles DNS tunneling for proprietary Abdal clients.
type Gateway struct {
	listenAddr       string
	resolver         string
	nameserver       string
	psk              string
	maxSessionsPerIP int
	idleTimeout      time.Duration
	ttl              uint32
	serverPorts      []int
	guard            *security.Guard

	sessions   map[uint32]*dnsttSession
	sessionsMu sync.RWMutex

	udpServer *dns.Server
	tcpServer *dns.Server
	stopChan  chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
}

// NewGateway creates a new DNSTT gateway from server configuration.
func NewGateway(cfg config.ServerConfig, guard *security.Guard) *Gateway {
	idle := time.Duration(cfg.DNSTTIdleTimeoutSec) * time.Second
	if idle <= 0 {
		idle = 60 * time.Second
	}
	return &Gateway{
		listenAddr:       cfg.DNSTTListen,
		resolver:         cfg.DNSTTResolver,
		nameserver:       strings.ToLower(strings.TrimSuffix(cfg.DNSTTNameserver, ".")),
		psk:              cfg.DNSTTPSK,
		maxSessionsPerIP: cfg.DNSTTMaxSessionsPerIP,
		idleTimeout:      idle,
		ttl:              0,
		serverPorts:      cfg.Ports,
		guard:            guard,
		sessions:         make(map[uint32]*dnsttSession),
		stopChan:         make(chan struct{}),
	}
}

func (gw *Gateway) getRandomServerPort() int {
	if len(gw.serverPorts) == 0 {
		return 0
	}
	return gw.serverPorts[mathrand.Intn(len(gw.serverPorts))]
}

func (gw *Gateway) expectedAuthTag(sid uint32) []byte {
	var sidBytes [4]byte
	binary.BigEndian.PutUint32(sidBytes[:], sid)
	mac := hmac.New(sha256.New, []byte(gw.psk))
	mac.Write(sidBytes[:])
	sum := mac.Sum(nil)
	return sum[:dnsttAuthTagLen]
}

func decodeQName(name, domain string) ([]byte, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == domain {
		return []byte{}, true
	}
	suffix := "." + domain
	if !strings.HasSuffix(name, suffix) {
		return nil, false
	}
	prefix := name[:len(name)-len(suffix)]
	prefix = strings.ReplaceAll(prefix, ".", "")
	if prefix == "" {
		return []byte{}, true
	}
	dec := base32.StdEncoding.WithPadding(base32.NoPadding)
	data, err := dec.DecodeString(strings.ToUpper(prefix))
	if err != nil {
		return []byte{}, true
	}
	return data, true
}

func parseUpstream(raw []byte) (*upMsg, error) {
	if len(raw) < dnsttUpHeaderLen {
		return nil, fmt.Errorf("short message")
	}
	m := &upMsg{
		typ:   raw[0],
		sid:   binary.BigEndian.Uint32(raw[1:5]),
		seq:   binary.BigEndian.Uint32(raw[5:9]),
		ack:   binary.BigEndian.Uint32(raw[9:13]),
		nonce: binary.BigEndian.Uint16(raw[13:15]),
	}
	n := int(binary.BigEndian.Uint16(raw[15:17]))
	if n > len(raw)-dnsttUpHeaderLen {
		return nil, fmt.Errorf("bad length")
	}
	if n > 0 {
		m.payload = raw[dnsttUpHeaderLen : dnsttUpHeaderLen+n]
	}
	return m, nil
}

func buildDownstream(status byte, sid, ack, dataSeq uint32, data []byte) []byte {
	b := make([]byte, dnsttDownHeaderLen+len(data))
	b[0] = status
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint32(b[5:9], ack)
	binary.BigEndian.PutUint32(b[9:13], dataSeq)
	binary.BigEndian.PutUint16(b[13:15], uint16(len(data)))
	copy(b[dnsttDownHeaderLen:], data)
	return b
}

func splitTXT(s string) []string {
	const maxLen = 255
	if len(s) <= maxLen {
		return []string{s}
	}
	var out []string
	for len(s) > maxLen {
		out = append(out, s[:maxLen])
		s = s[maxLen:]
	}
	if len(s) > 0 {
		out = append(out, s)
	}
	return out
}

func (gw *Gateway) respond(w dns.ResponseWriter, r *dns.Msg, payload []byte) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	if r.IsEdns0() != nil {
		m.SetEdns0(dnsttEDNSUDPSize, false)
	}
	encoded := base64.StdEncoding.EncodeToString(payload)
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    gw.ttl,
		},
		Txt: splitTXT(encoded),
	}
	m.Answer = append(m.Answer, txt)
	_ = w.WriteMsg(m)
}

func (gw *Gateway) respondEmpty(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	_ = w.WriteMsg(m)
}

func (gw *Gateway) handleDNSTTQuery(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	raw, ours := decodeQName(r.Question[0].Name, gw.nameserver)
	if !ours {
		return
	}
	m, err := parseUpstream(raw)
	if err != nil {
		gw.respondEmpty(w, r)
		return
	}
	switch m.typ {
	case dnsttTypeOpen:
		gw.handleOpen(w, r, m)
	case dnsttTypeData, dnsttTypePoll:
		gw.handleData(w, r, m)
	case dnsttTypeClose:
		gw.handleCloseMsg(w, r, m)
	default:
		gw.respondEmpty(w, r)
	}
}

func (gw *Gateway) handleOpen(w dns.ResponseWriter, r *dns.Msg, m *upMsg) {
	userIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())

	if gw.guard != nil && gw.guard.IsBlocked(userIP) {
		gw.respond(w, r, buildDownstream(dnsttStatusAuthFail, m.sid, 0, 0, nil))
		return
	}

	if gw.psk != "" {
		if len(m.payload) < dnsttAuthTagLen ||
			!hmac.Equal(m.payload[:dnsttAuthTagLen], gw.expectedAuthTag(m.sid)) {
			log.Printf("⛔ DNSTT OPEN auth failed from %s (session %08x)", userIP, m.sid)
			gw.respond(w, r, buildDownstream(dnsttStatusAuthFail, m.sid, 0, 0, nil))
			return
		}
	}

	gw.sessionsMu.Lock()
	if _, exists := gw.sessions[m.sid]; exists {
		gw.sessionsMu.Unlock()
		gw.respond(w, r, buildDownstream(dnsttStatusOK, m.sid, 0, 0, nil))
		return
	}

	if gw.maxSessionsPerIP > 0 {
		count := 0
		for _, s := range gw.sessions {
			if s.ip == userIP {
				count++
			}
		}
		if count >= gw.maxSessionsPerIP {
			gw.sessionsMu.Unlock()
			log.Printf("🚫 DNSTT per-IP session limit reached for %s (%d)", userIP, gw.maxSessionsPerIP)
			gw.respond(w, r, buildDownstream(dnsttStatusError, m.sid, 0, 0, nil))
			return
		}
	}

	backendPort := gw.getRandomServerPort()
	if backendPort == 0 {
		gw.sessionsMu.Unlock()
		gw.respond(w, r, buildDownstream(dnsttStatusError, m.sid, 0, 0, nil))
		return
	}

	tcpConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", backendPort))
	if err != nil {
		gw.sessionsMu.Unlock()
		log.Printf("❌ DNSTT failed to dial backend SSH port %d: %v", backendPort, err)
		gw.respond(w, r, buildDownstream(dnsttStatusError, m.sid, 0, 0, nil))
		return
	}
	if c, ok := tcpConn.(*net.TCPConn); ok {
		c.SetNoDelay(true)
		c.SetKeepAlive(true)
		c.SetKeepAlivePeriod(30 * time.Second)
	}

	s := &dnsttSession{
		id:         m.sid,
		ip:         userIP,
		backend:    backendPort,
		tcpConn:    tcpConn,
		created:    time.Now(),
		upExpected: 1,
		upBuffer:   make(map[uint32][]byte),
		downNext:   1,
	}
	s.lastSeen.Store(time.Now().Unix())
	gw.sessions[m.sid] = s
	gw.sessionsMu.Unlock()

	go gw.backendReadLoop(s)
	logging.DNSTTConnection(userIP, m.sid, backendPort)
	log.Printf("🔗 DNSTT session opened: %08x from %s → 127.0.0.1:%d", m.sid, userIP, backendPort)
	gw.respond(w, r, buildDownstream(dnsttStatusOK, m.sid, 0, 0, nil))
}

func (gw *Gateway) handleData(w dns.ResponseWriter, r *dns.Msg, m *upMsg) {
	gw.sessionsMu.RLock()
	s, ok := gw.sessions[m.sid]
	gw.sessionsMu.RUnlock()
	if !ok {
		gw.respond(w, r, buildDownstream(dnsttStatusNoSession, m.sid, 0, 0, nil))
		return
	}

	s.lastSeen.Store(time.Now().Unix())
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		gw.respond(w, r, buildDownstream(dnsttStatusClosed, m.sid, 0, 0, nil))
		return
	}

	s.dropAckedLocked(m.ack)
	var toWrite []byte
	if m.typ == dnsttTypeData && len(m.payload) > 0 {
		toWrite = s.acceptUpstreamLocked(m.seq, m.payload)
	}
	if len(toWrite) > 0 {
		_ = s.tcpConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := s.tcpConn.Write(toWrite); err != nil {
			s.closeLocked()
			s.mu.Unlock()
			gw.removeSession(m.sid)
			gw.respond(w, r, buildDownstream(dnsttStatusClosed, m.sid, 0, 0, nil))
			return
		}
	}

	upAck := s.upExpected - 1
	chunk := s.pickDownstreamLocked(time.Now())
	var dataSeq uint32
	var data []byte
	if chunk != nil {
		dataSeq = chunk.seq
		data = chunk.data
	}
	s.mu.Unlock()
	gw.respond(w, r, buildDownstream(dnsttStatusOK, m.sid, upAck, dataSeq, data))
}

func (gw *Gateway) handleCloseMsg(w dns.ResponseWriter, r *dns.Msg, m *upMsg) {
	gw.removeSession(m.sid)
	gw.respond(w, r, buildDownstream(dnsttStatusClosed, m.sid, 0, 0, nil))
}

func (s *dnsttSession) acceptUpstreamLocked(seq uint32, payload []byte) []byte {
	if seq < s.upExpected {
		return nil
	}
	if seq == s.upExpected {
		out := make([]byte, 0, len(payload))
		out = append(out, payload...)
		s.upExpected++
		for {
			d, ok := s.upBuffer[s.upExpected]
			if !ok {
				break
			}
			out = append(out, d...)
			delete(s.upBuffer, s.upExpected)
			s.upExpected++
		}
		return out
	}
	if _, exists := s.upBuffer[seq]; !exists && len(s.upBuffer) < dnsttMaxPendingChunks {
		cp := make([]byte, len(payload))
		copy(cp, payload)
		s.upBuffer[seq] = cp
	}
	return nil
}

func (s *dnsttSession) dropAckedLocked(ack uint32) {
	for len(s.downChunks) > 0 && s.downChunks[0].seq <= ack {
		s.downChunks = s.downChunks[1:]
	}
}

func (s *dnsttSession) pickDownstreamLocked(now time.Time) *dnsttDownChunk {
	for _, c := range s.downChunks {
		if !c.sent {
			c.sent = true
			c.sentAt = now
			return c
		}
	}
	for _, c := range s.downChunks {
		if now.Sub(c.sentAt) >= dnsttRetransmit {
			c.sentAt = now
			return c
		}
	}
	return nil
}

func (s *dnsttSession) closeLocked() {
	if s.closed {
		return
	}
	s.closed = true
	if s.tcpConn != nil {
		s.tcpConn.Close()
	}
}

func (gw *Gateway) removeSession(sid uint32) {
	gw.sessionsMu.Lock()
	s, ok := gw.sessions[sid]
	if ok {
		delete(gw.sessions, sid)
	}
	gw.sessionsMu.Unlock()
	if ok {
		s.mu.Lock()
		s.closeLocked()
		s.mu.Unlock()
		log.Printf("🔌 DNSTT session closed: %08x from %s", sid, s.ip)
	}
}

func (gw *Gateway) backendReadLoop(s *dnsttSession) {
	buf := make([]byte, dnsttMaxDownPayload)
	for {
		select {
		case <-gw.stopChan:
			gw.removeSession(s.id)
			return
		default:
		}
		s.mu.Lock()
		pending := len(s.downChunks)
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return
		}
		if pending >= dnsttMaxPendingChunks {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		_ = s.tcpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := s.tcpConn.Read(buf)
		if n > 0 {
			cp := make([]byte, n)
			copy(cp, buf[:n])
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				return
			}
			chunk := &dnsttDownChunk{seq: s.downNext, data: cp}
			s.downNext++
			s.downChunks = append(s.downChunks, chunk)
			s.mu.Unlock()
			s.lastSeen.Store(time.Now().Unix())
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			gw.removeSession(s.id)
			return
		}
	}
}

func (gw *Gateway) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-gw.stopChan:
			return
		case <-ticker.C:
			now := time.Now().Unix()
			idleSecs := int64(gw.idleTimeout.Seconds())
			var expired []uint32
			gw.sessionsMu.RLock()
			for sid, s := range gw.sessions {
				if now-s.lastSeen.Load() > idleSecs {
					expired = append(expired, sid)
				}
			}
			gw.sessionsMu.RUnlock()
			for _, sid := range expired {
				log.Printf("⏱️ DNSTT session %08x idle-timed out", sid)
				gw.removeSession(sid)
			}
		}
	}
}

// Start starts the DNSTT gateway DNS servers (UDP + TCP).
func (gw *Gateway) Start() error {
	if gw.listenAddr == "" {
		return fmt.Errorf("DNSTT listen address not configured")
	}
	if gw.nameserver == "" {
		return fmt.Errorf("DNSTT nameserver domain not configured")
	}
	addr := gw.listenAddr
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", gw.handleDNSTTQuery)
	gw.udpServer = &dns.Server{Addr: addr, Net: "udp", Handler: mux, UDPSize: dnsttEDNSUDPSize}
	gw.tcpServer = &dns.Server{Addr: addr, Net: "tcp", Handler: mux}
	gw.wg.Add(3)
	go func() {
		defer gw.wg.Done()
		log.Printf("🚀 DNSTT Gateway (UDP) listening on %s for domain %s", addr, gw.nameserver)
		if err := gw.udpServer.ListenAndServe(); err != nil {
			log.Printf("❌ DNSTT UDP server error: %v", err)
		}
	}()
	go func() {
		defer gw.wg.Done()
		log.Printf("🚀 DNSTT Gateway (TCP) listening on %s for domain %s", addr, gw.nameserver)
		if err := gw.tcpServer.ListenAndServe(); err != nil {
			log.Printf("❌ DNSTT TCP server error: %v", err)
		}
	}()
	go func() {
		defer gw.wg.Done()
		gw.cleanupLoop()
	}()
	return nil
}

// Stop stops the DNSTT gateway and closes all sessions.
func (gw *Gateway) Stop() error {
	gw.stopOnce.Do(func() {
		close(gw.stopChan)
	})
	if gw.udpServer != nil {
		_ = gw.udpServer.Shutdown()
	}
	if gw.tcpServer != nil {
		_ = gw.tcpServer.Shutdown()
	}
	gw.sessionsMu.Lock()
	for sid, s := range gw.sessions {
		s.mu.Lock()
		s.closeLocked()
		s.mu.Unlock()
		delete(gw.sessions, sid)
	}
	gw.sessionsMu.Unlock()
	gw.wg.Wait()
	log.Printf("🛑 DNSTT Gateway stopped")
	return nil
}

// StartGateway starts the DNSTT gateway based on server configuration.
func StartGateway(cfg config.ServerConfig, guard *security.Guard) {
	if !cfg.DNSTTEnabled {
		log.Printf("ℹ️  DNSTT Gateway is disabled in configuration")
		return
	}
	if cfg.DNSTTListen == "" {
		log.Printf("⚠️  DNSTT Gateway enabled but listen address not configured")
		return
	}
	if cfg.DNSTTNameserver == "" {
		log.Printf("⚠️  DNSTT Gateway enabled but nameserver domain not configured")
		return
	}
	if len(cfg.Ports) == 0 {
		log.Printf("⚠️  DNSTT Gateway enabled but no server ports configured")
		return
	}
	if cfg.DNSTTPSK == "" {
		log.Printf("⚠️  DNSTT Gateway running WITHOUT a PSK (dnstt_psk empty): the gateway is open to anyone")
	}
	gateway := NewGateway(cfg, guard)
	if err := gateway.Start(); err != nil {
		log.Printf("❌ Failed to start DNSTT Gateway: %v", err)
		return
	}
	log.Printf("✅ DNSTT Gateway started successfully on %s", cfg.DNSTTListen)
}
