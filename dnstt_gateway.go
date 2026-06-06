/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : dnstt_gateway.go
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2025-01-27 12:00:00
 * Description  : Operational DNS tunneling gateway. Carries the SSH byte
 *                stream of the Abdal 4iProto server over DNS queries using a
 *                custom, reliable, sequenced protocol designed for Abdal
 *                proprietary clients (NOT compatible with classic dnstt).
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package main

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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Protocol message types (first byte of every upstream message).
const (
	dnsttTypeOpen  = 0x01 // Establish a new tunnel session (authenticated)
	dnsttTypeData  = 0x02 // Carry upstream payload + acknowledge downstream
	dnsttTypePoll  = 0x03 // Pull downstream data / acknowledge without sending
	dnsttTypeClose = 0x04 // Tear the session down
)

// Response status codes (first byte of every downstream message).
const (
	dnsttStatusOK        = 0x00 // Request accepted
	dnsttStatusNoSession = 0x01 // Session ID unknown (client must re-OPEN)
	dnsttStatusAuthFail  = 0x02 // OPEN authentication failed
	dnsttStatusError     = 0x03 // Server-side error (e.g. backend dial failed)
	dnsttStatusClosed    = 0x04 // Session has been closed
)

// Wire framing sizes and limits.
const (
	// Upstream header layout (big-endian):
	//   [1]  Type
	//   [4]  Session ID (uint32, client-generated)
	//   [4]  Seq        (uint32, upstream chunk sequence)
	//   [4]  Ack        (uint32, highest contiguous downstream seq received)
	//   [2]  Nonce      (uint16, fresh per query to defeat resolver caching)
	//   [2]  Len        (uint16, payload length)
	//   [Len] payload
	dnsttUpHeaderLen = 17

	// Downstream header layout (big-endian):
	//   [1]  Status
	//   [4]  Session ID (echo)
	//   [4]  Ack        (uint32, highest contiguous upstream seq consumed)
	//   [4]  DataSeq    (uint32, seq of the downstream payload, 0 if none)
	//   [2]  DataLen    (uint16)
	//   [DataLen] payload
	dnsttDownHeaderLen = 15

	// Payload caps. Upstream is bounded by the 255-byte DNS QNAME limit after
	// base32 expansion and header overhead. Downstream is bounded by a safe
	// EDNS0 response budget after base64 expansion.
	dnsttMaxUpPayload   = 100
	dnsttMaxDownPayload = 180

	// Backpressure: stop pulling from the backend once this many downstream
	// chunks are pending (un-acknowledged) for a session.
	dnsttMaxPendingChunks = 1024

	// Retransmit a downstream chunk if it has not been acknowledged within this
	// interval (handles DNS packet loss).
	dnsttRetransmit = 2 * time.Second

	// EDNS0 UDP buffer size advertised on responses. Clients MUST send EDNS0
	// with at least this buffer size to receive full downstream payloads.
	dnsttEDNSUDPSize = 1232

	// Auth tag length (truncated HMAC-SHA256) carried in the OPEN payload.
	dnsttAuthTagLen = 8
)

// dnsttDownChunk is a single ordered downstream segment awaiting acknowledgement.
type dnsttDownChunk struct {
	seq    uint32
	data   []byte
	sent   bool
	sentAt time.Time
}

// dnsttSession holds the reliable per-tunnel state.
type dnsttSession struct {
	id       uint32
	ip       string
	backend  int
	tcpConn  net.Conn
	created  time.Time
	lastSeen atomic.Int64 // unix seconds

	mu         sync.Mutex
	upExpected uint32            // next in-order upstream seq expected
	upBuffer   map[uint32][]byte // out-of-order upstream chunks
	downChunks []*dnsttDownChunk // ordered downstream send buffer
	downNext   uint32            // next downstream seq to assign
	closed     bool
}

// upMsg is a parsed upstream message.
type upMsg struct {
	typ     byte
	sid     uint32
	seq     uint32
	ack     uint32
	nonce   uint16
	payload []byte
}

// DNSTTGateway handles DNS tunneling for proprietary Abdal clients.
type DNSTTGateway struct {
	listenAddr       string
	resolver         string
	nameserver       string
	psk              string
	maxSessionsPerIP int
	idleTimeout      time.Duration
	ttl              uint32
	serverPorts      []int

	sessions   map[uint32]*dnsttSession
	sessionsMu sync.RWMutex

	udpServer *dns.Server
	tcpServer *dns.Server
	stopChan  chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
}

// NewDNSTTGateway creates a new DNSTT gateway instance from server config.
func NewDNSTTGateway(config ServerConfig) *DNSTTGateway {
	idle := time.Duration(config.DNSTTIdleTimeoutSec) * time.Second
	if idle <= 0 {
		idle = 60 * time.Second
	}

	return &DNSTTGateway{
		listenAddr:       config.DNSTTListen,
		resolver:         config.DNSTTResolver,
		nameserver:       strings.ToLower(strings.TrimSuffix(config.DNSTTNameserver, ".")),
		psk:              config.DNSTTPSK,
		maxSessionsPerIP: config.DNSTTMaxSessionsPerIP,
		idleTimeout:      idle,
		ttl:              0, // TTL 0 prevents intermediate resolvers from caching
		serverPorts:      config.Ports,
		sessions:         make(map[uint32]*dnsttSession),
		stopChan:         make(chan struct{}),
	}
}

// getRandomServerPort returns a random backend SSH port for load balancing.
func (gw *DNSTTGateway) getRandomServerPort() int {
	if len(gw.serverPorts) == 0 {
		return 0
	}
	return gw.serverPorts[mathrand.Intn(len(gw.serverPorts))]
}

// expectedAuthTag computes the truncated HMAC-SHA256 tag a client must present
// in its OPEN message: HMAC-SHA256(psk, sessionID-as-4-bytes)[:dnsttAuthTagLen].
func (gw *DNSTTGateway) expectedAuthTag(sid uint32) []byte {
	var sidBytes [4]byte
	binary.BigEndian.PutUint32(sidBytes[:], sid)
	mac := hmac.New(sha256.New, []byte(gw.psk))
	mac.Write(sidBytes[:])
	sum := mac.Sum(nil)
	return sum[:dnsttAuthTagLen]
}

// decodeQName extracts and base32-decodes the data labels of a tunnel query.
// Returns (data, true) when the query targets our nameserver domain (data may
// be empty), or (nil, false) when the query is unrelated to this gateway.
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
		// Our domain but undecodable: signal "ours" with empty data so the
		// caller answers harmlessly instead of leaking that it is a tunnel.
		return []byte{}, true
	}
	return data, true
}

// parseUpstream parses a decoded upstream message.
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

// buildDownstream assembles a downstream response message.
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

// splitTXT splits a string into <=255-byte chunks for TXT character-strings.
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

// respond writes a downstream message back to the client as a TXT answer.
func (gw *DNSTTGateway) respond(w dns.ResponseWriter, r *dns.Msg, payload []byte) {
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

// respondEmpty answers a non-tunnel / unparseable query harmlessly.
func (gw *DNSTTGateway) respondEmpty(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	_ = w.WriteMsg(m)
}

// handleDNSTTQuery is the DNS handler entry point.
func (gw *DNSTTGateway) handleDNSTTQuery(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	raw, ours := decodeQName(r.Question[0].Name, gw.nameserver)
	if !ours {
		return // Not our domain; ignore.
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

// handleOpen authenticates and establishes a new tunnel session.
func (gw *DNSTTGateway) handleOpen(w dns.ResponseWriter, r *dns.Msg, m *upMsg) {
	userIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())

	// Honor the global blocked IP list.
	if isBlocked(userIP) {
		gw.respond(w, r, buildDownstream(dnsttStatusAuthFail, m.sid, 0, 0, nil))
		return
	}

	// Authenticate the OPEN when a PSK is configured.
	if gw.psk != "" {
		if len(m.payload) < dnsttAuthTagLen ||
			!hmac.Equal(m.payload[:dnsttAuthTagLen], gw.expectedAuthTag(m.sid)) {
			log.Printf("⛔ DNSTT OPEN auth failed from %s (session %08x)", userIP, m.sid)
			gw.respond(w, r, buildDownstream(dnsttStatusAuthFail, m.sid, 0, 0, nil))
			return
		}
	}

	// Idempotent OPEN: if the session already exists, just re-acknowledge.
	gw.sessionsMu.Lock()
	if _, exists := gw.sessions[m.sid]; exists {
		gw.sessionsMu.Unlock()
		gw.respond(w, r, buildDownstream(dnsttStatusOK, m.sid, 0, 0, nil))
		return
	}

	// Enforce per-IP session cap (anti-abuse).
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

	// Dial the backend SSH port.
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
	logDNSTTConnection(userIP, m.sid, backendPort)
	log.Printf("🔗 DNSTT session opened: %08x from %s → 127.0.0.1:%d", m.sid, userIP, backendPort)

	gw.respond(w, r, buildDownstream(dnsttStatusOK, m.sid, 0, 0, nil))
}

// handleData processes DATA/POLL: consumes acks, ingests upstream bytes (in
// order), writes them to the backend, and returns one downstream chunk.
func (gw *DNSTTGateway) handleData(w dns.ResponseWriter, r *dns.Msg, m *upMsg) {
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

	// Free downstream chunks the client has acknowledged.
	s.dropAckedLocked(m.ack)

	// Ingest upstream payload (DATA only) and assemble in-order bytes.
	var toWrite []byte
	if m.typ == dnsttTypeData && len(m.payload) > 0 {
		toWrite = s.acceptUpstreamLocked(m.seq, m.payload)
	}

	// Writing to the backend happens under the lock so that contiguous blocks
	// produced by concurrent queries cannot be reordered on the wire.
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

// handleCloseMsg tears down a session at the client's request.
func (gw *DNSTTGateway) handleCloseMsg(w dns.ResponseWriter, r *dns.Msg, m *upMsg) {
	gw.removeSession(m.sid)
	gw.respond(w, r, buildDownstream(dnsttStatusClosed, m.sid, 0, 0, nil))
}

// acceptUpstreamLocked stores/orders an upstream chunk and returns any newly
// contiguous bytes ready to be written to the backend. Caller holds s.mu.
func (s *dnsttSession) acceptUpstreamLocked(seq uint32, payload []byte) []byte {
	if seq < s.upExpected {
		return nil // Duplicate/retransmit already consumed.
	}

	if seq == s.upExpected {
		out := make([]byte, 0, len(payload))
		out = append(out, payload...)
		s.upExpected++
		// Drain any buffered, now-contiguous chunks.
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

	// Future chunk: buffer it (bounded).
	if _, exists := s.upBuffer[seq]; !exists && len(s.upBuffer) < dnsttMaxPendingChunks {
		cp := make([]byte, len(payload))
		copy(cp, payload)
		s.upBuffer[seq] = cp
	}
	return nil
}

// dropAckedLocked removes downstream chunks acknowledged by the client.
func (s *dnsttSession) dropAckedLocked(ack uint32) {
	for len(s.downChunks) > 0 && s.downChunks[0].seq <= ack {
		s.downChunks = s.downChunks[1:]
	}
}

// pickDownstreamLocked selects the next downstream chunk to transmit: first a
// never-sent chunk (pipelining), otherwise the oldest timed-out chunk
// (retransmission). Caller holds s.mu.
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

// closeLocked closes the backend connection. Caller holds s.mu.
func (s *dnsttSession) closeLocked() {
	if s.closed {
		return
	}
	s.closed = true
	if s.tcpConn != nil {
		s.tcpConn.Close()
	}
}

// removeSession closes and removes a session from the gateway.
func (gw *DNSTTGateway) removeSession(sid uint32) {
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

// backendReadLoop pulls bytes from the backend SSH connection and enqueues them
// as ordered downstream chunks. Applies backpressure when the buffer is full.
func (gw *DNSTTGateway) backendReadLoop(s *dnsttSession) {
	buf := make([]byte, dnsttMaxDownPayload)

	for {
		select {
		case <-gw.stopChan:
			gw.removeSession(s.id)
			return
		default:
		}

		// Backpressure: pause reading while the send buffer is saturated.
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
				continue // Idle read tick; keep looping.
			}
			// Backend closed or errored: tear the session down.
			gw.removeSession(s.id)
			return
		}
	}
}

// cleanupLoop expires idle sessions and reaps closed ones.
func (gw *DNSTTGateway) cleanupLoop() {
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
func (gw *DNSTTGateway) Start() error {
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
func (gw *DNSTTGateway) Stop() error {
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

// startDNSTTGateway starts the DNSTT gateway based on configuration.
func startDNSTTGateway(config ServerConfig) {
	if !config.DNSTTEnabled {
		log.Printf("ℹ️  DNSTT Gateway is disabled in configuration")
		return
	}
	if config.DNSTTListen == "" {
		log.Printf("⚠️  DNSTT Gateway enabled but listen address not configured")
		return
	}
	if config.DNSTTNameserver == "" {
		log.Printf("⚠️  DNSTT Gateway enabled but nameserver domain not configured")
		return
	}
	if len(config.Ports) == 0 {
		log.Printf("⚠️  DNSTT Gateway enabled but no server ports configured")
		return
	}
	if config.DNSTTPSK == "" {
		log.Printf("⚠️  DNSTT Gateway running WITHOUT a PSK (dnstt_psk empty): the gateway is open to anyone")
	}

	gateway := NewDNSTTGateway(config)
	if err := gateway.Start(); err != nil {
		log.Printf("❌ Failed to start DNSTT Gateway: %v", err)
		return
	}

	log.Printf("✅ DNSTT Gateway started successfully on %s", config.DNSTTListen)
}

// logDNSTTConnection appends a DNSTT connection record to the gateway log.
func logDNSTTConnection(userIP string, sessionID uint32, serverPort int) {
	exeDir, err := SetExecutableDir()
	if err != nil {
		log.Printf("❌ Failed to get executable directory: %v", err)
		return
	}

	dnsttLogDir := filepath.Join(exeDir, "dnstt_log")
	if err := os.MkdirAll(dnsttLogDir, 0755); err != nil {
		log.Printf("❌ Failed to create dnstt_log directory: %v", err)
		return
	}

	logEntry := fmt.Sprintf(
		"[🔗 DNSTT Connection] [%s] IP: %s | Session: %08x | Server Port: %d\n",
		time.Now().Format("2006-01-02 15:04:05"),
		userIP,
		sessionID,
		serverPort,
	)

	fullPath := filepath.Join(dnsttLogDir, "dnstt_connections.log")
	f, err := os.OpenFile(fullPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open DNSTT log file: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry); err != nil {
		log.Printf("Failed to write DNSTT connection log: %v", err)
	}
}
