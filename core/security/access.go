/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : access.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Per-user domain and IP access restrictions with wildcard matching
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package security

import (
	"strings"

	"Abdal_4iProto_Server/core/config"
)

// IsDomainOrIPBlocked checks whether a target is blocked for the given user.
func IsDomainOrIPBlocked(username, target string) bool {
	user, exists := config.GetUser(username)
	if !exists {
		return false
	}

	for _, blockedDomain := range user.BlockedDomains {
		if matchesWildcard(target, blockedDomain) {
			return true
		}
	}

	for _, blockedIP := range user.BlockedIPs {
		if matchesWildcard(target, blockedIP) {
			return true
		}
	}

	return false
}

func matchesWildcard(str, pattern string) bool {
	if str == pattern {
		return true
	}

	if strings.Contains(pattern, "*") {
		regexPattern := strings.ReplaceAll(pattern, ".", "\\.")
		regexPattern = strings.ReplaceAll(regexPattern, "*", ".*")

		if strings.HasPrefix(regexPattern, ".*") && strings.HasSuffix(regexPattern, ".*") {
			innerPattern := regexPattern[2 : len(regexPattern)-2]
			return strings.Contains(str, innerPattern)
		} else if strings.HasPrefix(regexPattern, ".*") {
			suffix := regexPattern[2:]
			return strings.HasSuffix(str, suffix)
		} else if strings.HasSuffix(regexPattern, ".*") {
			prefix := regexPattern[:len(regexPattern)-2]
			return strings.HasPrefix(str, prefix)
		}
	}

	return false
}
