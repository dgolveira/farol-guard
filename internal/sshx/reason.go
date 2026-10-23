package sshx

import "strings"

var reasons = []struct {
	code    string
	needles []string
}{
	{"hostkey_mismatch", []string{"HOST KEY MISMATCH"}},
	{"hostkey_unknown", []string{"unknown host key"}},
	{"key_locked", []string{"is encrypted and not loaded", "does not unlock it", "passphrase not found in the system keyring"}},
	{"dns", []string{"no such host", "server misbehaving", "Temporary failure in name resolution"}},
	{"refused", []string{"connection refused"}},
	{"no_route", []string{"no route to host", "network is unreachable"}},
	{"timeout", []string{"i/o timeout", "timed out", "deadline exceeded"}},
	{"auth", []string{"unable to authenticate", "no supported methods remain"}},
	{"reset", []string{"connection reset by peer", "EOF"}},
}

func Reason(msg string) string {
	for _, r := range reasons {
		for _, n := range r.needles {
			if strings.Contains(msg, n) {
				return r.code
			}
		}
	}
	return ""
}
