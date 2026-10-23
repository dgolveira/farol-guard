package sshx

import "testing"

func TestReason(t *testing.T) {
	cases := map[string]string{
		"dial tcp: lookup web01.example on 127.0.0.53:53: no such host":                          "dns",
		"dial tcp 203.0.113.5:22: connect: connection refused":                                   "refused",
		"dial tcp 203.0.113.5:22: i/o timeout":                                                   "timeout",
		"ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey]": "auth",
		"ssh: handshake failed: HOST KEY MISMATCH for x:22":                                      "hostkey_mismatch",
		"something else": "",
	}
	for msg, want := range cases {
		if got := Reason(msg); got != want {
			t.Errorf("%q: got %q want %q", msg, got, want)
		}
	}
}
