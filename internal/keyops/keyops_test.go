package keyops

import (
	"slices"
	"testing"

	"github.com/dgolveira/farol-guard/internal/inventory"
)

const (
	keyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOyIKCyDSiLT9NFPR3SZXkJB5iMCcl1KXO0prJete1y8 a@x"
	keyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAI3CM8tKqs9ejSBEzGIOYXjYXnGVmX8xxrzo4QxNA+ b@x"
)

func TestRemoveFingerprintKeepsOtherLines(t *testing.T) {
	fpA := lineFingerprint(keyA)
	lines := []string{"# managed by hand", keyA, `from="10.0.0.1" ` + keyA, keyB, ""}
	out, n := removeFingerprint(lines, fpA)
	if n != 2 || len(out) != 3 || out[0] != "# managed by hand" || out[1] != keyB {
		t.Fatalf("unexpected: n=%d out=%q", n, out)
	}
	if containsFingerprint(out, fpA) || !containsFingerprint(out, lineFingerprint(keyB)) {
		t.Fatal("fingerprint lookup mismatch")
	}
}

func TestValidateRejectsUnsafeInput(t *testing.T) {
	for _, r := range []Request{
		{Users: []string{"root; rm -rf /"}},
		{FromIPs: []string{`1.2.3.4" command="sh`}},
	} {
		r.DryRun = true
		if err := r.Validate(); err == nil {
			t.Fatalf("expected error for %+v", r)
		}
	}
}

func TestUsersForTargetsArePerHost(t *testing.T) {
	req := Request{Users: []string{"opc", "root"}, Targets: map[string][]string{"a": {"opc"}, "b": {"root"}}}
	if got := req.usersFor(inventory.Host{Name: "a", User: "root"}); !slices.Equal(got, []string{"opc"}) {
		t.Fatalf("host a: %q", got)
	}
	if got := req.usersFor(inventory.Host{Name: "b", User: "ubuntu"}); !slices.Equal(got, []string{"root"}) {
		t.Fatalf("host b: %q", got)
	}
	if got := req.usersFor(inventory.Host{Name: "c", User: "root"}); len(got) != 0 {
		t.Fatalf("host c: %q", got)
	}
	if got := (&Request{}).usersFor(inventory.Host{Name: "a", User: "root"}); !slices.Equal(got, []string{"root"}) {
		t.Fatalf("default: %q", got)
	}
}

func TestValidateRejectsUnsafeTargetUser(t *testing.T) {
	r := Request{DryRun: true, Targets: map[string][]string{"a": {"root; id"}}}
	if err := r.Validate(); err == nil {
		t.Fatal("expected error")
	}
}
