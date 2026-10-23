package collect

import "testing"

func TestParseUpgrades(t *testing.T) {
	u := parseUpgrades([]string{
		"libssl3t64/noble-updates,noble-security 3.0.13-0ubuntu3.6 amd64 [upgradable from: 3.0.13-0ubuntu3.5]",
		"libaudit1/noble-updates 1:3.1.2-2.1build1.1 amd64 [upgradable from: 1:3.1.2-2.1build1]",
	})
	if len(u) != 2 || !u[0].Security || u[1].Security || u[0].OldVersion != "3.0.13-0ubuntu3.5" {
		t.Fatalf("unexpected: %+v", u)
	}
}

func TestParseLogins(t *testing.T) {
	labels := map[string]string{"SHA256:abc": "ops"}
	logins, ips := parseLogins([]string{
		"2026-10-23T10:00:01-0300 web01 sshd[1]: Accepted publickey for root from 10.0.0.5 port 5000 ssh2: ED25519 SHA256:abc",
		"Oct 23 10:01:00 web01 sshd[2]: Failed password for invalid user admin from 198.51.100.7 port 4000 ssh2",
		"Accepted publickey for deploy from 10.0.0.5 port 5001 ssh2: ED25519 SHA256:zzz",
	}, labels)
	if len(logins) != 2 || logins[0].KeyLabel != "ops" || logins[0].Time != "2026-10-23T10:00:01-0300" || logins[1].Time != "" {
		t.Fatalf("unexpected logins: %+v", logins)
	}
	if len(ips) != 2 || ips[0].IP != "10.0.0.5" || ips[0].Accepted != 2 || ips[1].Failed != 1 {
		t.Fatalf("unexpected ips: %+v", ips)
	}
}

func TestParseSSHDFileFirstWins(t *testing.T) {
	c := parseSSHD(map[string][]string{"sshd_file": {
		"PermitRootLogin no", "PermitRootLogin yes", "Match User x", "PasswordAuthentication yes",
	}})
	if c.Effective || c.Get("permitrootlogin") != "no" || c.Get("passwordauthentication") != "" {
		t.Fatalf("unexpected: %+v", c)
	}
}
