package collect

import (
	"testing"

	"github.com/dgolveira/farol-guard/internal/model"
)

func TestResolveBase(t *testing.T) {
	cases := []struct {
		osr              map[string]string
		family           string
		wantFamily, base string
		version          string
		lts              bool
	}{
		{map[string]string{"ID": "linuxmint", "ID_LIKE": "ubuntu debian", "VERSION_ID": "22", "UBUNTU_CODENAME": "noble"}, "deb", "deb", "ubuntu", "24.04", true},
		{map[string]string{"ID": "pop", "ID_LIKE": "ubuntu debian", "VERSION_ID": "22.04", "UBUNTU_CODENAME": "jammy"}, "deb", "deb", "ubuntu", "22.04", true},
		{map[string]string{"ID": "raspbian", "ID_LIKE": "debian", "VERSION_ID": "12", "VERSION_CODENAME": "bookworm"}, "deb", "deb", "debian", "12", false},
		{map[string]string{"ID": "kali", "ID_LIKE": "debian", "VERSION_ID": "2026.3", "VERSION_CODENAME": "kali-rolling"}, "deb", "deb", "", "", false},
		{map[string]string{"ID": "rocky", "ID_LIKE": "rhel centos fedora", "VERSION_ID": "9.4"}, "rpm", "rpm", "rocky", "9", false},
		{map[string]string{"ID": "eurolinux", "ID_LIKE": "rhel fedora centos", "VERSION_ID": "9.2"}, "", "rpm", "rhel", "9", false},
		{map[string]string{"ID": "manjaro", "ID_LIKE": "arch"}, "arch", "arch", "arch", "", false},
		{map[string]string{"ID": "opensuse-leap", "ID_LIKE": "suse opensuse", "VERSION_ID": "16.0"}, "suse", "suse", "opensuse-leap", "16.0", false},
		{map[string]string{"ID": "opensuse-tumbleweed", "ID_LIKE": "opensuse suse", "VERSION_ID": "20261024"}, "suse", "suse", "opensuse-tumbleweed", "", false},
		{map[string]string{"ID": "amzn", "ID_LIKE": "centos rhel fedora", "VERSION_ID": "2"}, "rpm", "rpm", "amzn", "2", false},
		{map[string]string{"ID": "alpine", "VERSION_ID": "3.20.1"}, "", "", "", "", false},
	}
	for _, c := range cases {
		o := model.OSInfo{ID: c.osr["ID"], VersionID: c.osr["VERSION_ID"]}
		resolveBase(&o, c.osr, c.family)
		if o.Family != c.wantFamily || o.BaseID != c.base || o.BaseVersion != c.version || o.LTS != c.lts {
			t.Errorf("%s: got family=%q base=%q version=%q lts=%v", c.osr["ID"], o.Family, o.BaseID, o.BaseVersion, o.LTS)
		}
	}
}

func TestParseRPM(t *testing.T) {
	pkgs := parseRPMPackages([]string{
		"openssl-libs\t1:3.0.7-24.el9\topenssl-3.0.7-24.el9.src.rpm\tx86_64",
		"bash\t0:5.1.8-9.el9\tbash-5.1.8-9.el9.src.rpm\tx86_64",
		"gpg-pubkey\t0:350d275d-6279f0ec\t(none)\t(none)",
	})
	if len(pkgs) != 2 || pkgs[0].Source != "openssl" || pkgs[0].Version != "1:3.0.7-24.el9" || pkgs[1].Version != "5.1.8-9.el9" {
		t.Fatalf("packages: %+v", pkgs)
	}
	adv := parseRPMAdvisories([]string{
		"CVE-2024-5535 Important/Sec. openssl-libs-1:3.0.7-28.el9_4.x86_64",
		"CVE-2024-6119 Moderate/Sec.  openssl-libs-1:3.0.7-28.el9_4.x86_64",
		"@@advisories",
		"RLSA-2024:6783 Important/Sec. openssl-libs-1:3.0.7-28.el9_4.x86_64",
		"RLSA-2024:9000 Low/Sec.       bash-5.1.8-10.el9.x86_64",
	})
	if len(adv) != 3 || adv[0].ID != "RLSA-2024:9000" || adv[1].CVE != "CVE-2024-5535" || adv[1].ID != "RLSA-2024:6783" || adv[1].Severity != "important" {
		t.Fatalf("advisories: %+v", adv)
	}
	ups := parseRPMUpgrades([]string{
		"",
		"bash.x86_64                    5.1.8-10.el9                baseos",
		"openssl-libs.x86_64",
		"                               1:3.0.7-28.el9_4             baseos",
		"Obsoleting Packages",
	}, pkgs, adv)
	if len(ups) != 2 || ups[1].Name != "openssl-libs" || ups[1].NewVersion != "1:3.0.7-28.el9_4" || !ups[1].Security || ups[0].OldVersion != "5.1.8-9.el9" {
		t.Fatalf("upgrades: %+v", ups)
	}
}

func TestParseDNF5Advisories(t *testing.T) {
	adv := parseRPMAdvisories([]string{
		"Name           Type     Severity Package                    Issued",
		"CVE-2025-1111  security Moderate curl-8.9.1-3.fc41.x86_64   2025-01-10 00:00:00",
		"@@advisories",
		"FEDORA-2025-ab security Moderate curl-8.9.1-3.fc41.x86_64   2025-01-10 00:00:00",
	})
	if len(adv) != 1 || adv[0].ID != "FEDORA-2025-ab" || adv[0].CVE != "CVE-2025-1111" || adv[0].Severity != "moderate" {
		t.Fatalf("advisories: %+v", adv)
	}
}

func TestParseArch(t *testing.T) {
	pkgs := parseArchPackages([]string{"openssl 3.3.1-1", "vim 9.0.1224-1"})
	ups := parseArchUpgrades([]string{"openssl 3.3.1-1 -> 3.3.2-1"})
	if len(pkgs) != 2 || len(ups) != 1 || ups[0].NewVersion != "3.3.2-1" || ups[0].OldVersion != "3.3.1-1" {
		t.Fatalf("pkgs=%+v ups=%+v", pkgs, ups)
	}
}

func TestParseYumAdvisories(t *testing.T) {
	adv := parseRPMAdvisories([]string{
		" CVE-2026-107161 important/Sec. cyrus-sasl-lib-2.1.26-24.amzn2.0.2.x86_64",
		"@@advisories",
		"ALAS2-2026-4029 important/Sec. cyrus-sasl-lib-2.1.26-24.amzn2.0.2.x86_64",
	})
	if len(adv) != 1 || adv[0].ID != "ALAS2-2026-4029" || adv[0].CVE != "CVE-2026-107161" {
		t.Fatalf("advisories: %+v", adv)
	}
}

func TestParseSUSE(t *testing.T) {
	pkgs := parseRPMPackages([]string{
		"libopenssl3\t0:3.5.0-160000.3.2\topenssl-3-3.5.0-160000.3.2.src.rpm\tx86_64",
		"bash\t0:5.3.20-10.1\tbash-5.3.20-10.1.src.rpm\tx86_64",
	})
	patches := parseSUSEPatches([]string{
		`<update kind="patch" name="openSUSE-Leap-16.0-2001" edition="1" arch="noarch" status="needed" category="security" severity="important"><summary>Security update for openssl-3</summary>`,
		`<update kind="patch" name="openSUSE-Leap-16.0-1126" edition="1" arch="noarch" status="needed" category="recommended" severity="moderate"><summary>Recommended update for bash</summary>`,
	})
	ups := parseSUSEUpgrades([]string{
		`<update kind="package" name="libopenssl3" edition="3.5.0-160000.11.1" arch="x86_64" edition-old="3.5.0-160000.3.2">`,
		`<update kind="package" name="bash" edition="5.3.20-11.1" arch="x86_64" edition-old="5.3.20-10.1">`,
	}, pkgs, patches)
	if len(ups) != 2 || !ups[0].Security || ups[1].Security || ups[0].OldVersion != "3.5.0-160000.3.2" {
		t.Fatalf("upgrades: %+v", ups)
	}
}
