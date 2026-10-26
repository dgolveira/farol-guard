package collect

import (
	"strings"

	"github.com/dgolveira/farol-guard/internal/model"
)

var ubuntuReleases = map[string]string{
	"bionic": "18.04", "focal": "20.04", "jammy": "22.04", "kinetic": "22.10", "lunar": "23.04",
	"mantic": "23.10", "noble": "24.04", "oracular": "24.10", "plucky": "25.04", "questing": "25.10",
	"resolute": "26.04",
}

var debianReleases = map[string]string{
	"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14",
}

var suseIDs = map[string]bool{
	"opensuse-leap": true, "opensuse-tumbleweed": true, "opensuse-slowroll": true, "sles": true, "sled": true, "sle-micro": true,
}

var rpmIDs = map[string]bool{
	"rhel": true, "centos": true, "rocky": true, "almalinux": true, "ol": true, "fedora": true, "amzn": true,
}

func resolveBase(o *model.OSInfo, osr map[string]string, family string) {
	like := " " + osr["ID_LIKE"] + " "
	if family == "" {
		switch {
		case o.ID == "debian" || o.ID == "ubuntu" || strings.Contains(like, " debian ") || strings.Contains(like, " ubuntu "):
			family = model.FamilyDeb
		case suseIDs[o.ID] || strings.Contains(like, " suse "):
			family = model.FamilySUSE
		case rpmIDs[o.ID] || strings.Contains(like, " rhel ") || strings.Contains(like, " fedora "):
			family = model.FamilyRPM
		case o.ID == "arch" || strings.Contains(like, " arch "):
			family = model.FamilyArch
		}
	}
	o.Family = family
	major, _, _ := strings.Cut(o.VersionID, ".")
	switch family {
	case model.FamilyDeb:
		switch {
		case o.ID == "ubuntu":
			o.BaseID, o.BaseVersion = "ubuntu", o.VersionID
		case o.ID == "debian":
			o.BaseID, o.BaseVersion = "debian", major
		case ubuntuReleases[osr["UBUNTU_CODENAME"]] != "":
			o.BaseID, o.BaseVersion = "ubuntu", ubuntuReleases[osr["UBUNTU_CODENAME"]]
		case debianReleases[osr["DEBIAN_CODENAME"]] != "":
			o.BaseID, o.BaseVersion = "debian", debianReleases[osr["DEBIAN_CODENAME"]]
		case strings.Contains(like, " ubuntu ") && ubuntuReleases[osr["VERSION_CODENAME"]] != "":
			o.BaseID, o.BaseVersion = "ubuntu", ubuntuReleases[osr["VERSION_CODENAME"]]
		case debianReleases[osr["VERSION_CODENAME"]] != "":
			o.BaseID, o.BaseVersion = "debian", debianReleases[osr["VERSION_CODENAME"]]
		}
		if o.BaseID == "ubuntu" && o.ID != "ubuntu" {
			o.LTS = ubuntuLTS(o.BaseVersion)
		}
	case model.FamilyRPM:
		id := o.ID
		if !rpmIDs[id] {
			if strings.Contains(like, " fedora ") && !strings.Contains(like, " rhel ") {
				id = "fedora"
			} else {
				id = "rhel"
			}
		}
		o.BaseID, o.BaseVersion = id, major
	case model.FamilySUSE:
		id := o.ID
		if !suseIDs[id] {
			id = "opensuse-leap"
			if strings.Contains(strings.ToLower(osr["NAME"]), "tumbleweed") {
				id = "opensuse-tumbleweed"
			}
		}
		o.BaseID = id
		if id != "opensuse-tumbleweed" && id != "opensuse-slowroll" {
			o.BaseVersion = o.VersionID
		}
	case model.FamilyArch:
		o.BaseID = "arch"
	}
}

func ubuntuLTS(version string) bool {
	y, m, ok := strings.Cut(version, ".")
	if !ok || m != "04" || len(y) != 2 {
		return false
	}
	return (y[1]-'0')%2 == 0
}
