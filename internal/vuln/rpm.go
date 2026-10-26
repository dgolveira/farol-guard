package vuln

import (
	"strings"

	"github.com/dgolveira/farol-guard/internal/model"
)

func rpmSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "important", "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low":
		return "low"
	}
	return "unknown"
}

func splitNEVRA(nevra string) (name, version string) {
	s := nevra
	if i := strings.LastIndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	rel := strings.LastIndexByte(s, '-')
	if rel <= 0 {
		return s, ""
	}
	ver := strings.LastIndexByte(s[:rel], '-')
	if ver <= 0 {
		return s, ""
	}
	return s[:ver], strings.TrimPrefix(s[ver+1:], "0:")
}

func FromRPM(h *model.HostReport) {
	installed := map[string]string{}
	for _, p := range h.Packages {
		installed[p.Name] = p.Version
	}
	h.Vulns, h.VulnBulk = nil, nil
	seen := map[string]bool{}
	for _, a := range h.Advisories {
		name, fixed := splitNEVRA(a.Package)
		id := a.CVE
		if id == "" {
			id = a.ID
		}
		if id == "" || seen[id+"\x00"+name] {
			continue
		}
		seen[id+"\x00"+name] = true
		v := model.Vuln{
			ID:        id,
			Package:   name,
			Version:   installed[name],
			Fixed:     fixed,
			Severity:  rpmSeverity(a.Severity),
			Advisory:  a.ID,
			Binaries:  []string{name},
			Candidate: fixed,
		}
		if a.CVE != "" && a.ID != "" {
			v.Summary = a.ID
		}
		h.Vulns = append(h.Vulns, v)
	}
	sortVulns(h)
}
