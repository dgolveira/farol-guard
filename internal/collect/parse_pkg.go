package collect

import (
	"html"
	"sort"
	"strings"

	"github.com/dgolveira/farol-guard/internal/model"
)

func rpmSourceName(srpm string) string {
	srpm = strings.TrimSuffix(srpm, ".src.rpm")
	for i := 0; i < 2; i++ {
		j := strings.LastIndexByte(srpm, '-')
		if j <= 0 {
			return ""
		}
		srpm = srpm[:j]
	}
	return srpm
}

func trimEpochZero(v string) string { return strings.TrimPrefix(v, "0:") }

func parseRPMPackages(lines []string) []model.Package {
	var out []model.Package
	seen := map[string]bool{}
	for _, l := range lines {
		f := strings.Split(l, "\t")
		if len(f) < 3 || f[0] == "gpg-pubkey" || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		ver := trimEpochZero(f[1])
		src := rpmSourceName(f[2])
		if src == "" {
			src = f[0]
		}
		out = append(out, model.Package{Name: f[0], Version: ver, Source: src, SourceVersion: ver})
	}
	return out
}

var rpmArches = map[string]bool{
	"x86_64": true, "noarch": true, "aarch64": true, "i686": true, "i386": true, "ppc64le": true, "s390x": true, "armv7hl": true,
}

func stripArch(s string) string {
	if i := strings.LastIndexByte(s, '.'); i > 0 && rpmArches[s[i+1:]] {
		return s[:i]
	}
	return s
}

func SplitNEVRA(nevra string) (name, version string) {
	s := stripArch(nevra)
	rel := strings.LastIndexByte(s, '-')
	if rel <= 0 {
		return s, ""
	}
	ver := strings.LastIndexByte(s[:rel], '-')
	if ver <= 0 {
		return s, ""
	}
	return s[:ver], trimEpochZero(s[ver+1:])
}

func parseRPMUpgrades(lines []string, pkgs []model.Package, adv []model.RPMAdvisory) []model.Upgrade {
	installed := map[string]string{}
	for _, p := range pkgs {
		installed[p.Name] = p.Version
	}
	security := map[string]bool{}
	for _, a := range adv {
		n, _ := SplitNEVRA(a.Package)
		security[n] = true
	}
	var out []model.Upgrade
	seen := map[string]bool{}
	for _, l := range joinWrapped(lines, 3) {
		f := strings.Fields(l)
		if len(f) != 3 || !strings.Contains(f[0], ".") || strings.HasSuffix(l, ":") {
			continue
		}
		name := stripArch(f[0])
		if name == f[0] || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, model.Upgrade{
			Name: name, Suite: f[2], NewVersion: trimEpochZero(f[1]), OldVersion: installed[name], Security: security[name],
		})
	}
	return out
}

func joinWrapped(lines []string, want int) []string {
	var out []string
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		for n := len(strings.Fields(l)); n > 0 && n < want && i+1 < len(lines); n = len(strings.Fields(l)) {
			next := strings.Fields(lines[i+1])
			if len(next) == 0 || n+len(next) > want || strings.HasPrefix(l, "@@") || strings.HasPrefix(next[0], "@@") {
				break
			}
			l += " " + lines[i+1]
			i++
		}
		out = append(out, l)
	}
	return out
}

func rpmSeverity(s string) string {
	s, _, _ = strings.Cut(s, "/")
	return strings.ToLower(s)
}

func parseRPMAdvisories(lines []string) []model.RPMAdvisory {
	type row struct{ id, sev, pkg string }
	var cves, advs []row
	target := &cves
	for _, l := range joinWrapped(lines, 3) {
		if l == "@@advisories" {
			target = &advs
			continue
		}
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		r := row{id: f[0]}
		switch {
		case strings.Contains(f[1], "/Sec"):
			r.sev, r.pkg = rpmSeverity(f[1]), f[2]
		case f[1] == "security" && len(f) >= 4:
			r.sev, r.pkg = strings.ToLower(f[2]), f[3]
		default:
			continue
		}
		if r.id == "Name" {
			continue
		}
		*target = append(*target, r)
	}
	byPkg := map[string]string{}
	for _, a := range advs {
		byPkg[a.pkg] = a.id
	}
	var out []model.RPMAdvisory
	covered := map[string]bool{}
	for _, c := range cves {
		if !strings.HasPrefix(c.id, "CVE-") {
			continue
		}
		out = append(out, model.RPMAdvisory{ID: byPkg[c.pkg], CVE: c.id, Severity: c.sev, Package: c.pkg})
		covered[c.pkg] = true
	}
	for _, a := range advs {
		if !covered[a.pkg] {
			out = append(out, model.RPMAdvisory{ID: a.id, Severity: a.sev, Package: a.pkg})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out
}

func parseArchPackages(lines []string) []model.Package {
	var out []model.Package
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		out = append(out, model.Package{Name: f[0], Version: f[1], Source: f[0], SourceVersion: f[1]})
	}
	return out
}

func parseArchUpgrades(lines []string) []model.Upgrade {
	var out []model.Upgrade
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 4 || f[2] != "->" {
			continue
		}
		out = append(out, model.Upgrade{Name: f[0], OldVersion: f[1], NewVersion: f[3]})
	}
	return out
}

func xmlAttr(tag, name string) string {
	key := " " + name + `="`
	i := strings.Index(tag, key)
	if i < 0 {
		return ""
	}
	rest := tag[i+len(key):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return html.UnescapeString(rest[:j])
}

func parseSUSEPatches(lines []string) map[string]bool {
	out := map[string]bool{}
	for _, l := range lines {
		if xmlAttr(l, "category") != "security" || xmlAttr(l, "status") == "applied" {
			continue
		}
		_, sum, ok := strings.Cut(l, "<summary>")
		if !ok {
			continue
		}
		sum, _, _ = strings.Cut(sum, "</summary>")
		sum = html.UnescapeString(sum)
		if _, pkg, ok := strings.Cut(sum, "update for "); ok {
			for _, p := range strings.FieldsFunc(pkg, func(r rune) bool { return r == ',' || r == ' ' }) {
				if p != "and" && p != "the" {
					out[p] = true
				}
			}
		}
	}
	return out
}

func parseSUSEUpgrades(lines []string, pkgs []model.Package, securitySources map[string]bool) []model.Upgrade {
	source := map[string]string{}
	for _, p := range pkgs {
		source[p.Name] = p.Source
	}
	var out []model.Upgrade
	seen := map[string]bool{}
	for _, l := range lines {
		name := xmlAttr(l, "name")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		src := source[name]
		out = append(out, model.Upgrade{
			Name: name, NewVersion: trimEpochZero(xmlAttr(l, "edition")), OldVersion: trimEpochZero(xmlAttr(l, "edition-old")),
			Suite: xmlAttr(l, "alias"), Security: securitySources[name] || (src != "" && securitySources[src]),
		})
	}
	return out
}
