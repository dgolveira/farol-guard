package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dgolveira/farol-guard/internal/i18n"
	"github.com/dgolveira/farol-guard/internal/model"
)

//go:embed report.html.tmpl
var htmlTmpl string

//go:embed style.css
var Style string

type Format string

var advisoryID = regexp.MustCompile(`^(CVE|GHSA|USN|DSA|DLA|DTSA|UBUNTU|DEBIAN|PYSEC|GO|OSV|AVG|RHSA|RHBA|RHEA|RLSA|ALSA|ELSA|ALAS|ALAS2|ALAS2023|FEDORA|SUSE-SU|openSUSE-SU)-[0-9A-Za-z.:-]+$`)

var baseNames = map[string]string{
	"ubuntu": "Ubuntu", "debian": "Debian", "rhel": "RHEL", "fedora": "Fedora", "arch": "Arch Linux",
	"centos": "CentOS", "rocky": "Rocky Linux", "opensuse-leap": "openSUSE Leap", "opensuse-tumbleweed": "openSUSE Tumbleweed", "sles": "SLES", "almalinux": "AlmaLinux", "ol": "Oracle Linux", "amzn": "Amazon Linux",
}

func baseName(o model.OSInfo) string {
	name := baseNames[o.BaseID]
	if name == "" {
		name = o.BaseID
	}
	return strings.TrimSpace(name + " " + o.BaseVersion)
}

func advisoryURL(id string) string {
	esc := url.PathEscape(id)
	switch {
	case strings.HasPrefix(id, "AVG-"):
		return "https://security.archlinux.org/" + esc
	case strings.HasPrefix(id, "RHSA-"), strings.HasPrefix(id, "RHBA-"), strings.HasPrefix(id, "RHEA-"):
		return "https://access.redhat.com/errata/" + esc
	case strings.HasPrefix(id, "FEDORA-"):
		return "https://bodhi.fedoraproject.org/updates/" + esc
	case strings.HasPrefix(id, "ELSA-"):
		return "https://linux.oracle.com/errata/" + esc + ".html"
	}
	return "https://osv.dev/vulnerability/" + esc
}

func detailHTML(s string) template.HTML {
	var b strings.Builder
	for i, p := range strings.Split(s, " · ") {
		esc := template.HTMLEscapeString(p)
		long := utf8.RuneCountInString(p) > 100 && !strings.HasPrefix(p, "apt-get ")
		if i > 0 && !long {
			b.WriteString(" · ")
		}
		switch {
		case i == 0 && advisoryID.MatchString(p):
			fmt.Fprintf(&b, `<a class="detail-id" href="%s" target="_blank" rel="noopener noreferrer">%s</a>`, template.HTMLEscapeString(advisoryURL(p)), esc)
		case long:
			fmt.Fprintf(&b, `<span class="detail-desc">%s</span>`, esc)
		default:
			b.WriteString(esc)
		}
	}
	return template.HTML(b.String())
}

const (
	HTML     Format = "html"
	JSON     Format = "json"
	Markdown Format = "md"
)

func FormatFromPath(p string) Format {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".json":
		return JSON
	case ".md", ".markdown":
		return Markdown
	}
	return HTML
}

func Write(w io.Writer, rep *model.Report, f Format, lang string) error {
	return WriteBack(w, rep, f, lang, "")
}

func WriteBack(w io.Writer, rep *model.Report, f Format, lang, backURL string) error {
	switch f {
	case JSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case Markdown:
		return writeMarkdown(w, rep, lang)
	}
	return writeHTML(w, rep, lang, backURL)
}

type Summary struct {
	Hosts, Reachable, Critical, High, Medium, SecUpdates, CVEFix int
}

func Summarize(rep *model.Report) Summary {
	var s Summary
	s.Hosts = len(rep.Hosts)
	for _, h := range rep.Hosts {
		if h.Reachable {
			s.Reachable++
		}
		s.Critical += h.CountFindings(model.SevCritical)
		s.High += h.CountFindings(model.SevHigh)
		s.Medium += h.CountFindings(model.SevMedium)
		s.SecUpdates += h.SecurityUpgrades()
		s.CVEFix += h.FixableVulns(0)
	}
	return s
}

func Funcs(lang string) template.FuncMap {
	return template.FuncMap{
		"t":     func(key string, args ...any) string { return i18n.T(lang, key, args...) },
		"sev":   func(s any) string { return i18n.T(lang, "sev."+fmt.Sprint(s)) },
		"bytes": humanBytes,
		"kb":    func(v uint64) string { return humanBytes(v * 1024) },
		"pct":   func(v float64) string { return fmt.Sprintf("%.0f%%", v) },
		"f2":    func(v float64) string { return fmt.Sprintf("%.2f", v) },
		"dur":   humanDuration,
		"time":  func(t time.Time) string { return t.Local().Format("2006-01-02 15:04") },
		"yesno": func(b bool) string {
			if b {
				return i18n.T(lang, "t.yes")
			}
			return i18n.T(lang, "t.no")
		},
		"level": func(v, warn, crit float64) string {
			switch {
			case v >= crit:
				return "critical"
			case v >= warn:
				return "medium"
			}
			return "ok"
		},
		"maxdisk": func(h *model.HostReport) float64 {
			m := 0.0
			for _, d := range h.Disks {
				if d.UsedPct > m {
					m = d.UsedPct
				}
			}
			return m
		},
		"perCore": func(c model.CPU) float64 {
			if c.Cores == 0 {
				return 0
			}
			return c.Load5 / float64(c.Cores)
		},
		"detail":      detailHTML,
		"advisoryURL": advisoryURL,
		"baseName":    baseName,
		"words":       strings.Fields,
		"dcount": func(d []string) int {
			n := len(d)
			if n > 0 && strings.HasPrefix(d[n-1], "+") {
				var extra int
				if _, err := fmt.Sscanf(d[n-1], "+%d", &extra); err == nil {
					return n - 1 + extra
				}
			}
			return n
		},
		"after": func(n int, v []string) []string {
			if len(v) <= n {
				return nil
			}
			return v[n:]
		},
		"limit": func(n int, v any) any {
			switch s := v.(type) {
			case []model.Vuln:
				if len(s) > n {
					return s[:n]
				}
			case []model.Login:
				if len(s) > n {
					return s[len(s)-n:]
				}
			case []model.IPSummary:
				if len(s) > n {
					return s[:n]
				}
			case []string:
				if len(s) > n {
					return s[:n]
				}
			}
			return v
		},
		"rest":      func(n, total int) int { return total - n },
		"join":      strings.Join,
		"worst":     func(h *model.HostReport) string { return h.Worst().String() },
		"fixable":   func(h *model.HostReport) int { return h.FixableVulns(0) },
		"secup":     func(h *model.HostReport) int { return h.SecurityUpgrades() },
		"lang":      func() string { return lang },
		"sshdKeys":  func() []string { return sshdKeys },
		"hostID":    func(h *model.HostReport) string { return "host-" + strings.ReplaceAll(h.Name, ".", "-") },
		"countKeys": countKeys,
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
	}
}

var sshdKeys = []string{
	"port", "listenaddress", "permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication",
	"pubkeyauthentication", "permitemptypasswords", "authenticationmethods", "maxauthtries", "maxsessions",
	"logingracetime", "x11forwarding", "allowtcpforwarding", "allowagentforwarding", "permittunnel",
	"allowusers", "allowgroups", "denyusers", "usepam", "loglevel", "clientaliveinterval",
	"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms", "authorizedkeysfile",
}

func countKeys(users []model.User) int {
	n := 0
	for _, u := range users {
		n += len(u.Keys)
	}
	return n
}

func Fragment(w io.Writer, name string, data map[string]any, lang string) error {
	t, err := template.New("report").Funcs(Funcs(lang)).Parse(htmlTmpl)
	if err != nil {
		return err
	}
	return t.ExecuteTemplate(w, name, data)
}

func writeHTML(w io.Writer, rep *model.Report, lang, backURL string) error {
	t, err := template.New("report").Funcs(Funcs(lang)).Parse(htmlTmpl)
	if err != nil {
		return err
	}
	return t.Execute(w, map[string]any{
		"Report":  rep,
		"Summary": Summarize(rep),
		"Style":   template.CSS(Style),
		"BackURL": backURL,
	})
}

func humanBytes(v uint64) string {
	const unit = 1024
	if v < unit {
		return fmt.Sprintf("%d B", v)
	}
	div, exp := uint64(unit), 0
	for n := v / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(v)/float64(div), "KMGTPE"[exp])
}

func humanDuration(sec float64) string {
	d := time.Duration(sec) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	return fmt.Sprintf("%dh %dm", hours, int(d.Minutes())%60)
}

func writeMarkdown(w io.Writer, rep *model.Report, lang string) error {
	T := func(k string, a ...any) string { return i18n.T(lang, k, a...) }
	s := Summarize(rep)
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("# %s\n\n", T("report.title"))
	p("%s: %s | farol-guard %s\n\n", T("report.generated"), rep.GeneratedAt.Local().Format("2006-01-02 15:04"), rep.Version)
	p("| %s | %s | %s | %s | %s |\n|---|---|---|---|---|\n", T("report.hosts"), T("sev.critical"), T("sev.high"), T("report.secupdates"), T("report.cvefix"))
	p("| %d/%d %s | %d | %d | %d | %d |\n\n", s.Reachable, s.Hosts, T("report.reachable"), s.Critical, s.High, s.SecUpdates, s.CVEFix)

	p("## %s\n\n| %s | %s | %s | %s | %s | %s | %s |\n|---|---|---|---|---|---|---|\n",
		T("report.fleet"), T("report.host"), T("report.group"), T("report.os"), T("report.status"),
		T("report.updates"), T("report.cves"), T("report.disk"))
	for _, h := range rep.Hosts {
		status := T("sev." + h.Worst().String())
		if !h.Reachable {
			status = T("report.unreachable")
		}
		maxDisk := 0.0
		for _, d := range h.Disks {
			if d.UsedPct > maxDisk {
				maxDisk = d.UsedPct
			}
		}
		p("| %s | %s | %s | %s | %d (%d sec) | %d | %.0f%% |\n", h.Name, h.Group, h.OS.Pretty, status,
			len(h.Upgrades), h.SecurityUpgrades(), h.FixableVulns(0), maxDisk)
	}
	for _, h := range rep.Hosts {
		p("\n## %s (%s:%d)\n\n", h.Name, h.Address, h.Port)
		if len(h.Findings) == 0 {
			p("%s\n", T("report.none"))
		}
		for _, f := range h.Findings {
			p("- **%s** [%s] %s\n", T("sev."+f.Severity.String()), f.Category, f.Title)
			for _, d := range f.Details {
				p("  - `%s`\n", d)
			}
		}
		if !h.Reachable {
			continue
		}
		p("\n**%s:** %s, kernel %s, uptime %s\n", T("sec.system"), h.OS.Pretty, h.Kernel, humanDuration(h.UptimeSeconds))
		p("\n**%s**\n\n| %s | UID | %s | %s |\n|---|---|---|---|\n", T("sec.users"), T("c.user"), T("c.flags"), T("c.keys"))
		for _, u := range h.Users {
			var flags []string
			if u.Root {
				flags = append(flags, "root")
			}
			if u.Sudo {
				flags = append(flags, "sudo")
			}
			if u.NoPasswdSudo {
				flags = append(flags, T("t.nopasswd"))
			}
			if !u.CanLogin {
				flags = append(flags, T("t.nologin"))
			}
			p("| %s | %d | %s | %d |\n", u.Name, u.UID, strings.Join(flags, ", "), len(u.Keys))
		}
		if len(h.IPs) > 0 {
			p("\n**%s**\n\n| IP | %s | %s | %s | %s |\n|---|---|---|---|---|\n", T("sec.access"), T("c.users"), T("c.accepted"), T("c.failed"), T("c.last"))
			for i, ip := range h.IPs {
				if i == 30 {
					break
				}
				p("| %s | %s | %d | %d | %s |\n", ip.IP, strings.Join(ip.Users, ", "), ip.Accepted, ip.Failed, ip.Last)
			}
		}
		fixable := 0
		for _, v := range h.Vulns {
			if v.Fixed == "" || v.Rank() < 3 {
				continue
			}
			if fixable == 0 {
				p("\n**%s**\n\n| %s | %s | %s | %s |\n|---|---|---|---|\n", T("sec.cves"), T("c.id"), T("c.package"), T("c.severity"), T("c.fixed"))
			}
			fixable++
			if fixable > 50 {
				continue
			}
			p("| %s | %s %s | %s | %s |\n", v.ID, v.Package, v.Version, T("sev."+v.Severity), v.Fixed)
		}
	}
	return nil
}
