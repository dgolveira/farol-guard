package analyze

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/model"
)

var eolDates = map[string]string{
	"debian:10": "2024-06-30", "debian:11": "2026-08-31", "debian:12": "2028-06-30", "debian:13": "2030-06-30",
	"ubuntu:18.04": "2023-05-31", "ubuntu:20.04": "2025-05-31", "ubuntu:22.04": "2027-04-30",
	"ubuntu:24.04": "2029-04-30", "ubuntu:24.10": "2025-07-10", "ubuntu:25.04": "2026-01-15",
	"ubuntu:25.10": "2026-07-15", "ubuntu:26.04": "2031-04-30",
}

var weakAlgos = []string{"cbc", "arcfour", "hmac-md5", "-96", "diffie-hellman-group1-", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "ssh-dss"}

type adder struct {
	h *model.HostReport
}

func (a adder) addDetailed(sev model.Severity, cat, code string, details []string, args ...any) {
	a.h.Findings = append(a.h.Findings, model.Finding{Severity: sev, Category: cat, Code: code, Args: args, Details: details})
}

func (a adder) add(sev model.Severity, cat, code string, args ...any) {
	a.h.Findings = append(a.h.Findings, model.Finding{Severity: sev, Category: cat, Code: code, Args: args})
}

func Host(h *model.HostReport, t inventory.Thresholds, now time.Time) {
	h.Findings = nil
	a := adder{h}
	if !h.Reachable {
		if h.HostKey != nil {
			a.add(model.SevMedium, "access", "host_key_untrusted", h.HostKey.Type, h.HostKey.Fingerprint)
			return
		}
		a.add(model.SevHigh, "access", "host_unreachable", h.Error)
		return
	}
	if h.Error != "" {
		a.add(model.SevMedium, "access", "collector_error", h.Error)
	}
	if !h.Privileged {
		a.add(model.SevInfo, "access", "limited_privileges", h.User)
	}

	users(a, h)
	sshd(a, h)
	system(a, h, t, now)
	updates(a, h, t)
	vulns(a, h)
	resources(a, h, t)
	network(a, h, t)

	sort.SliceStable(h.Findings, func(i, j int) bool { return h.Findings[i].Severity > h.Findings[j].Severity })
}

func users(a adder, h *model.HostReport) {
	unknown := 0
	for _, u := range h.Users {
		if u.Root && u.Name != "root" {
			a.add(model.SevCritical, "users", "uid0_extra", u.Name)
		}
		if u.PasswordState == "empty" && u.CanLogin {
			a.add(model.SevCritical, "users", "empty_password", u.Name)
		}
		if u.NoPasswdSudo && u.Name != "root" {
			a.add(model.SevLow, "users", "nopasswd_sudo", u.Name)
		}
		for _, k := range u.Keys {
			if k.Label == "" && k.Farol == "" {
				unknown++
			}
			if k.Type == "ssh-dss" || (k.Type == "ssh-rsa" && strings.Contains(k.Comment, "1024")) {
				a.add(model.SevMedium, "keys", "weak_key", u.Name, k.Fingerprint)
			}
		}
	}
	if unknown > 0 {
		a.add(model.SevLow, "keys", "unknown_keys", unknown)
	}
	others := map[string]bool{}
	for _, u := range h.Users {
		for _, k := range u.Keys {
			if k.Farol == "other" {
				others[k.FarolHost] = true
			}
		}
	}
	if len(others) > 0 {
		hosts := make([]string, 0, len(others))
		for o := range others {
			hosts = append(hosts, o)
		}
		sort.Strings(hosts)
		a.add(model.SevInfo, "keys", "farol_other_install", strings.Join(hosts, ", "))
	}
}

func sshd(a adder, h *model.HostReport) {
	c := h.SSHD
	if len(c.Settings) == 0 {
		a.add(model.SevInfo, "ssh", "sshd_unavailable")
		return
	}
	if !c.Effective {
		a.add(model.SevInfo, "ssh", "sshd_not_effective")
	}
	pass := strings.ToLower(c.Get("passwordauthentication"))
	if pass == "" && !c.Effective {
		pass = "yes"
	}
	root := strings.ToLower(c.Get("permitrootlogin"))
	switch {
	case root == "yes" && pass == "yes":
		a.add(model.SevHigh, "ssh", "root_password_login")
	case root == "yes":
		a.add(model.SevLow, "ssh", "root_login_yes")
	}
	if pass == "yes" {
		a.add(model.SevMedium, "ssh", "password_auth")
	}
	if strings.ToLower(c.Get("permitemptypasswords")) == "yes" {
		a.add(model.SevCritical, "ssh", "permit_empty_passwords")
	}
	if strings.ToLower(c.Get("x11forwarding")) == "yes" {
		a.add(model.SevLow, "ssh", "x11_forwarding")
	}
	if n, err := strconv.Atoi(c.Get("maxauthtries")); err == nil && n > 6 {
		a.add(model.SevLow, "ssh", "max_auth_tries", n)
	}
	var weak []string
	for _, k := range []string{"ciphers", "macs", "kexalgorithms", "hostkeyalgorithms"} {
		for _, alg := range strings.Split(c.Get(k), ",") {
			for _, w := range weakAlgos {
				if alg != "" && strings.Contains(alg, w) {
					weak = append(weak, alg)
					break
				}
			}
		}
	}
	if len(weak) > 0 {
		a.add(model.SevMedium, "ssh", "weak_algorithms", strings.Join(weak, ", "))
	}
}

func system(a adder, h *model.HostReport, t inventory.Thresholds, now time.Time) {
	if h.OS.ID != "debian" && h.OS.ID != "ubuntu" {
		a.add(model.SevInfo, "system", "unsupported_os", h.OS.Pretty)
	}
	key := h.OS.ID + ":" + h.OS.VersionID
	if h.OS.ID == "debian" {
		major, _, _ := strings.Cut(h.OS.VersionID, ".")
		key = "debian:" + major
	}
	if d, ok := eolDates[key]; ok {
		h.OS.EOL = d
		if eol, err := time.Parse("2006-01-02", d); err == nil {
			switch days := eol.Sub(now).Hours() / 24; {
			case days < 0:
				a.add(model.SevHigh, "system", "os_eol", h.OS.Pretty, d)
			case days < 180:
				a.add(model.SevMedium, "system", "os_eol_soon", h.OS.Pretty, d)
			}
		}
	}
	if h.Reboot {
		a.add(model.SevMedium, "system", "reboot_required", strings.Join(h.RebootPkgs, ", "))
	}
	if len(h.FailedUnits) > 0 {
		a.add(model.SevMedium, "system", "failed_units", len(h.FailedUnits), strings.Join(h.FailedUnits, ", "))
	}
	if h.TimeSync == "no" {
		a.add(model.SevLow, "system", "time_unsynced")
	}
	if len(h.KernelErr) > 0 {
		a.add(model.SevLow, "system", "kernel_errors", len(h.KernelErr))
	}
}

func updates(a adder, h *model.HostReport, t inventory.Thresholds) {
	if sec := h.SecurityUpgrades(); sec > 0 {
		a.add(model.SevHigh, "updates", "security_updates", sec)
	}
	if n := len(h.Upgrades) - h.SecurityUpgrades(); n > 0 {
		a.add(model.SevLow, "updates", "pending_updates", n)
	}
	if h.AptListsAge > t.AptListsMaxDays {
		a.add(model.SevLow, "updates", "apt_lists_stale", int(h.AptListsAge))
	}
	if !h.Unattended && len(h.Packages) > 0 {
		a.add(model.SevLow, "updates", "unattended_disabled")
	}
}

const maxDetails = 12

func upgradeCommand(binaries []string) string {
	return "apt-get install --only-upgrade " + strings.Join(binaries, " ")
}

func annotateVulns(h *model.HostReport) {
	bySource := map[string][]string{}
	for _, p := range h.Packages {
		bySource[p.Source+"\x00"+p.SourceVersion] = append(bySource[p.Source+"\x00"+p.SourceVersion], p.Name)
	}
	candidate := map[string]string{}
	for _, u := range h.Upgrades {
		candidate[u.Name] = u.NewVersion
	}
	fixAll := map[string]bool{}
	for i := range h.Vulns {
		v := &h.Vulns[i]
		v.Binaries = bySource[v.Package+"\x00"+v.Version]
		sort.Strings(v.Binaries)
		v.Candidate = ""
		for _, b := range v.Binaries {
			if c := candidate[b]; c != "" {
				v.Candidate = c
			}
		}
		if v.Fixed != "" {
			for _, b := range v.Binaries {
				fixAll[b] = true
			}
		}
	}
	h.FixAll = ""
	if len(fixAll) > 0 {
		all := make([]string, 0, len(fixAll))
		for b := range fixAll {
			all = append(all, b)
		}
		sort.Strings(all)
		h.FixAll = upgradeCommand(all)
	}
}

func vulnDetails(list []model.Vuln) []string {
	var out []string
	for i, v := range list {
		if i == maxDetails {
			out = append(out, fmt.Sprintf("+%d", len(list)-maxDetails))
			break
		}
		line := fmt.Sprintf("%s · %s %s → %s", v.ID, v.Package, v.Version, v.Fixed)
		if len(v.Binaries) > 0 {
			line += " · " + upgradeCommand(v.Binaries)
		}
		out = append(out, line)
	}
	return out
}

func vulns(a adder, h *model.HostReport) {
	annotateVulns(h)
	var crit, high, other []model.Vuln
	unfixed := 0
	for _, v := range h.Vulns {
		if v.Fixed == "" {
			if v.Rank() >= 3 {
				unfixed++
			}
			continue
		}
		switch v.Rank() {
		case 4:
			crit = append(crit, v)
		case 3:
			high = append(high, v)
		default:
			other = append(other, v)
		}
	}
	if len(crit) > 0 {
		a.addDetailed(model.SevCritical, "cve", "cve_critical_fixable", vulnDetails(crit), len(crit))
	}
	if len(high) > 0 {
		a.addDetailed(model.SevHigh, "cve", "cve_high_fixable", vulnDetails(high), len(high))
	}
	if len(other) > 0 {
		a.addDetailed(model.SevMedium, "cve", "cve_other_fixable", vulnDetails(other), len(other))
	}
	if unfixed > 0 {
		a.add(model.SevInfo, "cve", "cve_unfixed", unfixed)
	}
	for _, b := range h.VulnBulk {
		a.add(model.SevInfo, "cve", "cve_bulk", b.Package, b.Version, b.Count)
	}
}

func resources(a adder, h *model.HostReport, t inventory.Thresholds) {
	for _, d := range h.Disks {
		switch {
		case d.UsedPct >= t.DiskCrit:
			a.add(model.SevCritical, "resources", "disk_usage", d.Mount, d.UsedPct)
		case d.UsedPct >= t.DiskWarn:
			a.add(model.SevMedium, "resources", "disk_usage", d.Mount, d.UsedPct)
		}
		switch {
		case d.InodePct >= t.InodeCrit:
			a.add(model.SevCritical, "resources", "inode_usage", d.Mount, d.InodePct)
		case d.InodePct >= t.InodeWarn:
			a.add(model.SevMedium, "resources", "inode_usage", d.Mount, d.InodePct)
		}
	}
	switch m := h.Memory.UsedPct; {
	case m >= t.MemCrit:
		a.add(model.SevHigh, "resources", "memory_usage", m)
	case m >= t.MemWarn:
		a.add(model.SevMedium, "resources", "memory_usage", m)
	}
	if h.Memory.SwapPct >= t.SwapWarn {
		a.add(model.SevLow, "resources", "swap_usage", h.Memory.SwapPct)
	}
	if h.CPU.Cores > 0 {
		per := h.CPU.Load5 / float64(h.CPU.Cores)
		switch {
		case per >= t.LoadCrit:
			a.add(model.SevHigh, "resources", "load_high", h.CPU.Load5, h.CPU.Cores)
		case per >= t.LoadWarn:
			a.add(model.SevMedium, "resources", "load_high", h.CPU.Load5, h.CPU.Cores)
		}
	}
	if h.CPU.UsagePct >= t.CPUWarn {
		a.add(model.SevMedium, "resources", "cpu_usage", h.CPU.UsagePct)
	}
}

func network(a adder, h *model.HostReport, t inventory.Thresholds) {
	for _, n := range h.Interfaces {
		if errs := n.RxErrs + n.TxErrs; errs > 0 {
			a.add(model.SevLow, "network", "iface_errors", n.Name, errs, n.RxDrop+n.TxDrop)
		}
	}
	failed, ips := 0, 0
	for _, s := range h.IPs {
		if s.Failed > 0 {
			failed += s.Failed
			ips++
		}
	}
	if failed >= t.FailedLoginsWarn {
		sev := model.SevLow
		if len(h.Fail2ban) == 0 {
			sev = model.SevMedium
		}
		a.add(sev, "network", "failed_logins", failed, ips)
	}
	active := false
	for _, l := range h.Firewall {
		if strings.HasPrefix(l, "Status: active") {
			active = true
		}
		if k, v, ok := strings.Cut(l, "="); ok && (k == "nft_rules" || k == "iptables_rules") {
			if n, _ := strconv.Atoi(v); n > 0 {
				active = true
			}
		}
	}
	if !active && h.Privileged {
		a.add(model.SevLow, "network", "firewall_inactive")
	}
}
