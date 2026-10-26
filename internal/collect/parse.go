package collect

import (
	"bufio"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/dgolveira/farol-guard/internal/model"
	"golang.org/x/crypto/ssh"
)

const marker = "@@farol:"

func splitSections(out []byte) map[string][]string {
	sec := map[string][]string{}
	cur := ""
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, marker) {
			cur = strings.TrimPrefix(line, marker)
			if _, ok := sec[cur]; !ok {
				sec[cur] = []string{}
			}
			continue
		}
		if cur == "" || strings.TrimSpace(line) == "" {
			continue
		}
		sec[cur] = append(sec[cur], line)
	}
	return sec
}

func kv(lines []string, sep string) map[string]string {
	m := map[string]string{}
	for _, l := range lines {
		if k, v, ok := strings.Cut(l, sep); ok {
			m[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return m
}

func Parse(h *model.HostReport, out []byte, keyLabels map[string]string) {
	s := splitSections(out)

	meta := kv(s["meta"], "=")
	h.Privileged = meta["uid"] == "0"
	h.Hostname = meta["hostname"]

	osr := kv(s["os_release"], "=")
	h.OS = model.OSInfo{
		ID:        osr["ID"],
		VersionID: osr["VERSION_ID"],
		Codename:  firstNonEmpty(osr["VERSION_CODENAME"], osr["UBUNTU_CODENAME"]),
		Pretty:    osr["PRETTY_NAME"],
		LTS:       strings.Contains(osr["VERSION"], "LTS"),
	}
	family := ""
	if f := s["pkg_family"]; len(f) > 0 && f[0] != "unknown" {
		family = f[0]
		if len(f) > 1 {
			h.OS.PkgTool = f[1]
		}
	}
	resolveBase(&h.OS, osr, family)
	if len(s["kernel"]) > 0 {
		h.Kernel = s["kernel"][0]
	}
	if len(s["uptime"]) > 0 {
		h.UptimeSeconds, _ = strconv.ParseFloat(s["uptime"][0], 64)
	}

	h.Users = parseUsers(s, keyLabels)
	h.SSHD = parseSSHD(s)
	switch h.OS.Family {
	case model.FamilyRPM:
		h.Packages = parseRPMPackages(s["packages_rpm"])
		h.Advisories = parseRPMAdvisories(s["security_rpm"])
		h.Upgrades = parseRPMUpgrades(s["upgradable_rpm"], h.Packages, h.Advisories)
		h.Unattended = len(s["unattended_rpm"]) > 0
	case model.FamilySUSE:
		h.Packages = parseRPMPackages(s["packages_rpm"])
		h.Upgrades = parseSUSEUpgrades(s["upgradable_suse"], h.Packages, parseSUSEPatches(s["patches_suse"]))
		h.Unattended = len(s["unattended_rpm"]) > 0
	case model.FamilyArch:
		h.Packages = parseArchPackages(s["packages_arch"])
		h.Upgrades = parseArchUpgrades(s["upgradable_arch"])
	default:
		h.Packages = parsePackages(s["packages"])
		h.Upgrades = parseUpgrades(s["upgradable"])
		h.Unattended = parseUnattended(s["unattended"])
	}
	if l := s["apt_lists_mtime"]; len(l) == 2 {
		mt, _ := strconv.ParseFloat(l[0], 64)
		now, _ := strconv.ParseFloat(l[1], 64)
		if mt > 0 {
			h.AptListsAge = (now - mt) / 86400
		}
	}
	if r := s["reboot_required"]; len(r) > 0 && r[0] == "yes" {
		h.Reboot = true
		seen := map[string]bool{}
		for _, p := range r[1:] {
			if !seen[p] {
				seen[p] = true
				h.RebootPkgs = append(h.RebootPkgs, p)
			}
		}
	}
	h.Snaps = parseSnaps(s["snaps"])
	h.Containers = parseContainers(s["containers"])
	h.Services = s["services"]
	h.FailedUnits = s["failed_units"]
	h.Listening = parseListening(s["listening"])
	h.Logins, h.IPs = parseLogins(s["sshd_log"], keyLabels)
	h.LastRaw = s["last"]
	h.Fail2ban = s["fail2ban"]
	h.Firewall = s["firewall"]
	if t := s["time_sync"]; len(t) > 0 {
		h.TimeSync = t[0]
	}
	h.KernelErr = s["kernel_errors"]
	h.Interfaces = parseInterfaces(s["ip_addr"], s["net_dev"])
	h.Disks = parseDisks(s["df"], s["df_inodes"])
	h.Memory = parseMemory(s["meminfo"])
	h.CPU = parseCPU(s["loadavg"], s["cpu_stat"])
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

var nologinShells = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true,
	"/usr/bin/false": true, "/bin/sync": true, "": true,
}

func parseUsers(s map[string][]string, keyLabels map[string]string) []model.User {
	sudoGroups := map[string]bool{}
	for _, l := range s["group"] {
		f := strings.Split(l, ":")
		if len(f) < 4 {
			continue
		}
		if f[0] == "sudo" || f[0] == "wheel" || f[0] == "admin" {
			for _, m := range strings.Split(f[3], ",") {
				if m != "" {
					sudoGroups[m] = true
				}
			}
		}
	}
	shadow := kv(s["shadow"], ":")
	nopasswd := s["sudoers"]

	keys := map[string][]model.AuthKey{}
	for _, l := range s["authorized_keys"] {
		f := strings.SplitN(l, "\t", 3)
		if len(f) != 3 {
			continue
		}
		pub, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(f[2]))
		if err != nil {
			continue
		}
		fp := ssh.FingerprintSHA256(pub)
		keys[f[0]] = append(keys[f[0]], model.AuthKey{
			User: f[0], File: f[1], Type: pub.Type(), Fingerprint: fp,
			Comment: comment, Options: strings.Join(opts, ","), Label: keyLabels[fp],
		})
	}

	var users []model.User
	for _, l := range s["passwd"] {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		u := model.User{
			Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6],
			CanLogin:      !nologinShells[f[6]],
			Root:          uid == 0,
			Sudo:          sudoGroups[f[0]],
			PasswordState: shadow[f[0]],
			Keys:          keys[f[0]],
		}
		for _, rule := range nopasswd {
			fields := strings.Fields(rule)
			if len(fields) == 0 {
				continue
			}
			who := fields[0]
			if who == f[0] || (strings.HasPrefix(who, "%") && groupHas(s["group"], who[1:], f[0], gid)) {
				u.NoPasswdSudo = true
				u.Sudo = true
			}
		}
		if uid == 0 || uid >= 1000 || u.CanLogin || len(u.Keys) > 0 || u.Sudo {
			if (uid == 65534 || strings.HasPrefix(u.Name, "snapd-range-")) && !u.CanLogin && len(u.Keys) == 0 {
				continue
			}
			users = append(users, u)
		}
	}
	return users
}

func groupHas(groups []string, group, user string, gid int) bool {
	for _, l := range groups {
		f := strings.Split(l, ":")
		if len(f) < 4 || f[0] != group {
			continue
		}
		if g, _ := strconv.Atoi(f[2]); g == gid {
			return true
		}
		for _, m := range strings.Split(f[3], ",") {
			if m == user {
				return true
			}
		}
	}
	return false
}

func parseSSHD(s map[string][]string) model.SSHDConfig {
	cfg := model.SSHDConfig{Settings: map[string][]string{}}
	lines := s["sshd_effective"]
	if len(lines) > 0 {
		cfg.Effective = true
	} else {
		lines = s["sshd_file"]
	}
	seen := map[string]bool{}
	inMatch := false
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, _ := strings.Cut(strings.Join(strings.Fields(l), " "), " ")
		k = strings.ToLower(k)
		if k == "match" {
			inMatch = true
		}
		if inMatch {
			continue
		}
		if !cfg.Effective && seen[k] {
			continue
		}
		seen[k] = true
		cfg.Settings[k] = append(cfg.Settings[k], v)
	}
	if v := s["ssh_version"]; len(v) > 0 {
		cfg.Version = v[0]
	}
	return cfg
}

func parsePackages(lines []string) []model.Package {
	var out []model.Package
	for _, l := range lines {
		f := strings.Split(l, "\t")
		if len(f) < 5 || !strings.HasPrefix(f[0], "ii") {
			continue
		}
		name := f[1]
		if i := strings.IndexByte(name, ':'); i > 0 {
			name = name[:i]
		}
		src, srcVer := f[3], f[4]
		if src == "" {
			src = name
		}
		if srcVer == "" {
			srcVer = f[2]
		}
		out = append(out, model.Package{Name: name, Version: f[2], Source: src, SourceVersion: srcVer})
	}
	return out
}

var upgradeRe = regexp.MustCompile(`^(\S+)/(\S+)\s+(\S+)\s+\S+(?:\s+\[upgradable from: ([^\]]+)\])?`)

func parseUpgrades(lines []string) []model.Upgrade {
	var out []model.Upgrade
	for _, l := range lines {
		m := upgradeRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		out = append(out, model.Upgrade{
			Name: m[1], Suite: m[2], NewVersion: m[3], OldVersion: m[4],
			Security: strings.Contains(m[2], "-security"),
		})
	}
	return out
}

func parseUnattended(lines []string) bool {
	installed := false
	enabled := false
	for _, l := range lines {
		if strings.HasPrefix(l, "ii") {
			installed = true
		}
		if strings.HasPrefix(l, "APT::Periodic::Unattended-Upgrade") {
			v := strings.Trim(strings.TrimSuffix(strings.Fields(l)[len(strings.Fields(l))-1], ";"), `"`)
			enabled = v != "0"
		}
	}
	return installed && enabled
}

func parseSnaps(lines []string) []model.Snap {
	var out []model.Snap
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		out = append(out, model.Snap{Name: f[0], Version: f[1], Revision: f[2], Channel: f[3]})
	}
	return out
}

func parseContainers(lines []string) []model.Container {
	var out []model.Container
	for _, l := range lines {
		f := strings.SplitN(l, "\t", 3)
		if len(f) == 3 {
			out = append(out, model.Container{Name: f[0], Image: f[1], Status: f[2]})
		}
	}
	return out
}

var procRe = regexp.MustCompile(`users:\(\("([^"]+)"`)

func parseListening(lines []string) []model.Listener {
	var out []model.Listener
	seen := map[string]bool{}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		if f[0] == "udp" && f[1] != "UNCONN" {
			continue
		}
		proc := ""
		if m := procRe.FindStringSubmatch(l); m != nil {
			proc = m[1]
		}
		key := f[0] + f[4] + proc
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, model.Listener{Proto: f[0], Address: f[4], Process: proc})
	}
	return out
}

var (
	acceptedRe = regexp.MustCompile(`Accepted (\S+) for (\S+) from (\S+) port \d+(?: ssh2)?(?:: (\S+) (\S+))?`)
	failedRe   = regexp.MustCompile(`Failed (\S+) for (?:invalid user )?(\S*) from (\S+) port`)
	invalidRe  = regexp.MustCompile(`Invalid user (\S*) from (\S+)`)
	isoTimeRe  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`)
	syslogRe   = regexp.MustCompile(`^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}`)
)

func logTime(l string) string {
	f := strings.Fields(l)
	if len(f) == 0 {
		return ""
	}
	if isoTimeRe.MatchString(f[0]) {
		return f[0]
	}
	if syslogRe.MatchString(l) && len(f) >= 3 {
		return strings.Join(f[:3], " ")
	}
	return ""
}

func parseLogins(lines []string, keyLabels map[string]string) ([]model.Login, []model.IPSummary) {
	var logins []model.Login
	ips := map[string]*model.IPSummary{}
	users := map[string]map[string]bool{}
	keys := map[string]map[string]bool{}
	get := func(ip string) *model.IPSummary {
		if s, ok := ips[ip]; ok {
			return s
		}
		s := &model.IPSummary{IP: ip}
		ips[ip] = s
		users[ip] = map[string]bool{}
		keys[ip] = map[string]bool{}
		return s
	}
	for _, l := range lines {
		t := logTime(l)
		if m := acceptedRe.FindStringSubmatch(l); m != nil {
			lg := model.Login{Time: t, Method: m[1], User: m[2], IP: m[3], Fingerprint: m[5], Success: true}
			lg.KeyLabel = keyLabels[lg.Fingerprint]
			logins = append(logins, lg)
			s := get(lg.IP)
			s.Accepted++
			s.Last = t
			users[lg.IP][lg.User] = true
			if lg.Fingerprint != "" {
				name := lg.Fingerprint
				if lg.KeyLabel != "" {
					name = lg.KeyLabel
				}
				keys[lg.IP][name] = true
			}
			continue
		}
		if m := failedRe.FindStringSubmatch(l); m != nil {
			get(m[3]).Failed++
			users[m[3]][m[2]] = true
			continue
		}
		if m := invalidRe.FindStringSubmatch(l); m != nil {
			get(m[2])
			users[m[2]][m[1]] = true
		}
	}
	var out []model.IPSummary
	for ip, s := range ips {
		s.Users = sortedKeys(users[ip])
		s.Keys = sortedKeys(keys[ip])
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Accepted != out[j].Accepted {
			return out[i].Accepted > out[j].Accepted
		}
		return out[i].Failed > out[j].Failed
	})
	if len(logins) > 200 {
		logins = logins[len(logins)-200:]
	}
	return logins, out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func parseInterfaces(addr, dev []string) []model.NetIface {
	ifs := map[string]*model.NetIface{}
	var order []string
	for _, l := range addr {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		name := strings.SplitN(f[0], "@", 2)[0]
		ifs[name] = &model.NetIface{Name: name, State: f[1], Addrs: f[2:]}
		order = append(order, name)
	}
	for _, l := range dev {
		name, rest, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if len(f) < 12 {
			continue
		}
		n, ok := ifs[name]
		if !ok {
			n = &model.NetIface{Name: name}
			ifs[name] = n
			order = append(order, name)
		}
		n.RxErrs, n.RxDrop = atou(f[2]), atou(f[3])
		n.TxErrs, n.TxDrop = atou(f[10]), atou(f[11])
	}
	var out []model.NetIface
	for _, name := range order {
		if name == "lo" || strings.HasPrefix(name, "veth") {
			continue
		}
		out = append(out, *ifs[name])
	}
	return out
}

func parseDisks(df, inodes []string) []model.Disk {
	ipct := map[string]float64{}
	for _, l := range inodes {
		f := strings.Fields(l)
		if len(f) < 6 || f[0] == "Filesystem" {
			continue
		}
		ipct[strings.Join(f[5:], " ")] = pct(f[4])
	}
	var out []model.Disk
	for _, l := range df {
		f := strings.Fields(l)
		if len(f) < 7 || f[0] == "Filesystem" {
			continue
		}
		mount := strings.Join(f[6:], " ")
		out = append(out, model.Disk{
			Filesystem: f[0], Type: f[1], Size: atou(f[2]), Used: atou(f[3]), Avail: atou(f[4]),
			UsedPct: pct(f[5]), Mount: mount, InodePct: ipct[mount],
		})
	}
	return out
}

func parseMemory(lines []string) model.Memory {
	m := map[string]uint64{}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) >= 2 {
			m[strings.TrimSuffix(f[0], ":")] = atou(f[1])
		}
	}
	mem := model.Memory{TotalKB: m["MemTotal"], AvailKB: m["MemAvailable"], SwapTotalKB: m["SwapTotal"], SwapFreeKB: m["SwapFree"]}
	if mem.TotalKB > 0 {
		mem.UsedPct = 100 * float64(mem.TotalKB-mem.AvailKB) / float64(mem.TotalKB)
	}
	if mem.SwapTotalKB > 0 {
		mem.SwapPct = 100 * float64(mem.SwapTotalKB-mem.SwapFreeKB) / float64(mem.SwapTotalKB)
	}
	return mem
}

func parseCPU(load, stat []string) model.CPU {
	var c model.CPU
	if len(load) >= 1 {
		f := strings.Fields(load[0])
		if len(f) >= 3 {
			c.Load1, _ = strconv.ParseFloat(f[0], 64)
			c.Load5, _ = strconv.ParseFloat(f[1], 64)
			c.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	if len(load) >= 2 {
		c.Cores, _ = strconv.Atoi(strings.TrimSpace(load[1]))
	}
	if len(stat) == 2 {
		i1, t1 := cpuTimes(stat[0])
		i2, t2 := cpuTimes(stat[1])
		if t2 > t1 {
			c.UsagePct = 100 * (1 - float64(i2-i1)/float64(t2-t1))
		}
	}
	return c
}

func cpuTimes(l string) (idle, total uint64) {
	f := strings.Fields(l)
	for i, v := range f[1:] {
		n := atou(v)
		total += n
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return
}

func atou(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

func pct(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
	return v
}
