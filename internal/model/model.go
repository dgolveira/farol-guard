package model

import (
	"fmt"
	"strings"
	"time"
)

type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if int(s) < 0 || int(s) >= len(severityNames) {
		return "info"
	}
	return severityNames[s]
}

func ParseSeverity(v string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(v, n) {
			return Severity(i), nil
		}
	}
	return SevInfo, fmt.Errorf("unknown severity %q", v)
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	*s = v
	return err
}

type Finding struct {
	Severity Severity `json:"severity"`
	Category string   `json:"category"`
	Code     string   `json:"code"`
	Args     []any    `json:"args,omitempty"`
	Title    string   `json:"title"`
	Details  []string `json:"details,omitempty"`
}

type AuthKey struct {
	User        string `json:"user"`
	File        string `json:"file"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment,omitempty"`
	Options     string `json:"options,omitempty"`
	Label       string `json:"label,omitempty"`
	Farol       string `json:"farol,omitempty"`
	FarolHost   string `json:"farol_host,omitempty"`
}

type User struct {
	Name          string    `json:"name"`
	UID           int       `json:"uid"`
	GID           int       `json:"gid"`
	Home          string    `json:"home"`
	Shell         string    `json:"shell"`
	CanLogin      bool      `json:"can_login"`
	Root          bool      `json:"root"`
	Sudo          bool      `json:"sudo"`
	NoPasswdSudo  bool      `json:"nopasswd_sudo"`
	PasswordState string    `json:"password_state,omitempty"`
	Keys          []AuthKey `json:"keys,omitempty"`
}

type OSInfo struct {
	ID          string `json:"id"`
	VersionID   string `json:"version_id"`
	Codename    string `json:"codename"`
	Pretty      string `json:"pretty"`
	LTS         bool   `json:"lts"`
	EOL         string `json:"eol,omitempty"`
	Family      string `json:"family,omitempty"`
	PkgTool     string `json:"pkg_tool,omitempty"`
	BaseID      string `json:"base_id,omitempty"`
	BaseVersion string `json:"base_version,omitempty"`
}

const (
	FamilyDeb  = "deb"
	FamilyRPM  = "rpm"
	FamilyArch = "arch"
	FamilySUSE = "suse"
)

func (o OSInfo) Rolling() bool {
	return o.Family == FamilyArch || o.BaseID == "opensuse-tumbleweed"
}

func (o OSInfo) Derived() bool {
	return o.BaseID != "" && o.BaseID != o.ID
}

type RPMAdvisory struct {
	ID       string `json:"id"`
	CVE      string `json:"cve,omitempty"`
	Severity string `json:"severity"`
	Package  string `json:"package"`
}

type SSHDConfig struct {
	Effective bool                `json:"effective"`
	Settings  map[string][]string `json:"settings,omitempty"`
	Version   string              `json:"version,omitempty"`
}

func (c SSHDConfig) Get(key string) string {
	if v := c.Settings[strings.ToLower(key)]; len(v) > 0 {
		return v[0]
	}
	return ""
}

type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
}

type FixPlan struct {
	Family          string   `json:"family"`
	Rolling         bool     `json:"rolling,omitempty"`
	Packages        []string `json:"packages"`
	Sensitive       []string `json:"sensitive,omitempty"`
	NotInApt        int      `json:"not_in_apt,omitempty"`
	Security        []string `json:"security_packages,omitempty"`
	Command         string   `json:"command"`
	Simulate        string   `json:"simulate"`
	SecurityCommand string   `json:"security_command,omitempty"`
	After           []string `json:"after"`
}

type Upgrade struct {
	Name       string `json:"name"`
	Suite      string `json:"suite"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
	Security   bool   `json:"security"`
}

type Container struct {
	Name   string `json:"name"`
	Image  string `json:"image"`
	Status string `json:"status"`
}

type Snap struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Channel  string `json:"channel"`
	Revision string `json:"revision"`
}

type Listener struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Process string `json:"process,omitempty"`
}

type Login struct {
	Time        string `json:"time"`
	User        string `json:"user"`
	IP          string `json:"ip"`
	Method      string `json:"method"`
	Fingerprint string `json:"fingerprint,omitempty"`
	KeyLabel    string `json:"key_label,omitempty"`
	Success     bool   `json:"success"`
}

type IPSummary struct {
	IP       string   `json:"ip"`
	Users    []string `json:"users"`
	Keys     []string `json:"keys,omitempty"`
	Accepted int      `json:"accepted"`
	Failed   int      `json:"failed"`
	Last     string   `json:"last"`
}

type NetIface struct {
	Name   string   `json:"name"`
	State  string   `json:"state"`
	Addrs  []string `json:"addrs,omitempty"`
	RxErrs uint64   `json:"rx_errors"`
	RxDrop uint64   `json:"rx_dropped"`
	TxErrs uint64   `json:"tx_errors"`
	TxDrop uint64   `json:"tx_dropped"`
}

type Disk struct {
	Filesystem string  `json:"filesystem"`
	Type       string  `json:"type"`
	Mount      string  `json:"mount"`
	Size       uint64  `json:"size"`
	Used       uint64  `json:"used"`
	Avail      uint64  `json:"avail"`
	UsedPct    float64 `json:"used_pct"`
	InodePct   float64 `json:"inode_pct"`
}

type Memory struct {
	TotalKB     uint64  `json:"total_kb"`
	AvailKB     uint64  `json:"available_kb"`
	SwapTotalKB uint64  `json:"swap_total_kb"`
	SwapFreeKB  uint64  `json:"swap_free_kb"`
	UsedPct     float64 `json:"used_pct"`
	SwapPct     float64 `json:"swap_pct"`
}

type CPU struct {
	Cores    int     `json:"cores"`
	Load1    float64 `json:"load1"`
	Load5    float64 `json:"load5"`
	Load15   float64 `json:"load15"`
	UsagePct float64 `json:"usage_pct"`
}

type Vuln struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases,omitempty"`
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	Fixed     string   `json:"fixed,omitempty"`
	Severity  string   `json:"severity"`
	Score     float64  `json:"score,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Details   string   `json:"details,omitempty"`
	Binaries  []string `json:"binaries,omitempty"`
	Candidate string   `json:"apt_candidate,omitempty"`
	FixCmd    string   `json:"fix_command,omitempty"`
	Advisory  string   `json:"advisory,omitempty"`
}

func (v Vuln) Rank() int {
	switch v.Severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

type HostReport struct {
	Name          string        `json:"name"`
	Address       string        `json:"address"`
	Port          int           `json:"port"`
	User          string        `json:"user"`
	Group         string        `json:"group"`
	Tags          []string      `json:"tags,omitempty"`
	Reachable     bool          `json:"reachable"`
	HostKey       *HostKeyInfo  `json:"host_key_pending,omitempty"`
	Error         string        `json:"error,omitempty"`
	Privileged    bool          `json:"privileged"`
	CollectedAt   time.Time     `json:"collected_at"`
	Duration      time.Duration `json:"duration_ns"`
	Hostname      string        `json:"hostname,omitempty"`
	OS            OSInfo        `json:"os"`
	Kernel        string        `json:"kernel,omitempty"`
	UptimeSeconds float64       `json:"uptime_seconds"`

	Users       []User        `json:"users,omitempty"`
	SSHD        SSHDConfig    `json:"sshd"`
	Packages    []Package     `json:"packages,omitempty"`
	Upgrades    []Upgrade     `json:"upgrades,omitempty"`
	AptListsAge float64       `json:"apt_lists_age_days"`
	Reboot      bool          `json:"reboot_required"`
	RebootPkgs  []string      `json:"reboot_packages,omitempty"`
	Unattended  bool          `json:"unattended_upgrades"`
	Advisories  []RPMAdvisory `json:"rpm_advisories,omitempty"`
	Snaps       []Snap        `json:"snaps,omitempty"`
	Containers  []Container   `json:"containers,omitempty"`
	Services    []string      `json:"services,omitempty"`
	FailedUnits []string      `json:"failed_units,omitempty"`
	Listening   []Listener    `json:"listening,omitempty"`

	Logins    []Login     `json:"logins,omitempty"`
	IPs       []IPSummary `json:"ips,omitempty"`
	LastRaw   []string    `json:"last_raw,omitempty"`
	Fail2ban  []string    `json:"fail2ban,omitempty"`
	Firewall  []string    `json:"firewall,omitempty"`
	TimeSync  string      `json:"time_sync,omitempty"`
	KernelErr []string    `json:"kernel_errors,omitempty"`

	Interfaces []NetIface `json:"interfaces,omitempty"`
	Disks      []Disk     `json:"disks,omitempty"`
	Memory     Memory     `json:"memory"`
	CPU        CPU        `json:"cpu"`

	Vulns    []Vuln     `json:"vulns,omitempty"`
	FixAll   string     `json:"fix_all_command,omitempty"`
	Fix      *FixPlan   `json:"fix_plan,omitempty"`
	VulnBulk []VulnBulk `json:"vuln_bulk,omitempty"`
	Findings []Finding  `json:"findings,omitempty"`
}

func (h *HostReport) Worst() Severity {
	w := SevInfo
	for _, f := range h.Findings {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

func (h *HostReport) CountFindings(s Severity) int {
	n := 0
	for _, f := range h.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

func (h *HostReport) SecurityUpgrades() int {
	n := 0
	for _, u := range h.Upgrades {
		if u.Security {
			n++
		}
	}
	return n
}

func (h *HostReport) FixableVulns(minRank int) int {
	n := 0
	for _, v := range h.Vulns {
		if v.Fixed != "" && v.Rank() >= minRank {
			n++
		}
	}
	return n
}

type HostKeyInfo struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Key         string `json:"key,omitempty"`
	Skipped     bool   `json:"skipped,omitempty"`
}

type Report struct {
	Tool        string        `json:"tool"`
	Version     string        `json:"version"`
	GeneratedAt time.Time     `json:"generated_at"`
	CVEChecked  bool          `json:"cve_checked"`
	Limits      Limits        `json:"limits"`
	Hosts       []*HostReport `json:"hosts"`
}

type Limits struct {
	DiskWarn float64 `json:"disk_warn"`
	DiskCrit float64 `json:"disk_crit"`
	MemWarn  float64 `json:"mem_warn"`
	MemCrit  float64 `json:"mem_crit"`
	LoadWarn float64 `json:"load_warn"`
	LoadCrit float64 `json:"load_crit"`
}

type VulnBulk struct {
	Package string `json:"package"`
	Version string `json:"version"`
	Count   int    `json:"count"`
	More    bool   `json:"more,omitempty"`
}
