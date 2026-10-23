package inventory

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed sample.yaml
var Sample []byte

type Thresholds struct {
	DiskWarn         float64 `yaml:"disk_warn"`
	DiskCrit         float64 `yaml:"disk_crit"`
	InodeWarn        float64 `yaml:"inode_warn"`
	InodeCrit        float64 `yaml:"inode_crit"`
	MemWarn          float64 `yaml:"mem_warn"`
	MemCrit          float64 `yaml:"mem_crit"`
	SwapWarn         float64 `yaml:"swap_warn"`
	LoadWarn         float64 `yaml:"load_warn"`
	LoadCrit         float64 `yaml:"load_crit"`
	CPUWarn          float64 `yaml:"cpu_warn"`
	FailedLoginsWarn int     `yaml:"failed_logins_warn"`
	AptListsMaxDays  float64 `yaml:"apt_lists_max_days"`
}

var DefaultThresholds = Thresholds{
	DiskWarn: 80, DiskCrit: 90,
	InodeWarn: 80, InodeCrit: 90,
	MemWarn: 85, MemCrit: 95,
	SwapWarn: 50,
	LoadWarn: 1.5, LoadCrit: 3,
	CPUWarn:          90,
	FailedLoginsWarn: 100,
	AptListsMaxDays:  7,
}

type KnownKey struct {
	Name        string `yaml:"name" json:"name"`
	Fingerprint string `yaml:"fingerprint"`
}

type Settings struct {
	User     string `yaml:"user,omitempty" json:"user"`
	Port     int    `yaml:"port,omitempty" json:"port"`
	Identity string `yaml:"identity,omitempty" json:"identity"`
}

type Host struct {
	Name     string   `yaml:"name" json:"name"`
	Address  string   `yaml:"address" json:"address"`
	Port     int      `yaml:"port,omitempty" json:"port"`
	User     string   `yaml:"user,omitempty" json:"user"`
	Identity string   `yaml:"identity,omitempty" json:"identity"`
	Tags     []string `yaml:"tags,omitempty" json:"tags"`
	Group    string   `yaml:"-"`
}

type Group struct {
	Settings `yaml:",inline"`
	Hosts    []Host `yaml:"hosts"`
}

type Inventory struct {
	Defaults   Settings         `yaml:"defaults"`
	KnownKeys  []KnownKey       `yaml:"known_keys"`
	Thresholds Thresholds       `yaml:"thresholds"`
	Groups     map[string]Group `yaml:"groups"`
	Path       string           `yaml:"-"`
}

func DefaultPath() string {
	if p := os.Getenv("FAROL_GUARD_CONFIG"); p != "" {
		return p
	}
	return filepath.Join(ConfigDir(), "inventory.yaml")
}

func ConfigDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "farol-guard")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "farol-guard")
}

func CacheDir() string {
	if d := os.Getenv("XDG_CACHE_HOME"); d != "" {
		return filepath.Join(d, "farol-guard")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "farol-guard")
}

func ShortHome(p string) string {
	home, _ := os.UserHomeDir()
	if home != "" && strings.HasPrefix(p, home+"/") {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

func ExpandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p
}

func Load(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inventory not found at %s (run 'farol init' to create one)", path)
		}
		return nil, err
	}
	inv := &Inventory{Thresholds: DefaultThresholds}
	if err := yaml.Unmarshal(data, inv); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	inv.Path = path
	if inv.Defaults.User == "" {
		inv.Defaults.User = "root"
	}
	if inv.Defaults.Port == 0 {
		inv.Defaults.Port = 22
	}
	if inv.Defaults.Identity == "" {
		inv.Defaults.Identity = "~/.ssh/id_ed25519"
	}
	return inv, inv.validate()
}

func (inv *Inventory) validate() error {
	seen := map[string]string{}
	for gname, g := range inv.Groups {
		for _, h := range g.Hosts {
			if h.Name == "" || h.Address == "" {
				return fmt.Errorf("group %s: every host needs name and address", gname)
			}
			if prev, ok := seen[h.Name]; ok {
				return fmt.Errorf("host %s defined in groups %s and %s", h.Name, prev, gname)
			}
			seen[h.Name] = gname
		}
	}
	return nil
}

func (inv *Inventory) Hosts() []Host {
	var out []Host
	for gname, g := range inv.Groups {
		for _, h := range g.Hosts {
			h.Group = gname
			h.User = first(h.User, g.User, inv.Defaults.User)
			h.Identity = ExpandHome(first(h.Identity, g.Identity, inv.Defaults.Identity))
			if h.Port == 0 {
				h.Port = g.Port
			}
			if h.Port == 0 {
				h.Port = inv.Defaults.Port
			}
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (inv *Inventory) Select(groups, hosts []string) ([]Host, error) {
	all := inv.Hosts()
	if len(groups) == 0 && len(hosts) == 0 {
		return all, nil
	}
	gset, hset := toSet(groups), toSet(hosts)
	for g := range gset {
		if _, ok := inv.Groups[g]; !ok {
			return nil, fmt.Errorf("unknown group %q", g)
		}
	}
	var out []Host
	found := map[string]bool{}
	for _, h := range all {
		if gset[h.Group] || hset[h.Name] {
			out = append(out, h)
			found[h.Name] = true
		}
	}
	for h := range hset {
		if !found[h] {
			return nil, fmt.Errorf("unknown host %q", h)
		}
	}
	return out, nil
}

func (inv *Inventory) KeyLabels() map[string]string {
	m := make(map[string]string, len(inv.KnownKeys))
	for _, k := range inv.KnownKeys {
		m[k.Fingerprint] = k.Name
	}
	return m
}

func WriteSample(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, Sample, 0o600)
}

func first(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func toSet(v []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range v {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				m[p] = true
			}
		}
	}
	return m
}

func (inv *Inventory) Save() error {
	data, err := yaml.Marshal(inv)
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(inv.Path); err == nil {
		if err := os.WriteFile(inv.Path+".bak", old, 0o600); err != nil {
			return err
		}
	}
	tmp := inv.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, inv.Path)
}

func (inv *Inventory) Find(name string) (Host, bool) {
	for _, h := range inv.Hosts() {
		if h.Name == name {
			return h, true
		}
	}
	return Host{}, false
}

func (inv *Inventory) UpsertHost(original string, h Host) error {
	h.Name, h.Address, h.Group = strings.TrimSpace(h.Name), strings.TrimSpace(h.Address), strings.TrimSpace(h.Group)
	if h.Name == "" || h.Address == "" || h.Group == "" {
		return errors.New("name, address and group are required")
	}
	if h.Port < 0 || h.Port > 65535 {
		return fmt.Errorf("invalid port %d", h.Port)
	}
	if original != h.Name {
		if _, exists := inv.Find(h.Name); exists {
			return fmt.Errorf("host %q already exists", h.Name)
		}
	}
	if original != "" {
		inv.DeleteHost(original)
	}
	if inv.Groups == nil {
		inv.Groups = map[string]Group{}
	}
	g := inv.Groups[h.Group]
	g.Hosts = append(g.Hosts, h)
	inv.Groups[h.Group] = g
	return inv.validate()
}

func (inv *Inventory) DeleteHost(name string) bool {
	for gname, g := range inv.Groups {
		for i, h := range g.Hosts {
			if h.Name == name {
				g.Hosts = append(g.Hosts[:i], g.Hosts[i+1:]...)
				if len(g.Hosts) == 0 && g.Settings == (Settings{}) {
					delete(inv.Groups, gname)
				} else {
					inv.Groups[gname] = g
				}
				return true
			}
		}
	}
	return false
}

func (inv *Inventory) RawHost(name string) (Host, bool) {
	for gname, g := range inv.Groups {
		for _, h := range g.Hosts {
			if h.Name == name {
				h.Group = gname
				return h, true
			}
		}
	}
	return Host{}, false
}

func (inv *Inventory) SetIdentity(hosts []Host, identity string) {
	selected := map[string]bool{}
	for _, h := range hosts {
		selected[h.Name] = true
	}
	for gname, g := range inv.Groups {
		all := len(g.Hosts) > 0
		for _, h := range g.Hosts {
			if !selected[h.Name] {
				all = false
			}
		}
		if all {
			g.Identity = identity
			for i := range g.Hosts {
				g.Hosts[i].Identity = ""
			}
		} else {
			for i, h := range g.Hosts {
				if selected[h.Name] {
					g.Hosts[i].Identity = identity
				}
			}
		}
		inv.Groups[gname] = g
	}
}

func (inv *Inventory) SetKnownKey(name, fingerprint string) {
	for i, k := range inv.KnownKeys {
		if k.Name == name {
			inv.KnownKeys[i].Fingerprint = fingerprint
			return
		}
	}
	inv.AddKnownKey(name, fingerprint)
}

func (inv *Inventory) AddKnownKey(name, fingerprint string) {
	for _, k := range inv.KnownKeys {
		if k.Fingerprint == fingerprint {
			return
		}
	}
	inv.KnownKeys = append(inv.KnownKeys, KnownKey{Name: name, Fingerprint: fingerprint})
}

type Duplicate struct {
	Target string   `json:"target"`
	Hosts  []string `json:"hosts"`
}

func Duplicates(hosts []Host) []Duplicate {
	byTarget := map[string][]string{}
	var order []string
	for _, h := range hosts {
		key := fmt.Sprintf("%s:%d", strings.ToLower(strings.TrimSuffix(h.Address, ".")), h.Port)
		if _, ok := byTarget[key]; !ok {
			order = append(order, key)
		}
		byTarget[key] = append(byTarget[key], h.Name)
	}
	var out []Duplicate
	for _, k := range order {
		if len(byTarget[k]) > 1 {
			out = append(out, Duplicate{Target: k, Hosts: byTarget[k]})
		}
	}
	return out
}
