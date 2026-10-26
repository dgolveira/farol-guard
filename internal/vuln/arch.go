package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dgolveira/farol-guard/internal/model"
)

const archTrackerURL = "https://security.archlinux.org/issues/all.json"

type archAVG struct {
	Name     string   `json:"name"`
	Packages []string `json:"packages"`
	Status   string   `json:"status"`
	Severity string   `json:"severity"`
	Type     string   `json:"type"`
	Affected string   `json:"affected"`
	Fixed    string   `json:"fixed"`
	Issues   []string `json:"issues"`
}

func (c *Client) archTracker(ctx context.Context) ([]archAVG, error) {
	path := filepath.Join(c.CacheDir, "arch-avg.json")
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) < 6*time.Hour {
		if data, err := os.ReadFile(path); err == nil {
			var avgs []archAVG
			if json.Unmarshal(data, &avgs) == nil {
				return avgs, nil
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archTrackerURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "farol-guard")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("arch security tracker: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	var avgs []archAVG
	if err := json.Unmarshal(data, &avgs); err != nil {
		return nil, fmt.Errorf("arch security tracker: %w", err)
	}
	if err := os.MkdirAll(c.CacheDir, 0o700); err == nil {
		_ = os.WriteFile(path, data, 0o600)
	}
	return avgs, nil
}

func archAffected(a archAVG, installed string) bool {
	if a.Status == "Not affected" {
		return false
	}
	if a.Fixed != "" && Vercmp(installed, a.Fixed) >= 0 {
		return false
	}
	if a.Affected != "" && Vercmp(installed, a.Affected) < 0 && a.Fixed == "" {
		return false
	}
	return true
}

func (c *Client) EnrichArch(ctx context.Context, hosts []*model.HostReport) error {
	if len(hosts) == 0 {
		return nil
	}
	avgs, err := c.archTracker(ctx)
	if err != nil {
		return err
	}
	byPkg := map[string][]archAVG{}
	for _, a := range avgs {
		for _, p := range a.Packages {
			byPkg[p] = append(byPkg[p], a)
		}
	}
	c.logf("cve: arch security tracker has %d advisory groups", len(avgs))
	for _, h := range hosts {
		h.Vulns, h.VulnBulk = nil, nil
		upgrades := map[string]string{}
		for _, u := range h.Upgrades {
			upgrades[u.Name] = u.NewVersion
		}
		fixedBy := map[string]string{}
		for _, p := range h.Packages {
			for _, a := range byPkg[p.Name] {
				if !archAffected(a, p.Version) {
					continue
				}
				fixed := a.Fixed
				if a.Status == "Vulnerable" {
					fixed = ""
				}
				if fixed != "" && Vercmp(fixed, fixedBy[p.Name]) > 0 {
					fixedBy[p.Name] = fixed
				}
				ids := a.Issues
				if len(ids) == 0 {
					ids = []string{a.Name}
				}
				for _, id := range ids {
					v := model.Vuln{
						ID:       id,
						Package:  p.Name,
						Version:  p.Version,
						Fixed:    fixed,
						Severity: rpmSeverity(a.Severity),
						Advisory: a.Name,
						Summary:  strings.TrimSpace(a.Name + " · " + a.Type),
						Binaries: []string{p.Name},
					}
					if nv := upgrades[p.Name]; nv != "" && fixed != "" && Vercmp(nv, fixed) >= 0 {
						v.Candidate = nv
					}
					h.Vulns = append(h.Vulns, v)
				}
			}
		}
		for i := range h.Upgrades {
			if f := fixedBy[h.Upgrades[i].Name]; f != "" && Vercmp(h.Upgrades[i].NewVersion, f) >= 0 {
				h.Upgrades[i].Security = true
			}
		}
		sortVulns(h)
	}
	return nil
}
