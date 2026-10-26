package vuln

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dgolveira/farol-guard/internal/model"
)

const redhatAPI = "https://access.redhat.com/hydra/rest/securitydata/"

var elCompatible = map[string]bool{"rhel": true, "rocky": true, "almalinux": true, "ol": true, "centos": true}

var openStates = map[string]bool{
	"Affected": true, "Fix deferred": true, "Will not fix": true, "Under investigation": true,
}

type rhListItem struct {
	CVE              string   `json:"CVE"`
	Severity         string   `json:"severity"`
	AffectedPackages []string `json:"affected_packages"`
	Description      string   `json:"bugzilla_description"`
	CVSS3Score       string   `json:"cvss3_score"`
}

type rhDetail struct {
	ThreatSeverity string `json:"threat_severity"`
	PackageState   []struct {
		ProductName string `json:"product_name"`
		FixState    string `json:"fix_state"`
		PackageName string `json:"package_name"`
		CPE         string `json:"cpe"`
	} `json:"package_state"`
	Bugzilla struct {
		Description string `json:"description"`
	} `json:"bugzilla"`
	Details []string `json:"details"`
}

func (c *Client) cachedGet(ctx context.Context, rawURL, cacheName string, ttl time.Duration, out any) error {
	path := filepath.Join(c.CacheDir, cacheName)
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) < ttl {
		if data, err := os.ReadFile(path); err == nil && json.Unmarshal(data, out) == nil {
			return nil
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "farol-guard")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		data := []byte("null")
		_ = os.WriteFile(path, data, 0o600)
		return json.Unmarshal(data, out)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", rawURL, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return err
	}
	if err := os.MkdirAll(c.CacheDir, 0o700); err == nil {
		_ = os.WriteFile(path, data, 0o600)
	}
	return nil
}

func elMajor(o model.OSInfo) string {
	if !elCompatible[o.BaseID] {
		return ""
	}
	switch o.BaseVersion {
	case "8", "9", "10":
		return o.BaseVersion
	}
	return ""
}

func fixedForEL(item rhListItem, srpm, major string) bool {
	prefix := srpm + "-"
	tag := ".el" + major
	for _, p := range item.AffectedPackages {
		if strings.HasPrefix(p, prefix) && strings.Contains(p, tag) && !strings.Contains(p, "/") {
			return true
		}
	}
	return false
}

type rhKey struct{ srpm, major string }

func (c *Client) parallel(ctx context.Context, n int, fn func(i int)) {
	jobs := make(chan int)
	var wg sync.WaitGroup
	workers := c.Workers
	if workers > 4 {
		workers = 4
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				fn(i)
			}
		}()
	}
	for i := 0; i < n && ctx.Err() == nil; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

func (c *Client) EnrichRedHat(ctx context.Context, hosts []*model.HostReport, progress func(done, total int)) error {
	need := map[rhKey]bool{}
	for _, h := range hosts {
		major := elMajor(h.OS)
		if major == "" {
			continue
		}
		for _, p := range h.Packages {
			need[rhKey{p.Source, major}] = true
		}
	}
	if len(need) == 0 {
		return nil
	}
	keys := make([]rhKey, 0, len(need))
	for k := range need {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].srpm < keys[j].srpm })
	c.logf("cve: red hat security data for %d source packages", len(keys))

	var mu sync.Mutex
	var firstErr error
	lists := map[rhKey][]rhListItem{}
	c.parallel(ctx, len(keys), func(i int) {
		k := keys[i]
		q := url.Values{"package": {k.srpm}, "product": {"Red Hat Enterprise Linux " + k.major}, "per_page": {"1000"}}
		var items []rhListItem
		err := c.cachedGet(ctx, redhatAPI+"cve.json?"+q.Encode(), "rh-list-"+hashKey(k.srpm+"|"+k.major)+".json", c.TTL, &items)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		lists[k] = items
	})

	candidates := map[string]bool{}
	for k, items := range lists {
		for _, it := range items {
			if !fixedForEL(it, k.srpm, k.major) {
				candidates[it.CVE] = true
			}
		}
	}
	ids := make([]string, 0, len(candidates))
	for id := range candidates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	c.logf("cve: red hat fix state for %d CVEs", len(ids))
	details := map[string]*rhDetail{}
	done := 0
	c.parallel(ctx, len(ids), func(i int) {
		var d rhDetail
		err := c.cachedGet(ctx, redhatAPI+"cve/"+url.PathEscape(ids[i])+".json", "rh-cve-"+ids[i]+".json", c.VulnTTL, &d)
		mu.Lock()
		defer mu.Unlock()
		done++
		if progress != nil {
			progress(done, len(ids))
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		details[ids[i]] = &d
	})

	for _, h := range hosts {
		major := elMajor(h.OS)
		if major == "" {
			continue
		}
		known := map[string]bool{}
		for _, v := range h.Vulns {
			known[v.ID] = true
		}
		cpe := "enterprise_linux:" + major
		seen := map[string]bool{}
		for _, p := range h.Packages {
			if seen[p.Source] {
				continue
			}
			seen[p.Source] = true
			for _, it := range lists[rhKey{p.Source, major}] {
				d := details[it.CVE]
				if d == nil || known[it.CVE] {
					continue
				}
				state := ""
				for _, ps := range d.PackageState {
					if ps.PackageName == p.Source && strings.Contains(ps.CPE, cpe) && openStates[ps.FixState] {
						state = ps.FixState
						break
					}
				}
				if state == "" {
					continue
				}
				known[it.CVE] = true
				sev := d.ThreatSeverity
				if sev == "" {
					sev = it.Severity
				}
				v := model.Vuln{
					ID:       it.CVE,
					Package:  p.Source,
					Version:  p.SourceVersion,
					Severity: rpmSeverity(sev),
					Advisory: state,
					Summary:  strings.TrimSpace(state + " · " + strings.TrimSpace(it.Description)),
				}
				if len(d.Details) > 0 {
					v.Details = strings.TrimSpace(strings.Join(d.Details, "\n\n"))
					if len(v.Details) > maxText {
						v.Details = v.Details[:maxText] + "..."
					}
				}
				if it.CVSS3Score != "" {
					fmt.Sscanf(it.CVSS3Score, "%g", &v.Score)
				}
				h.Vulns = append(h.Vulns, v)
			}
		}
		sortVulns(h)
	}
	return firstErr
}

func hashKey(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:16])
}
