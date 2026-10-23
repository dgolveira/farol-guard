package vuln

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dgolveira/farol-guard/internal/model"
)

const (
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
	osvVulnURL  = "https://api.osv.dev/v1/vulns/"
	batchSize   = 500
	maxDetailed = 150
	maxText     = 4000
)

type Client struct {
	HTTP      *http.Client
	CacheDir  string
	TTL       time.Duration
	VulnTTL   time.Duration
	Workers   int
	Log       func(format string, a ...any)
	vulnMu    sync.Mutex
	vulnCache map[string]*osvVuln
}

func NewClient(cacheDir string) *Client {
	return &Client{
		HTTP:      &http.Client{Timeout: 60 * time.Second},
		CacheDir:  filepath.Join(cacheDir, "osv"),
		TTL:       24 * time.Hour,
		VulnTTL:   7 * 24 * time.Hour,
		Workers:   8,
		vulnCache: map[string]*osvVuln{},
	}
}

func (c *Client) logf(format string, a ...any) {
	if c.Log != nil {
		c.Log(format, a...)
	}
}

func Ecosystem(os model.OSInfo) string {
	switch os.ID {
	case "debian":
		major, _, _ := strings.Cut(os.VersionID, ".")
		if major == "" {
			return ""
		}
		return "Debian:" + major
	case "ubuntu":
		if os.VersionID == "" {
			return ""
		}
		if os.LTS {
			return "Ubuntu:" + os.VersionID + ":LTS"
		}
		return "Ubuntu:" + os.VersionID
	}
	return ""
}

type query struct {
	eco, name, version string
}

func (q query) key() string {
	h := sha256.Sum256([]byte(q.eco + "\x00" + q.name + "\x00" + q.version))
	return hex.EncodeToString(h[:16])
}

type pkgResult struct {
	Vulns []model.Vuln `json:"vulns"`
	Bulk  int          `json:"bulk,omitempty"`
	More  bool         `json:"more,omitempty"`
}

func (c *Client) Enrich(ctx context.Context, hosts []*model.HostReport, progress func(done, total int)) error {
	need := map[query]bool{}
	for _, h := range hosts {
		eco := Ecosystem(h.OS)
		if eco == "" {
			continue
		}
		for _, p := range h.Packages {
			need[query{eco, p.Source, p.SourceVersion}] = true
		}
	}
	results := make(map[query]*pkgResult, len(need))
	var pending []query
	for q := range need {
		if r := c.readPkgCache(q); r != nil {
			results[q] = r
		} else {
			pending = append(pending, q)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].name < pending[j].name })
	c.logf("cve: %d unique source packages, %d cached, %d to query", len(need), len(need)-len(pending), len(pending))

	ids, err := c.batch(ctx, pending)
	if err != nil {
		return err
	}

	detailSet := map[string]bool{}
	for _, q := range pending {
		r := ids[q]
		if r == nil {
			continue
		}
		if r.more || len(r.ids) > maxDetailed {
			c.logf("cve: %s %s has %d+ advisories, counting only (not detailed)", q.name, q.version, len(r.ids))
			continue
		}
		for _, id := range r.ids {
			detailSet[id] = true
		}
	}
	detailIDs := make([]string, 0, len(detailSet))
	for id := range detailSet {
		detailIDs = append(detailIDs, id)
	}
	sort.Strings(detailIDs)
	c.logf("cve: fetching details for %d advisories", len(detailIDs))
	firstErr := c.fetchDetails(ctx, detailIDs, progress)

	for _, q := range pending {
		r := ids[q]
		res := &pkgResult{}
		if r != nil && (r.more || len(r.ids) > maxDetailed) {
			res.Bulk, res.More = len(r.ids), r.more
		} else if r != nil {
			var raw []osvVuln
			complete := true
			for _, id := range r.ids {
				if v := c.cachedVuln(id); v != nil {
					raw = append(raw, *v)
				} else {
					complete = false
				}
			}
			res.Vulns = buildVulns(raw, q)
			if !complete {
				results[q] = res
				continue
			}
		}
		results[q] = res
		c.writePkgCache(q, res)
	}

	for _, h := range hosts {
		eco := Ecosystem(h.OS)
		if eco == "" {
			continue
		}
		seen := map[string]bool{}
		h.Vulns, h.VulnBulk = nil, nil
		for _, p := range h.Packages {
			q := query{eco, p.Source, p.SourceVersion}
			if seen[q.name+q.version] {
				continue
			}
			seen[q.name+q.version] = true
			r := results[q]
			if r == nil {
				continue
			}
			h.Vulns = append(h.Vulns, r.Vulns...)
			if r.Bulk > 0 {
				h.VulnBulk = append(h.VulnBulk, model.VulnBulk{Package: q.name, Version: q.version, Count: r.Bulk, More: r.More})
			}
		}
		sort.SliceStable(h.Vulns, func(i, j int) bool {
			a, b := h.Vulns[i], h.Vulns[j]
			if (a.Fixed != "") != (b.Fixed != "") {
				return a.Fixed != ""
			}
			if a.Rank() != b.Rank() {
				return a.Rank() > b.Rank()
			}
			return a.Score > b.Score
		})
	}
	return firstErr
}

func (c *Client) readPkgCache(q query) *pkgResult {
	path := filepath.Join(c.CacheDir, "pkg2-"+q.key()+".json")
	st, err := os.Stat(path)
	if err != nil || time.Since(st.ModTime()) > c.TTL {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var r pkgResult
	if json.Unmarshal(data, &r) != nil {
		return nil
	}
	return &r
}

func (c *Client) writePkgCache(q query, r *pkgResult) {
	if err := os.MkdirAll(c.CacheDir, 0o700); err != nil {
		return
	}
	if data, err := json.Marshal(r); err == nil {
		_ = os.WriteFile(filepath.Join(c.CacheDir, "pkg2-"+q.key()+".json"), data, 0o600)
	}
}

type idList struct {
	ids  []string
	more bool
}

func (c *Client) batch(ctx context.Context, queries []query) (map[query]*idList, error) {
	out := make(map[query]*idList, len(queries))
	for start := 0; start < len(queries); start += batchSize {
		end := min(start+batchSize, len(queries))
		chunk := queries[start:end]
		type pkg struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		}
		type q struct {
			Package pkg    `json:"package"`
			Version string `json:"version"`
		}
		body := struct {
			Queries []q `json:"queries"`
		}{}
		for _, x := range chunk {
			body.Queries = append(body.Queries, q{Package: pkg{x.name, x.eco}, Version: x.version})
		}
		t0 := time.Now()
		var res struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
				NextPageToken string `json:"next_page_token"`
			} `json:"results"`
		}
		if err := c.postJSON(ctx, osvBatchURL, body, &res); err != nil {
			return out, fmt.Errorf("osv querybatch: %w", err)
		}
		total := 0
		for i, r := range res.Results {
			if i >= len(chunk) {
				break
			}
			l := &idList{more: r.NextPageToken != ""}
			for _, v := range r.Vulns {
				l.ids = append(l.ids, v.ID)
			}
			total += len(l.ids)
			out[chunk[i]] = l
		}
		c.logf("cve: batch %d-%d of %d packages -> %d advisories (%s)", start+1, end, len(queries), total, time.Since(t0).Round(time.Millisecond))
	}
	return out, nil
}

func (c *Client) cachedVuln(id string) *osvVuln {
	c.vulnMu.Lock()
	defer c.vulnMu.Unlock()
	return c.vulnCache[id]
}

func (c *Client) fetchDetails(ctx context.Context, ids []string, progress func(done, total int)) error {
	var mu sync.Mutex
	var firstErr error
	done := 0
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < c.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				v, src, dur, err := c.vuln(ctx, id)
				mu.Lock()
				done++
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
					c.logf("cve: %s failed: %v", id, err)
				} else {
					c.vulnMu.Lock()
					c.vulnCache[id] = v
					c.vulnMu.Unlock()
					if src == "network" && dur > 3*time.Second {
						c.logf("cve: %s slow response (%s)", id, dur.Round(time.Millisecond))
					}
				}
				if progress != nil {
					progress(done, len(ids))
				}
				mu.Unlock()
			}
		}()
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		jobs <- id
	}
	close(jobs)
	wg.Wait()
	return firstErr
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

func (c *Client) vuln(ctx context.Context, id string) (*osvVuln, string, time.Duration, error) {
	if !safeID.MatchString(id) {
		return nil, "", 0, fmt.Errorf("unexpected advisory id %q", id)
	}
	path := filepath.Join(c.CacheDir, "vuln2", id+".json")
	if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) < c.VulnTTL {
		if data, err := os.ReadFile(path); err == nil {
			var v osvVuln
			if json.Unmarshal(data, &v) == nil {
				return &v, "cache", 0, nil
			}
		}
	}
	t0 := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvVulnURL+id, nil)
	if err != nil {
		return nil, "", 0, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var v osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, "", 0, err
	}
	v.trim()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		if data, err := json.Marshal(&v); err == nil {
			_ = os.WriteFile(path, data, 0o600)
		}
	}
	return &v, "network", time.Since(t0), nil
}

func (c *Client) postJSON(ctx context.Context, url string, body, out any) error {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func buildVulns(raw []osvVuln, q query) []model.Vuln {
	covered := map[string]bool{}
	for _, r := range raw {
		if !isAdvisory(r.ID) {
			covered[cveID(r.ID)] = true
		}
	}
	var out []model.Vuln
	for _, r := range raw {
		if isAdvisory(r.ID) && advisoryCovered(r, covered) {
			continue
		}
		out = append(out, convert(r, q))
	}
	return out
}

type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"`
	Related  []string `json:"related"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific map[string]any `json:"ecosystem_specific"`
	} `json:"affected"`
}

func (v *osvVuln) trim() {
	if len(v.Details) > maxText {
		v.Details = v.Details[:maxText]
	}
}

var advisoryPrefixes = []string{"DSA-", "DLA-", "DTSA-", "USN-", "LSN-"}

func isAdvisory(id string) bool {
	for _, p := range advisoryPrefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

func cveID(id string) string {
	return strings.TrimPrefix(strings.TrimPrefix(id, "DEBIAN-"), "UBUNTU-")
}

func advisoryCovered(r osvVuln, covered map[string]bool) bool {
	refs := append(append(append([]string{}, r.Aliases...), r.Upstream...), r.Related...)
	n := 0
	for _, ref := range refs {
		ref = cveID(ref)
		if !strings.HasPrefix(ref, "CVE-") {
			continue
		}
		n++
		if !covered[ref] {
			return false
		}
	}
	return n > 0
}

func convert(r osvVuln, q query) model.Vuln {
	v := model.Vuln{
		ID:      cveID(r.ID),
		Aliases: append(r.Aliases, r.Upstream...),
		Package: q.name,
		Version: q.version,
		Summary: r.Summary,
	}
	if v.Summary == "" {
		v.Summary, _, _ = strings.Cut(strings.TrimSpace(r.Details), "\n")
	}
	full := strings.TrimSpace(r.Details)
	if full == "" {
		full = r.Summary
	}
	if len(full) > maxText {
		full = full[:maxText] + "..."
	}
	if len(v.Summary) > 220 {
		v.Summary = v.Summary[:217] + "..."
	}
	if full != v.Summary {
		v.Details = full
	}

	urgency := ""
	for _, a := range r.Affected {
		if a.Package.Ecosystem != q.eco || a.Package.Name != q.name {
			continue
		}
		for _, rg := range a.Ranges {
			for _, ev := range rg.Events {
				if f, ok := ev["fixed"]; ok {
					v.Fixed = f
				}
			}
		}
		if u, ok := a.EcosystemSpecific["urgency"].(string); ok {
			urgency = strings.TrimSuffix(u, "*")
		}
	}

	label := ""
	for _, s := range r.Severity {
		switch s.Type {
		case "Ubuntu":
			label = strings.ToLower(s.Score)
		case "CVSS_V3":
			v.Score = cvss3Score(s.Score)
		}
	}
	switch {
	case urgency == "unimportant":
		v.Severity = "negligible"
	case label != "":
		v.Severity = label
	case v.Score > 0:
		v.Severity = scoreLabel(v.Score)
	case urgency == "low" || urgency == "medium" || urgency == "high":
		v.Severity = urgency
	default:
		v.Severity = "unknown"
	}
	return v
}
