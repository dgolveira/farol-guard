package check

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/dgolveira/farol-guard/internal/analyze"
	"github.com/dgolveira/farol-guard/internal/collect"
	"github.com/dgolveira/farol-guard/internal/i18n"
	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/keys"
	"github.com/dgolveira/farol-guard/internal/model"
	"github.com/dgolveira/farol-guard/internal/sshx"
	"github.com/dgolveira/farol-guard/internal/vuln"
)

type Options struct {
	Parallel   int
	Timeout    time.Duration
	RefreshApt bool
	NoCVE      bool
	Lang       string
	Version    string
	OnHost     func(h *model.HostReport)
	OnCVE      func(done, total int)
	Log        func(format string, a ...any)
	Pending    map[string]*model.HostKeyInfo
}

func Run(ctx context.Context, inv *inventory.Inventory, hosts []inventory.Host, d *sshx.Dialer, opts Options) (*model.Report, error) {
	if opts.Parallel < 1 {
		opts.Parallel = 8
	}
	labels := inv.KeyLabels()
	results := make([]*model.HostReport, len(hosts))
	sem := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h inventory.Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := collect.Host(ctx, d, h, labels, collect.Options{RefreshApt: opts.RefreshApt, Timeout: opts.Timeout, Log: opts.Log, Pending: opts.Pending})
			results[i] = r
			if opts.OnHost != nil {
				mu.Lock()
				opts.OnHost(r)
				mu.Unlock()
			}
		}(i, h)
	}
	wg.Wait()

	rep := &model.Report{Tool: "farol-guard", Version: opts.Version, GeneratedAt: time.Now(), Hosts: results}
	var cveErr error
	if !opts.NoCVE {
		vc := vuln.NewClient(inventory.CacheDir())
		vc.Log = opts.Log
		cveErr = vc.Enrich(ctx, results, opts.OnCVE)
		rep.CVEChecked = true
	}
	Finalize(rep, inv.Thresholds, opts.Lang)
	return rep, cveErr
}

func Finalize(rep *model.Report, t inventory.Thresholds, lang string) {
	rep.Limits = model.Limits{
		DiskWarn: t.DiskWarn, DiskCrit: t.DiskCrit, MemWarn: t.MemWarn, MemCrit: t.MemCrit,
		LoadWarn: t.LoadWarn, LoadCrit: t.LoadCrit,
	}
	annotateKeys(rep)
	for _, h := range rep.Hosts {
		analyze.Host(h, t, rep.GeneratedAt)
		Localize(h, lang)
	}
	sort.SliceStable(rep.Hosts, func(i, j int) bool {
		a, b := rep.Hosts[i], rep.Hosts[j]
		if a.Worst() != b.Worst() {
			return a.Worst() > b.Worst()
		}
		return a.Name < b.Name
	})
}

func Localize(h *model.HostReport, lang string) {
	for i := range h.Findings {
		f := &h.Findings[i]
		f.Title = i18n.T(lang, f.Code, f.Args...)
	}
}

func PendingFrom(rep *model.Report, hosts []inventory.Host) map[string]*model.HostKeyInfo {
	out := map[string]*model.HostKeyInfo{}
	if rep == nil {
		return out
	}
	cur := map[string]inventory.Host{}
	for _, h := range hosts {
		cur[h.Name] = h
	}
	for _, h := range rep.Hosts {
		c, ok := cur[h.Name]
		if !ok || h.HostKey == nil || h.HostKey.Key == "" || c.Address != h.Address || c.Port != h.Port {
			continue
		}
		out[h.Name] = h.HostKey
	}
	return out
}

func annotateKeys(rep *model.Report) {
	local := keys.LocalFingerprints()
	self := keys.InstanceID()
	for _, h := range rep.Hosts {
		for ui := range h.Users {
			for ki := range h.Users[ui].Keys {
				k := &h.Users[ui].Keys[ki]
				k.Farol, k.FarolHost = "", ""
				o := keys.ParseComment(k.Comment)
				switch {
				case local[k.Fingerprint] != "":
					k.Farol = "this"
					if k.Label == "" {
						k.Label = local[k.Fingerprint]
					}
				case o.Farol && o.Instance != "" && o.Instance == self:
					k.Farol = "this-retired"
				case o.Farol:
					k.Farol, k.FarolHost = "other", o.Host
				}
			}
		}
	}
}
