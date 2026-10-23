package collect

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/model"
	"github.com/dgolveira/farol-guard/internal/sshx"
)

//go:embed collect.sh
var script []byte

const remoteCmd = `if [ "$(id -u)" = 0 ]; then exec bash -s; elif sudo -n true 2>/dev/null; then exec sudo -n bash -s; else exec bash -s; fi`

type Options struct {
	RefreshApt bool
	Timeout    time.Duration
	Log        func(format string, a ...any)
	Pending    map[string]*model.HostKeyInfo
}

var sectionLabels = map[string]string{
	"meta": "identifying host", "passwd": "reading users and groups", "authorized_keys": "reading authorized_keys",
	"sshd_effective": "reading sshd configuration", "apt_update": "running apt-get update",
	"packages": "listing installed packages", "upgradable": "checking pending updates",
	"snaps": "listing snaps and containers", "services": "listing services", "listening": "listing open ports",
	"sshd_log": "reading SSH access log", "firewall": "checking firewall", "kernel_errors": "reading kernel errors",
	"net_dev": "reading network counters", "df": "reading disks", "meminfo": "reading memory",
	"cpu_stat": "sampling CPU", "end": "collection finished",
}

func Host(ctx context.Context, d *sshx.Dialer, h inventory.Host, keyLabels map[string]string, opts Options) *model.HostReport {
	start := time.Now()
	logf := func(format string, a ...any) {
		if opts.Log != nil {
			opts.Log(h.Name+": "+format, a...)
		}
	}
	r := &model.HostReport{
		Name: h.Name, Address: h.Address, Port: h.Port, User: h.User,
		Group: h.Group, Tags: h.Tags, CollectedAt: start,
	}
	defer func() { r.Duration = time.Since(start) }()

	if p := opts.Pending[h.Name]; p != nil && !d.IsTrusted(sshx.Target{Address: h.Address, Port: h.Port}, p.Key) {
		pk := *p
		pk.Skipped = true
		r.HostKey = &pk
		r.Error = "skipped: host key still pending review (no connection made)"
		logf("skipped, host key %s still pending review", p.Fingerprint)
		return r
	}
	logf("connecting to %s@%s:%d", h.User, h.Address, h.Port)
	client, err := d.Dial(sshx.Target{Address: h.Address, Port: h.Port, User: h.User, Identity: h.Identity})
	if err != nil {
		r.Error = err.Error()
		var uh *sshx.UnknownHostError
		if errors.As(err, &uh) {
			r.HostKey = &model.HostKeyInfo{Type: uh.Type, Fingerprint: uh.Fingerprint, Key: uh.Key}
			logf("host key not trusted yet (%s %s)", uh.Type, uh.Fingerprint)
			return r
		}
		logf("connection failed: %v", err)
		return r
	}
	logf("connected (%s)", client.ServerVersion())
	defer client.Close()
	r.Reachable = true

	payload := script
	if opts.RefreshApt {
		payload = append([]byte("FAROL_APT_UPDATE=1\n"), script...)
	}
	cctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	out, stderr, err := sshx.RunStream(cctx, client, remoteCmd, payload, func(line string) {
		if name, ok := strings.CutPrefix(line, marker); ok {
			if label, ok := sectionLabels[name]; ok {
				logf("%s", label)
			}
		}
	})
	if err != nil && len(out) == 0 {
		r.Error = fmt.Sprintf("collector failed: %v %s", err, strings.TrimSpace(string(stderr)))
		return r
	}
	if !strings.Contains(string(out), marker+"end") {
		r.Error = "collector output truncated (timeout?)"
	}
	Parse(r, out, keyLabels)
	logf("done in %s: %s, %d packages, %d updates (%d security)", time.Since(start).Round(time.Millisecond),
		r.OS.Pretty, len(r.Packages), len(r.Upgrades), r.SecurityUpgrades())
	return r
}
