package keyops

import (
	"context"
	"errors"

	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/keys"
	"github.com/dgolveira/farol-guard/internal/sshx"
)

type AppRotation struct {
	OldFingerprint string   `json:"old_fingerprint"`
	NewFingerprint string   `json:"new_fingerprint,omitempty"`
	Deploy         []Result `json:"deploy"`
	Remove         []Result `json:"remove"`
	Completed      bool     `json:"completed"`
	Retired        string   `json:"retired,omitempty"`
}

func RotateApp(ctx context.Context, d *sshx.Dialer, hosts []inventory.Host, fromIPs []string, dryRun bool) (*AppRotation, error) {
	old, err := keys.Get(keys.AppKeyName)
	if err != nil {
		return nil, errors.New("there is no app key to replace yet")
	}
	if len(hosts) == 0 {
		return nil, errors.New("no hosts selected")
	}
	out := &AppRotation{OldFingerprint: old.Fingerprint}
	next, err := keys.Get(keys.AppNextName)
	if err != nil {
		if dryRun {
			next = keys.Placeholder(keys.AppNextName)
		} else if next, _, err = keys.GenerateApp(keys.AppNextName); err != nil {
			return nil, err
		}
	}
	out.NewFingerprint = next.Fingerprint

	req := Request{Hosts: hosts, NewKey: next, FromIPs: fromIPs, DryRun: dryRun}
	if !dryRun {
		if req.NewSigner, err = d.LoadKey(next.Path); err != nil {
			return nil, err
		}
	}
	if out.Deploy, err = Deploy(ctx, d, req); err != nil {
		return nil, err
	}
	good := map[string]bool{}
	for _, r := range out.Deploy {
		if r.OK {
			good[r.Host] = true
		}
	}
	var ok []inventory.Host
	for _, h := range hosts {
		if good[h.Name] {
			ok = append(ok, h)
		}
	}
	req.Hosts = ok
	req.RemoveFP = old.Fingerprint
	if len(ok) > 0 {
		if out.Remove, err = Remove(ctx, d, req); err != nil {
			return nil, err
		}
	}
	out.Completed = len(ok) == len(hosts)
	for _, r := range out.Remove {
		if !r.OK {
			out.Completed = false
		}
	}
	if out.Completed && !dryRun {
		if out.Retired, err = keys.PromoteNext(); err != nil {
			return out, err
		}
		d.ForgetKey(old.Path)
		d.ForgetKey(next.Path)
	}
	return out, nil
}

func AppKeyHosts(inv *inventory.Inventory, fingerprintHosts map[string]bool) []inventory.Host {
	var out []inventory.Host
	for _, h := range inv.Hosts() {
		if fingerprintHosts[h.Name] {
			out = append(out, h)
		}
	}
	return out
}
