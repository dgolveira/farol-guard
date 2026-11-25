package server

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/keyops"
)

type removal struct {
	Fingerprint string    `json:"fingerprint"`
	Host        string    `json:"host"`
	User        string    `json:"user"`
	At          time.Time `json:"at"`
}

func removalsPath() string { return filepath.Join(inventory.ConfigDir(), "removals.json") }

func installsPath() string { return filepath.Join(inventory.ConfigDir(), "installs.json") }

func loadChanges(path string) ([]removal, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []removal
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func saveChanges(path string, list []removal) error {
	if len(list) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func removalKey(fp, host, user string) string { return fp + "\x00" + host + "\x00" + user }

func pendingRemovals(since time.Time) map[string]bool { return pendingChanges(removalsPath(), since) }

func pendingChanges(path string, since time.Time) map[string]bool {
	list, _ := loadChanges(path)
	out := map[string]bool{}
	for _, r := range list {
		if r.At.After(since) {
			out[removalKey(r.Fingerprint, r.Host, r.User)] = true
		}
	}
	return out
}

func removedPairs(results []keyops.Result) [][2]string {
	var out [][2]string
	for _, res := range results {
		gone := map[string]bool{}
		var order []string
		for _, e := range res.Events {
			switch {
			case e.Action == "remove" && (e.Status == keyops.StatusOK || e.Status == keyops.StatusSkip):
				if !gone[e.User] {
					order = append(order, e.User)
				}
				gone[e.User] = true
			case e.Action == "rollback":
				gone[e.User] = false
			}
		}
		for _, u := range order {
			if gone[u] {
				out = append(out, [2]string{res.Host, u})
			}
		}
	}
	return out
}

func recordRemovals(fp string, results []keyops.Result, since time.Time) error {
	return recordChanges(removalsPath(), fp, removedPairs(results), since)
}

func recordChanges(path, fp string, pairs [][2]string, since time.Time) error {
	if len(pairs) == 0 {
		return nil
	}
	list, err := loadChanges(path)
	if err != nil {
		list = nil
	}
	now := time.Now().UTC()
	idx := map[string]int{}
	kept := list[:0]
	for _, r := range list {
		if r.At.After(since) {
			idx[removalKey(r.Fingerprint, r.Host, r.User)] = len(kept)
			kept = append(kept, r)
		}
	}
	for _, p := range pairs {
		k := removalKey(fp, p[0], p[1])
		if i, ok := idx[k]; ok {
			kept[i].At = now
			continue
		}
		idx[k] = len(kept)
		kept = append(kept, removal{Fingerprint: fp, Host: p[0], User: p[1], At: now})
	}
	return saveChanges(path, kept)
}
