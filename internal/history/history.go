package history

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dgolveira/farol-guard/internal/model"
)

const keep = 200

var idRe = regexp.MustCompile(`^\d{8}-\d{6}$`)

type Meta struct {
	ID          string    `json:"id"`
	GeneratedAt time.Time `json:"generated_at"`
	Hosts       int       `json:"hosts"`
	Reachable   int       `json:"reachable"`
	Critical    int       `json:"critical"`
	High        int       `json:"high"`
	Medium      int       `json:"medium"`
}

func Dir() string {
	if d := os.Getenv("FAROL_GUARD_DATA"); d != "" {
		return filepath.Join(d, "reports")
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "farol-guard", "reports")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "farol-guard", "reports")
}

func Save(rep *model.Report) (string, error) {
	dir := Dir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	id := rep.GeneratedAt.Local().Format("20060102-150405")
	data, err := json.Marshal(rep)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, id+".json"), data, 0o600); err != nil {
		return "", err
	}
	meta := summarize(id, rep)
	mdata, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(dir, id+".meta"), mdata, 0o600); err != nil {
		return "", err
	}
	prune(dir)
	return id, nil
}

func summarize(id string, rep *model.Report) Meta {
	m := Meta{ID: id, GeneratedAt: rep.GeneratedAt, Hosts: len(rep.Hosts)}
	for _, h := range rep.Hosts {
		if h.Reachable {
			m.Reachable++
		}
		m.Critical += h.CountFindings(model.SevCritical)
		m.High += h.CountFindings(model.SevHigh)
		m.Medium += h.CountFindings(model.SevMedium)
	}
	return m
}

func List() ([]Meta, error) {
	entries, err := os.ReadDir(Dir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Meta
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".meta") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(Dir(), e.Name()))
		if err != nil {
			continue
		}
		var m Meta
		if json.Unmarshal(data, &m) == nil {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

func Load(id string) (*model.Report, error) {
	if !idRe.MatchString(id) {
		return nil, errors.New("invalid report id")
	}
	data, err := os.ReadFile(filepath.Join(Dir(), id+".json"))
	if err != nil {
		return nil, err
	}
	var rep model.Report
	return &rep, json.Unmarshal(data, &rep)
}

func Latest() (*model.Report, string, error) {
	list, err := List()
	if err != nil || len(list) == 0 {
		return nil, "", err
	}
	rep, err := Load(list[0].ID)
	return rep, list[0].ID, err
}

func prune(dir string) {
	list, err := List()
	if err != nil || len(list) <= keep {
		return
	}
	for _, m := range list[keep:] {
		os.Remove(filepath.Join(dir, m.ID+".json"))
		os.Remove(filepath.Join(dir, m.ID+".meta"))
	}
}

func Delete(id string) error {
	if !idRe.MatchString(id) {
		return errors.New("invalid report id")
	}
	if err := os.Remove(filepath.Join(Dir(), id+".json")); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(Dir(), id+".meta"))
	return nil
}

func Clear(keepLatest bool) (int, error) {
	list, err := List()
	if err != nil {
		return 0, err
	}
	if keepLatest && len(list) > 0 {
		list = list[1:]
	}
	n := 0
	for _, m := range list {
		if err := Delete(m.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
