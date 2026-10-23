package keys

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dgolveira/farol-guard/internal/inventory"
)

const AppNextName = AppKeyName + ".next"

var (
	instanceOnce sync.Once
	instanceID   string
	appCommentRe = regexp.MustCompile(`^farol-guard:app:([0-9a-f]{8,32})@(\S+)`)
	legacyAppRe  = regexp.MustCompile(`^farol-guard-app@(\S+)`)
	namedKeyRe   = regexp.MustCompile(`^farol-guard:([A-Za-z0-9_.-]+)@(\S+)`)
)

func InstanceID() string {
	instanceOnce.Do(func() {
		path := filepath.Join(inventory.ConfigDir(), "instance-id")
		if data, err := os.ReadFile(path); err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				instanceID = id
				return
			}
		}
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		instanceID = hex.EncodeToString(b)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
			_ = os.WriteFile(path, []byte(instanceID+"\n"), 0o600)
		}
	})
	return instanceID
}

func AppComment() string {
	host, _ := os.Hostname()
	return fmt.Sprintf("farol-guard:app:%s@%s %s", InstanceID(), host, time.Now().Format("2006-01-02"))
}

type Origin struct {
	Farol    bool
	App      bool
	Instance string
	Host     string
}

func ParseComment(comment string) Origin {
	if m := appCommentRe.FindStringSubmatch(comment); m != nil {
		return Origin{Farol: true, App: true, Instance: m[1], Host: m[2]}
	}
	if m := legacyAppRe.FindStringSubmatch(comment); m != nil {
		return Origin{Farol: true, App: true, Host: m[1]}
	}
	if m := namedKeyRe.FindStringSubmatch(comment); m != nil {
		return Origin{Farol: true, Host: m[2]}
	}
	return Origin{}
}

func LocalFingerprints() map[string]string {
	out := map[string]string{}
	list, _ := List()
	for _, k := range list {
		out[k.Fingerprint] = k.Name
	}
	return out
}

func Placeholder(name string) *Key {
	return &Key{Name: name, Fingerprint: "(new key)", Type: "ssh-ed25519", PublicLine: "ssh-ed25519 (new-key) " + AppComment()}
}

func PromoteNext() (retired string, err error) {
	dir := Dir()
	cur := filepath.Join(dir, AppKeyName)
	next := filepath.Join(dir, AppNextName)
	if _, err := os.Stat(next); err != nil {
		return "", fmt.Errorf("%s not found", next)
	}
	retired = filepath.Join(dir, AppKeyName+".retired-"+time.Now().Format("20060102-150405"))
	if _, err := os.Stat(cur); err == nil {
		if err := os.Rename(cur, retired); err != nil {
			return "", err
		}
		if err := os.Rename(cur+".pub", retired+".pub"); err != nil {
			return "", err
		}
	}
	if err := os.Rename(next, cur); err != nil {
		return "", err
	}
	return retired, os.Rename(next+".pub", cur+".pub")
}
