package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dgolveira/farol-guard/internal/inventory"
	"golang.org/x/crypto/ssh"
)

const AppKeyName = "farol-app"

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

type Key struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	Type        string    `json:"type"`
	Fingerprint string    `json:"fingerprint"`
	Comment     string    `json:"comment"`
	Encrypted   bool      `json:"encrypted"`
	Created     time.Time `json:"created"`
	PublicLine  string    `json:"public"`
	Managed     bool      `json:"managed"`
	Source      string    `json:"source,omitempty"`
	InAgent     bool      `json:"in_agent,omitempty"`
	Retired     bool      `json:"retired,omitempty"`
}

func Dir() string { return filepath.Join(inventory.ConfigDir(), "keys") }

func ValidName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid key name %q (letters, digits, '.', '_' and '-')", name)
	}
	return nil
}

func Generate(name, comment string, passphrase []byte) (*Key, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	dir := Dir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("key %q already exists", name)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if comment == "" {
		host, _ := os.Hostname()
		comment = fmt.Sprintf("farol-guard:%s@%s %s", name, host, time.Now().Format("2006-01-02"))
	}
	var block *pem.Block
	if len(passphrase) > 0 {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, comment, passphrase)
	} else {
		block, err = ssh.MarshalPrivateKey(priv, comment)
	}
	if err != nil {
		return nil, err
	}
	spub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(spub))) + " " + comment
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path+".pub", []byte(line+"\n"), 0o644); err != nil {
		return nil, err
	}
	return Get(name)
}

const SSHPrefix = "ssh:"

func Get(name string) (*Key, error) {
	if rest, ok := strings.CutPrefix(name, SSHPrefix); ok {
		if err := ValidName(rest); err != nil {
			return nil, err
		}
		k, err := load(inventory.ExpandHome("~/.ssh/" + rest))
		if err != nil {
			return nil, err
		}
		k.Name, k.Source = name, "ssh"
		return k, nil
	}
	if err := ValidName(name); err != nil {
		return nil, err
	}
	return load(filepath.Join(Dir(), name))
}

func ListSSH() []Key {
	var out []Key
	entries, err := os.ReadDir(inventory.ExpandHome("~/.ssh"))
	if err != nil {
		return nil
	}
	for _, e := range entries {
		base, ok := strings.CutSuffix(e.Name(), ".pub")
		if !ok || ValidName(base) != nil {
			continue
		}
		if k, err := Get(SSHPrefix + base); err == nil {
			out = append(out, *k)
		}
	}
	return out
}

func IsRetired(name string) bool {
	return strings.HasPrefix(name, AppKeyName+".retired-")
}

func Delete(name string) error {
	if strings.HasPrefix(name, SSHPrefix) {
		return errors.New("keys in ~/.ssh are not managed by farol-guard")
	}
	if err := ValidName(name); err != nil {
		return err
	}
	if name == AppKeyName || name == AppNextName {
		return errors.New("the current app key cannot be deleted; replace it instead")
	}
	path := filepath.Join(Dir(), name)
	if _, err := os.Stat(path + ".pub"); err != nil {
		return fmt.Errorf("key %q not found", name)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Remove(path + ".pub")
}

func load(path string) (*Key, error) {
	data, err := os.ReadFile(path + ".pub")
	if err != nil {
		return nil, err
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s.pub: %w", path, err)
	}
	k := &Key{
		Name: filepath.Base(path), Path: path, Type: pub.Type(),
		Fingerprint: ssh.FingerprintSHA256(pub), Comment: comment,
		PublicLine: strings.TrimSpace(string(data)),
	}
	if st, err := os.Stat(path); err == nil {
		k.Created = st.ModTime()
	}
	if priv, err := os.ReadFile(path); err == nil {
		_, perr := ssh.ParsePrivateKey(priv)
		var missing *ssh.PassphraseMissingError
		k.Encrypted = errors.As(perr, &missing)
	}
	k.Managed = IsAppKeyPath(path)
	k.Retired = IsRetired(k.Name)
	return k, nil
}

func List() ([]Key, error) {
	entries, err := os.ReadDir(Dir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Key
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		if k, err := load(filepath.Join(Dir(), e.Name())); err == nil {
			out = append(out, *k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func FingerprintOfFile(privatePath string) (string, error) {
	data, err := os.ReadFile(privatePath + ".pub")
	if err != nil {
		return "", err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(pub), nil
}

func AuthorizedLine(k *Key, fromIPs []string) string {
	var opts []string
	if k.Managed || strings.HasPrefix(k.Name, AppKeyName) {
		opts = append(opts, "restrict")
	}
	if len(fromIPs) > 0 {
		opts = append(opts, fmt.Sprintf(`from="%s"`, strings.Join(fromIPs, ",")))
	}
	if len(opts) == 0 {
		return k.PublicLine
	}
	return strings.Join(opts, ",") + " " + k.PublicLine
}

type Identity struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
	Source      string `json:"source"`
	InAgent     bool   `json:"in_agent"`
}

func Discover(agentFingerprints map[string]bool) []Identity {
	var out []Identity
	seen := map[string]bool{}
	add := func(priv, source string) {
		data, err := os.ReadFile(priv + ".pub")
		if err != nil {
			return
		}
		pub, comment, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return
		}
		if st, err := os.Stat(priv); err != nil || !st.Mode().IsRegular() {
			return
		}
		short := inventory.ShortHome(priv)
		if seen[short] {
			return
		}
		seen[short] = true
		fp := ssh.FingerprintSHA256(pub)
		out = append(out, Identity{Path: short, Type: pub.Type(), Fingerprint: fp, Comment: comment, Source: source, InAgent: agentFingerprints[fp]})
	}
	if entries, err := os.ReadDir(inventory.ExpandHome("~/.ssh")); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".pub") {
				add(inventory.ExpandHome("~/.ssh/"+strings.TrimSuffix(e.Name(), ".pub")), "ssh")
			}
		}
	}
	if list, err := List(); err == nil {
		for _, k := range list {
			add(k.Path, "farol")
		}
	}
	return out
}

func CheckPassphrase(path string, pass []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(pass) == 0 {
		_, err = ssh.ParsePrivateKey(data)
		return err
	}
	_, err = ssh.ParsePrivateKeyWithPassphrase(data, pass)
	return err
}
