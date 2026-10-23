package keys

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

const (
	keyringService = "farol-guard"
	envPassphrase  = "FAROL_GUARD_APP_PASSPHRASE"
	credentialName = "farol-app-passphrase"
)

var (
	ErrNoSecretStore = errors.New("no secret store available (system keyring, " + envPassphrase + " or systemd credential)")
	secretMu         sync.Mutex
)

func keyringAccount() string { return "app-key-passphrase:" + InstanceID() }

func IsAppKeyPath(path string) bool {
	base := filepath.Base(path)
	return filepath.Dir(path) == Dir() && (base == AppKeyName || strings.HasPrefix(base, AppKeyName+"."))
}

func externalPassphrase() []byte {
	if v := os.Getenv(envPassphrase); v != "" {
		return []byte(v)
	}
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		if data, err := os.ReadFile(filepath.Join(dir, credentialName)); err == nil {
			return []byte(strings.TrimSpace(string(data)))
		}
	}
	return nil
}

func AppPassphrase(create bool) ([]byte, string, error) {
	if p := externalPassphrase(); p != nil {
		return p, "external", nil
	}
	secretMu.Lock()
	defer secretMu.Unlock()
	v, err := keyring.Get(keyringService, keyringAccount())
	if err == nil {
		return []byte(v), "keyring", nil
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return nil, "", fmt.Errorf("%w: %v", ErrNoSecretStore, err)
	}
	if !create {
		return nil, "", fmt.Errorf("app key passphrase not found in the system keyring")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, "", err
	}
	secret := base64.RawStdEncoding.EncodeToString(b)
	if err := keyring.Set(keyringService, keyringAccount(), secret); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrNoSecretStore, err)
	}
	return []byte(secret), "keyring", nil
}

func SecretStoreStatus() string {
	if externalPassphrase() != nil {
		return "external"
	}
	_, err := keyring.Get(keyringService, keyringAccount())
	switch {
	case err == nil:
		return "keyring"
	case errors.Is(err, keyring.ErrNotFound):
		return "keyring-empty"
	}
	return "unavailable"
}

func PassphraseFor(path string) []byte {
	if !IsAppKeyPath(path) {
		return nil
	}
	p, _, err := AppPassphrase(false)
	if err != nil {
		return nil
	}
	return p
}

func GenerateApp(name string) (*Key, bool, error) {
	pass, _, err := AppPassphrase(true)
	if err != nil {
		k, gerr := Generate(name, AppComment(), nil)
		return k, false, gerr
	}
	k, err := Generate(name, AppComment(), pass)
	return k, err == nil, err
}

func ProtectApp() (*Key, error) {
	k, err := Get(AppKeyName)
	if err != nil {
		return nil, err
	}
	if k.Encrypted {
		return k, nil
	}
	data, err := os.ReadFile(k.Path)
	if err != nil {
		return nil, err
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, err
	}
	pass, _, err := AppPassphrase(true)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(raw, k.Comment, pass)
	if err != nil {
		return nil, err
	}
	tmp := k.Path + ".tmp"
	if err := os.WriteFile(tmp, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	if _, err := ssh.ParsePrivateKeyWithPassphrase(pem.EncodeToMemory(block), pass); err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("verification of the protected key failed: %w", err)
	}
	if err := os.Rename(tmp, k.Path); err != nil {
		return nil, err
	}
	return Get(AppKeyName)
}
