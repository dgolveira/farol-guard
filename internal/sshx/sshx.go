package sshx

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

type Options struct {
	KnownHostsPath string
	AcceptNew      bool
	Interactive    bool
	Timeout        time.Duration
	PassphraseFor  func(path string) []byte
}

type Dialer struct {
	opts      Options
	promptMu  sync.Mutex
	hostsMu   sync.Mutex
	keyMu     sync.Mutex
	keys      map[string]ssh.Signer
	keyErrs   map[string]error
	pendingMu sync.Mutex
	pending   map[string]ssh.PublicKey
	agent     agent.ExtendedAgent
}

type Target struct {
	Address  string
	Port     int
	User     string
	Identity string
}

func (t Target) HostPort() string {
	return net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
}

func NewDialer(opts Options) *Dialer {
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	d := &Dialer{opts: opts, keys: map[string]ssh.Signer{}, keyErrs: map[string]error{}, pending: map[string]ssh.PublicKey{}}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			d.agent = agent.NewClient(conn)
		}
	}
	return d
}

func (d *Dialer) HasAgent() bool { return d.agent != nil }

func (d *Dialer) Dial(t Target) (*ssh.Client, error) {
	return d.dial(t, func() ([]ssh.Signer, error) { return d.signers(t.Identity) })
}

func (d *Dialer) DialWithSigner(t Target, s ssh.Signer) (*ssh.Client, error) {
	return d.dial(t, func() ([]ssh.Signer, error) { return []ssh.Signer{s}, nil })
}

type algoMismatch struct{ algos []string }

func (e *algoMismatch) Error() string { return "known host key uses another algorithm" }

func (d *Dialer) dial(t Target, sig func() ([]ssh.Signer, error)) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            t.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(sig)},
		HostKeyCallback: d.hostKeyCallback,
		Timeout:         d.opts.Timeout,
	}
	c, err := ssh.Dial("tcp", t.HostPort(), cfg)
	var am *algoMismatch
	if err != nil && errors.As(err, &am) {
		cfg.HostKeyAlgorithms = am.algos
		return ssh.Dial("tcp", t.HostPort(), cfg)
	}
	return c, err
}

func algorithmsFor(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

func (d *Dialer) agentSigners() []ssh.Signer {
	if d.agent == nil {
		return nil
	}
	s, err := d.agent.Signers()
	if err != nil {
		return nil
	}
	return s
}

func (d *Dialer) signers(identity string) ([]ssh.Signer, error) {
	agentSigners := d.agentSigners()
	if identity == "" {
		return agentSigners, nil
	}
	if pub, err := readPublicKey(identity + ".pub"); err == nil {
		want := ssh.FingerprintSHA256(pub)
		for i, s := range agentSigners {
			if ssh.FingerprintSHA256(s.PublicKey()) == want {
				ordered := append([]ssh.Signer{s}, agentSigners[:i]...)
				return append(ordered, agentSigners[i+1:]...), nil
			}
		}
	}
	s, err := d.LoadKey(identity)
	if err != nil {
		if len(agentSigners) > 0 {
			return agentSigners, nil
		}
		return nil, err
	}
	return append([]ssh.Signer{s}, agentSigners...), nil
}

func (d *Dialer) LoadKey(path string) (ssh.Signer, error) {
	d.keyMu.Lock()
	defer d.keyMu.Unlock()
	if s, ok := d.keys[path]; ok {
		return s, nil
	}
	if err, ok := d.keyErrs[path]; ok {
		return nil, err
	}
	if pub, err := readPublicKey(path + ".pub"); err == nil {
		want := ssh.FingerprintSHA256(pub)
		for _, s := range d.agentSigners() {
			if ssh.FingerprintSHA256(s.PublicKey()) == want {
				d.keys[path] = s
				return s, nil
			}
		}
	}
	s, err := d.loadKey(path)
	if err != nil {
		d.keyErrs[path] = err
		return nil, err
	}
	d.keys[path] = s
	return s, nil
}

func (d *Dialer) loadKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return s, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if d.opts.PassphraseFor != nil {
		if pass := d.opts.PassphraseFor(path); pass != nil {
			if s, err := ssh.ParsePrivateKeyWithPassphrase(data, pass); err == nil {
				return s, nil
			}
			return nil, fmt.Errorf("%s: the passphrase stored in the system keyring does not unlock it", path)
		}
	}
	if !d.opts.Interactive {
		return nil, fmt.Errorf("%s is encrypted and not loaded in ssh-agent (run ssh-add; for the farol-guard app key, unlock the system keyring or set FAROL_GUARD_APP_PASSPHRASE)", path)
	}
	d.promptMu.Lock()
	defer d.promptMu.Unlock()
	fmt.Fprintf(os.Stderr, "Passphrase for %s: ", path)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKeyWithPassphrase(data, pass)
}

func readPublicKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	return pub, err
}

func (d *Dialer) hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	d.hostsMu.Lock()
	defer d.hostsMu.Unlock()
	path := d.opts.KnownHostsPath
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	cb, err := knownhosts.New(path)
	if err != nil {
		return err
	}
	err = cb(hostname, remote, key)
	var kerr *knownhosts.KeyError
	if err == nil || !errors.As(err, &kerr) {
		return err
	}
	if len(kerr.Want) > 0 {
		var algos []string
		for _, w := range kerr.Want {
			if w.Key.Type() == key.Type() {
				algos = nil
				break
			}
			algos = append(algos, algorithmsFor(w.Key.Type())...)
		}
		if len(algos) > 0 {
			return &algoMismatch{algos: algos}
		}
		return fmt.Errorf("HOST KEY MISMATCH for %s (got %s %s): possible MITM, fix %s manually",
			hostname, key.Type(), ssh.FingerprintSHA256(key), path)
	}
	if !d.opts.AcceptNew {
		if !d.opts.Interactive {
			d.pendingMu.Lock()
			d.pending[knownhosts.Normalize(hostname)] = key
			d.pendingMu.Unlock()
			return &UnknownHostError{Host: hostname, Type: key.Type(), Fingerprint: ssh.FingerprintSHA256(key),
				Key: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))}
		}
		d.promptMu.Lock()
		ok := confirm(fmt.Sprintf("Unknown host %s\n  %s %s\nTrust and add to %s? [y/N] ",
			hostname, key.Type(), ssh.FingerprintSHA256(key), path))
		d.promptMu.Unlock()
		if !ok {
			return fmt.Errorf("host key for %s rejected by user", hostname)
		}
	}
	return appendKnownHost(path, hostname, key)
}

func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
	af, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer af.Close()
	_, err = fmt.Fprintln(af, line)
	return err
}

type UnknownHostError struct {
	Host, Type, Fingerprint, Key string
}

func (e *UnknownHostError) Error() string {
	return fmt.Sprintf("unknown host key for %s (%s %s): trust it interactively, in the UI or with --accept-new", e.Host, e.Type, e.Fingerprint)
}

func (d *Dialer) SetInteractive(v bool) { d.opts.Interactive = v }

var errScanned = errors.New("host key scanned")

func (d *Dialer) ScanHostKey(t Target) (ssh.PublicKey, error) {
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "farol-scan",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errScanned
		},
		Timeout: d.opts.Timeout,
	}
	_, err := ssh.Dial("tcp", t.HostPort(), cfg)
	if got != nil {
		return got, nil
	}
	return nil, err
}

func (d *Dialer) TrustHostKey(t Target, fingerprint, capturedKey string) error {
	key := d.capturedKey(t, capturedKey)
	if key == nil || ssh.FingerprintSHA256(key) != fingerprint {
		var err error
		if key, err = d.ScanHostKey(t); err != nil {
			return err
		}
	}
	if fp := ssh.FingerprintSHA256(key); fp != fingerprint {
		return fmt.Errorf("host key changed during confirmation: expected %s, got %s", fingerprint, fp)
	}
	d.hostsMu.Lock()
	defer d.hostsMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(d.opts.KnownHostsPath), 0o700); err != nil {
		return err
	}
	return appendKnownHost(d.opts.KnownHostsPath, t.HostPort(), key)
}

func (d *Dialer) capturedKey(t Target, line string) ssh.PublicKey {
	d.pendingMu.Lock()
	key := d.pending[knownhosts.Normalize(t.HostPort())]
	d.pendingMu.Unlock()
	if key != nil {
		return key
	}
	if line == "" {
		return nil
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil
	}
	return pub
}

func (d *Dialer) IsTrusted(t Target, keyLine string) bool {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
	if err != nil {
		return false
	}
	d.hostsMu.Lock()
	defer d.hostsMu.Unlock()
	cb, err := knownhosts.New(d.opts.KnownHostsPath)
	if err != nil {
		return false
	}
	addr := &net.TCPAddr{IP: net.IPv4zero, Port: t.Port}
	return cb(t.HostPort(), addr, pub) == nil
}

func (d *Dialer) PreloadKey(identity string) error {
	if pub, err := readPublicKey(identity + ".pub"); err == nil {
		want := ssh.FingerprintSHA256(pub)
		for _, s := range d.agentSigners() {
			if ssh.FingerprintSHA256(s.PublicKey()) == want {
				return nil
			}
		}
	}
	_, err := d.LoadKey(identity)
	return err
}

func confirm(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	r := bufio.NewReader(os.Stdin)
	ans, _ := r.ReadString('\n')
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes" || ans == "s" || ans == "sim"
}

func Run(ctx context.Context, c *ssh.Client, cmd string, stdin []byte) ([]byte, []byte, error) {
	sess, err := c.NewSession()
	if err != nil {
		return nil, nil, err
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdout, sess.Stderr = &out, &errb
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		c.Close()
		err = ctx.Err()
	}
	return out.Bytes(), errb.Bytes(), err
}

func Fingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }

func (d *Dialer) ForgetKey(path string) {
	d.keyMu.Lock()
	defer d.keyMu.Unlock()
	delete(d.keys, path)
	delete(d.keyErrs, path)
}

func (d *Dialer) LoadKeyWithPassphrase(path string, pass []byte) (ssh.Signer, error) {
	d.keyMu.Lock()
	defer d.keyMu.Unlock()
	if s, ok := d.keys[path]; ok {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s ssh.Signer
	if len(pass) > 0 {
		s, err = ssh.ParsePrivateKeyWithPassphrase(data, pass)
	} else {
		s, err = ssh.ParsePrivateKey(data)
	}
	if err != nil {
		return nil, err
	}
	d.keys[path] = s
	delete(d.keyErrs, path)
	return s, nil
}

func (d *Dialer) AgentFingerprints() map[string]bool {
	m := map[string]bool{}
	for _, s := range d.agentSigners() {
		m[ssh.FingerprintSHA256(s.PublicKey())] = true
	}
	return m
}

func RunStream(ctx context.Context, c *ssh.Client, cmd string, stdin []byte, onLine func(string)) ([]byte, []byte, error) {
	sess, err := c.NewSession()
	if err != nil {
		return nil, nil, err
	}
	defer sess.Close()
	var errb bytes.Buffer
	sess.Stderr = &errb
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	pipe, err := sess.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := sess.Start(cmd); err != nil {
		return nil, nil, err
	}
	var out bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		sc := bufio.NewScanner(pipe)
		sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			out.WriteString(line)
			out.WriteByte('\n')
			if onLine != nil {
				onLine(line)
			}
		}
	}()
	done := make(chan error, 1)
	go func() {
		<-readDone
		done <- sess.Wait()
	}()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		c.Close()
		<-readDone
		err = ctx.Err()
	}
	return out.Bytes(), errb.Bytes(), err
}
