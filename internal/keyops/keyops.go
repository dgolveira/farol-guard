package keyops

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/keys"
	"github.com/dgolveira/farol-guard/internal/sshx"
	"golang.org/x/crypto/ssh"
)

//go:embed keyops.sh
var script string

var userRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}\$?$`)

const (
	StatusOK     = "ok"
	StatusFail   = "fail"
	StatusSkip   = "skip"
	StatusDryRun = "dry-run"
)

type Request struct {
	Hosts     []inventory.Host
	Users     []string
	NewKey    *keys.Key
	NewSigner ssh.Signer
	FromIPs   []string
	RemoveFP  string
	RemoveCur bool
	DryRun    bool
	Parallel  int
}

type Event struct {
	User    string `json:"user"`
	Action  string `json:"action"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type Result struct {
	Host   string  `json:"host"`
	OK     bool    `json:"ok"`
	Events []Event `json:"events"`
}

func (r *Result) add(user, action, status, format string, a ...any) {
	r.Events = append(r.Events, Event{User: user, Action: action, Status: status, Message: fmt.Sprintf(format, a...)})
	if status == StatusFail {
		r.OK = false
	}
}

func (req *Request) Validate() error {
	for _, u := range req.Users {
		if !userRe.MatchString(u) {
			return fmt.Errorf("invalid user name %q", u)
		}
	}
	for _, ip := range req.FromIPs {
		if net.ParseIP(ip) == nil {
			if _, _, err := net.ParseCIDR(ip); err != nil {
				return fmt.Errorf("invalid from address %q", ip)
			}
		}
	}
	if !req.DryRun && req.NewKey != nil && req.NewSigner == nil {
		return errors.New("new key signer required to verify access")
	}
	return nil
}

func (req *Request) usersFor(h inventory.Host) []string {
	if len(req.Users) == 0 {
		return []string{h.User}
	}
	return req.Users
}

func target(h inventory.Host) sshx.Target {
	return sshx.Target{Address: h.Address, Port: h.Port, User: h.User, Identity: h.Identity}
}

func forEach(req *Request, fn func(h inventory.Host) Result) []Result {
	n := req.Parallel
	if n < 1 {
		n = 8
	}
	out := make([]Result, len(req.Hosts))
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, h := range req.Hosts {
		wg.Add(1)
		go func(i int, h inventory.Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = fn(h)
		}(i, h)
	}
	wg.Wait()
	return out
}

func Deploy(ctx context.Context, d *sshx.Dialer, req Request) ([]Result, error) {
	if req.NewKey == nil {
		return nil, errors.New("no key to deploy")
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	line := keys.AuthorizedLine(req.NewKey, req.FromIPs)
	return forEach(&req, func(h inventory.Host) Result {
		res := Result{Host: h.Name, OK: true}
		client, err := d.Dial(target(h))
		if err != nil {
			res.add(h.User, "connect", StatusFail, "%v", err)
			return res
		}
		defer client.Close()
		for _, u := range req.usersFor(h) {
			original, err := readKeys(ctx, client, u)
			if err != nil {
				res.add(u, "read", StatusFail, "%v", err)
				continue
			}
			added := false
			if idx := lineIndex(original, req.NewKey.Fingerprint); idx >= 0 {
				if strings.TrimSpace(original[idx]) == line {
					res.add(u, "add", StatusSkip, "key already present")
				} else if req.DryRun {
					res.add(u, "update", StatusDryRun, "[DRY-RUN] would update the options of the existing line")
					continue
				} else {
					updated := append([]string{}, original...)
					updated[idx] = line
					backup, err := writeKeys(ctx, client, u, updated)
					if err != nil {
						res.add(u, "update", StatusFail, "%v", err)
						continue
					}
					added = true
					res.add(u, "update", StatusOK, "options updated, backup %s", backup)
				}
			} else if req.DryRun {
				res.add(u, "add", StatusDryRun, "[DRY-RUN] would append %s to authorized_keys", req.NewKey.Fingerprint)
				continue
			} else {
				backup, err := writeKeys(ctx, client, u, appendLine(original, line))
				if err != nil {
					res.add(u, "add", StatusFail, "%v", err)
					continue
				}
				added = true
				res.add(u, "add", StatusOK, "backup %s", backup)
			}
			if req.DryRun {
				continue
			}
			if err := verify(d, h, u, req.NewSigner); err != nil {
				res.add(u, "verify", StatusFail, "new key rejected: %v", err)
				if added {
					if _, rerr := writeKeys(ctx, client, u, original); rerr != nil {
						res.add(u, "rollback", StatusFail, "%v", rerr)
					} else {
						res.add(u, "rollback", StatusOK, "previous authorized_keys restored")
					}
				}
				continue
			}
			res.add(u, "verify", StatusOK, "login with the new key works")
		}
		return res
	}), nil
}

func Remove(ctx context.Context, d *sshx.Dialer, req Request) ([]Result, error) {
	if req.RemoveFP == "" && !req.RemoveCur {
		return nil, errors.New("no key to remove")
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return forEach(&req, func(h inventory.Host) Result {
		res := Result{Host: h.Name, OK: true}
		fp := req.RemoveFP
		identityFP, _ := keys.FingerprintOfFile(h.Identity)
		if req.RemoveCur {
			if identityFP == "" {
				res.add(h.User, "remove", StatusFail, "cannot read %s.pub to find the current key", h.Identity)
				return res
			}
			fp = identityFP
		}
		if req.NewKey == nil && fp == identityFP {
			res.add(h.User, "remove", StatusFail, "refusing to remove the key farol-guard logs in with; use rotate with a new key")
			return res
		}
		client, err := d.Dial(target(h))
		if err != nil {
			res.add(h.User, "connect", StatusFail, "%v", err)
			return res
		}
		defer client.Close()
		for _, u := range req.usersFor(h) {
			if req.NewSigner != nil && !req.DryRun {
				if err := verify(d, h, u, req.NewSigner); err != nil {
					res.add(u, "verify", StatusFail, "new key does not work yet, old key kept: %v", err)
					continue
				}
			}
			original, err := readKeys(ctx, client, u)
			if err != nil {
				res.add(u, "read", StatusFail, "%v", err)
				continue
			}
			updated, n := removeFingerprint(original, fp)
			if n == 0 {
				res.add(u, "remove", StatusSkip, "%s not present", fp)
				continue
			}
			if req.DryRun {
				res.add(u, "remove", StatusDryRun, "[DRY-RUN] would remove %d line(s) with %s", n, fp)
				continue
			}
			backup, err := writeKeys(ctx, client, u, updated)
			if err != nil {
				res.add(u, "remove", StatusFail, "%v", err)
				continue
			}
			res.add(u, "remove", StatusOK, "removed %d line(s), backup %s", n, backup)
			if u != h.User {
				continue
			}
			var verr error
			if req.NewSigner != nil {
				verr = verify(d, h, u, req.NewSigner)
			} else {
				var c *ssh.Client
				if c, verr = d.Dial(target(h)); verr == nil {
					c.Close()
				}
			}
			if verr != nil {
				res.add(u, "verify", StatusFail, "login failed after removal: %v", verr)
				if _, rerr := writeKeys(ctx, client, u, original); rerr != nil {
					res.add(u, "rollback", StatusFail, "%v", rerr)
				} else {
					res.add(u, "rollback", StatusOK, "previous authorized_keys restored")
				}
				continue
			}
			res.add(u, "verify", StatusOK, "login still works")
		}
		return res
	}), nil
}

func verify(d *sshx.Dialer, h inventory.Host, user string, s ssh.Signer) error {
	t := target(h)
	t.User = user
	c, err := d.DialWithSigner(t, s)
	if err != nil {
		return err
	}
	return c.Close()
}

func remoteCmd(action, user string) string {
	args := action + " " + user
	return fmt.Sprintf(`if [ "$(id -u)" = 0 ]; then exec bash -s -- %[1]s; elif sudo -n true 2>/dev/null; then exec sudo -n bash -s -- %[1]s; else exec bash -s -- %[1]s; fi`, args)
}

func run(ctx context.Context, client *ssh.Client, action, user, prologue string) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, stderr, err := sshx.Run(cctx, client, remoteCmd(action, user), []byte(prologue+script))
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "@@error ") {
			return nil, errors.New(strings.TrimPrefix(l, "@@error "))
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%v %s", err, strings.TrimSpace(string(stderr)))
	}
	return lines, nil
}

func readKeys(ctx context.Context, client *ssh.Client, user string) ([]string, error) {
	lines, err := run(ctx, client, "read", user, "")
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "@@path ") {
		return nil, errors.New("unexpected helper output")
	}
	return lines[1:], nil
}

func writeKeys(ctx context.Context, client *ssh.Client, user string, content []string) (string, error) {
	data := strings.Join(content, "\n")
	if data != "" {
		data += "\n"
	}
	prologue := "FAROL_CONTENT_B64=" + base64.StdEncoding.EncodeToString([]byte(data)) + "\n"
	lines, err := run(ctx, client, "write", user, prologue)
	if err != nil {
		return "", err
	}
	backup := "none"
	written := false
	for _, l := range lines {
		if strings.HasPrefix(l, "@@backup ") {
			backup = strings.TrimPrefix(l, "@@backup ")
		}
		if strings.HasPrefix(l, "@@written ") {
			written = true
		}
	}
	if !written {
		return "", errors.New("helper did not confirm the write")
	}
	return backup, nil
}

func lineFingerprint(l string) string {
	t := strings.TrimSpace(l)
	if t == "" || strings.HasPrefix(t, "#") {
		return ""
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

func lineIndex(lines []string, fp string) int {
	for i, l := range lines {
		if lineFingerprint(l) == fp {
			return i
		}
	}
	return -1
}

func containsFingerprint(lines []string, fp string) bool {
	for _, l := range lines {
		if lineFingerprint(l) == fp {
			return true
		}
	}
	return false
}

func appendLine(lines []string, line string) []string {
	out := append([]string{}, lines...)
	return append(out, line)
}

func removeFingerprint(lines []string, fp string) ([]string, int) {
	var out []string
	n := 0
	for _, l := range lines {
		if lineFingerprint(l) == fp {
			n++
			continue
		}
		out = append(out, l)
	}
	return out, n
}
