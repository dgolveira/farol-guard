package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/keys"
	"github.com/dgolveira/farol-guard/internal/server"
	"github.com/dgolveira/farol-guard/internal/sshx"
	"golang.org/x/term"
)

func cmdUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	cfg := fs.String("c", inventory.DefaultPath(), "inventory path")
	listen := fs.String("listen", "127.0.0.1:7380", "listen address")
	idleExit := fs.Duration("idle-exit", envDuration("FAROL_GUARD_IDLE_EXIT"), "exit when no dashboard page has been open for this long (0 = never; set by 'farol open')")
	var allowed listFlag
	fs.Var(&allowed, "allowed-host", "extra Host header accepted, e.g. the domain of a reverse proxy (repeatable; also FAROL_GUARD_ALLOWED_HOSTS)")
	noOpen := fs.Bool("no-open", false, "do not open the browser")
	acceptNew := fs.Bool("accept-new", false, "trust unknown host keys automatically")
	knownHosts := fs.String("known-hosts", defaultKnownHosts(), "known_hosts file")
	fs.Parse(args)

	inv, err := inventory.Load(*cfg)
	if err != nil {
		if err := inventory.WriteSample(*cfg); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "created sample inventory at", *cfg)
		if inv, err = inventory.Load(*cfg); err != nil {
			return err
		}
	}

	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("invalid --listen: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		fmt.Fprintln(os.Stderr, "WARNING: listening on a non-loopback address. Anyone with the token URL can control farol-guard;")
		fmt.Fprintln(os.Stderr, "         put it behind an authenticating proxy (see docs/hosting.md).")
	}
	if os.Getenv("FAROL_GUARD_TOKEN") == "" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
		fmt.Fprintln(os.Stderr, "NOTE: using the session token stored in "+tokenPath()+"; set FAROL_GUARD_TOKEN to manage it as a secret.")
	}

	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	d := sshx.NewDialer(sshx.Options{KnownHostsPath: *knownHosts, AcceptNew: *acceptNew, Interactive: interactive, PassphraseFor: keys.PassphraseFor})
	seen := map[string]bool{}
	for _, h := range inv.Hosts() {
		if seen[h.Identity] {
			continue
		}
		seen[h.Identity] = true
		if err := d.PreloadKey(h.Identity); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}
	d.SetInteractive(false)

	token, err := uiToken()
	if err != nil {
		return err
	}
	hosts := splitList(strings.Join(allowed, ","))
	hosts = append(hosts, splitList(os.Getenv("FAROL_GUARD_ALLOWED_HOSTS"))...)
	srv := server.New(server.Config{Listen: *listen, InventoryPath: *cfg, Version: version, Token: token, Dialer: d, AllowedHosts: hosts, IdleExit: *idleExit})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := srv.Listen()
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s/?token=%s", *listen, token)
	fmt.Fprintf(os.Stderr, "farol-guard %s dashboard: %s\nPress Ctrl+C to stop.\n", version, url)
	if !*noOpen {
		_ = exec.Command("xdg-open", url).Start()
	}
	return srv.Serve(ctx, ln)
}

func envDuration(key string) time.Duration {
	d, _ := time.ParseDuration(os.Getenv(key))
	return d
}
