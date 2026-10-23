package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/dgolveira/farol-guard/internal/check"
	"github.com/dgolveira/farol-guard/internal/history"
	"github.com/dgolveira/farol-guard/internal/i18n"
	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/keys"
	"github.com/dgolveira/farol-guard/internal/model"
	"github.com/dgolveira/farol-guard/internal/report"
	"github.com/dgolveira/farol-guard/internal/sshx"
	"golang.org/x/term"
)

var version = "dev"

const usage = `farol-guard - agentless SSH auditor for Debian/Ubuntu fleets

Usage:
  farol <command> [flags]

Commands:
  init      Create a sample inventory at the default path
  hosts     List hosts from the inventory
  check     Audit hosts and write a report (html, json or md)
  ui        Start the local web dashboard
  keys      Manage SSH keys: generate, deploy, rotate, remove
  version   Print version

Run 'farol <command> -h' for command flags.
Inventory: $FAROL_GUARD_CONFIG or ~/.config/farol-guard/inventory.yaml
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "hosts":
		err = cmdHosts(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "ui":
		err = cmdUI(os.Args[2:])
	case "keys":
		err = cmdKeys(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("farol-guard", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		var ec exitCode
		if errors.As(err, &ec) {
			os.Exit(int(ec))
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	cfg := fs.String("c", inventory.DefaultPath(), "inventory path")
	fs.Parse(args)
	if err := inventory.WriteSample(*cfg); err != nil {
		return err
	}
	fmt.Println("created", *cfg)
	return nil
}

func cmdHosts(args []string) error {
	fs := flag.NewFlagSet("hosts", flag.ExitOnError)
	cfg := fs.String("c", inventory.DefaultPath(), "inventory path")
	fs.Parse(args)
	inv, err := inventory.Load(*cfg)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "GROUP\tNAME\tTARGET\tIDENTITY\tTAGS")
	for _, h := range inv.Hosts() {
		fmt.Fprintf(w, "%s\t%s\t%s@%s:%d\t%s\t%s\n", h.Group, h.Name, h.User, h.Address, h.Port, h.Identity, strings.Join(h.Tags, ","))
	}
	return w.Flush()
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfg := fs.String("c", inventory.DefaultPath(), "inventory path")
	var groups, hosts listFlag
	fs.Var(&groups, "g", "group to audit (repeatable or comma separated)")
	fs.Var(&hosts, "H", "host to audit (repeatable or comma separated)")
	out := fs.String("o", "", "output file (default farol-report-<timestamp>.html; '-' for stdout)")
	format := fs.String("f", "", "output format: html, json, md (default from -o extension)")
	lang := fs.String("lang", "", "report language: en, pt-BR (default from $LANG)")
	parallel := fs.Int("parallel", 8, "hosts audited in parallel")
	timeout := fs.Duration("timeout", 3*time.Minute, "per-host collection timeout")
	connTimeout := fs.Duration("connect-timeout", 15*time.Second, "SSH connect timeout")
	refresh := fs.Bool("refresh", false, "run apt-get update on hosts before checking updates")
	noCVE := fs.Bool("no-cve", false, "skip CVE lookup on OSV.dev")
	acceptNew := fs.Bool("accept-new", false, "trust unknown host keys automatically (like StrictHostKeyChecking=accept-new)")
	knownHosts := fs.String("known-hosts", defaultKnownHosts(), "known_hosts file")
	failOn := fs.String("fail-on", "", "exit with code 3 if any finding has at least this severity (low, medium, high, critical)")
	quiet := fs.Bool("q", false, "no progress output")
	verbose := fs.Bool("v", false, "print every collection and CVE lookup step")
	noHistory := fs.Bool("no-history", false, "do not save the report in the dashboard history")
	fs.Parse(args)

	var failSev model.Severity
	if *failOn != "" {
		s, err := model.ParseSeverity(*failOn)
		if err != nil {
			return err
		}
		failSev = s
	}
	inv, err := inventory.Load(*cfg)
	if err != nil {
		return err
	}
	selected, err := inv.Select(groups, hosts)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		return errors.New("no hosts selected")
	}
	for _, dup := range inventory.Duplicates(selected) {
		fmt.Fprintf(os.Stderr, "warning: %s is the target of several hosts: %s (it will be audited more than once)\n", dup.Target, strings.Join(dup.Hosts, ", "))
	}
	language := i18n.Detect(*lang)
	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	logf := func(format string, a ...any) {
		if !*quiet {
			fmt.Fprintf(os.Stderr, format+"\n", a...)
		}
	}

	d := sshx.NewDialer(sshx.Options{KnownHostsPath: *knownHosts, AcceptNew: *acceptNew, Interactive: interactive, Timeout: *connTimeout, PassphraseFor: keys.PassphraseFor})
	if !d.HasAgent() {
		logf("ssh-agent not available: encrypted keys will ask for the passphrase")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logf("auditing %d hosts", len(selected))
	lastPct := -1
	var pending map[string]*model.HostKeyInfo
	if !interactive && !*acceptNew {
		prev, _, _ := history.Latest()
		pending = check.PendingFrom(prev, selected)
	}
	rep, err := check.Run(ctx, inv, selected, d, check.Options{
		Pending:  pending,
		Parallel: *parallel, Timeout: *timeout, RefreshApt: *refresh, NoCVE: *noCVE,
		Lang: language, Version: version,
		Log: func(format string, a ...any) {
			if *verbose {
				logf("  "+time.Now().Format("15:04:05")+" "+format, a...)
			}
		},
		OnHost: func(h *model.HostReport) {
			if h.Reachable {
				logf("  %-24s ok   %s (%s)", h.Name, h.OS.Pretty, h.Duration.Round(time.Millisecond))
			} else {
				logf("  %-24s FAIL %s", h.Name, h.Error)
			}
		},
		OnCVE: func(done, total int) {
			if pct := done * 100 / total; pct/10 != lastPct/10 || done == total {
				lastPct = pct
				logf("  cve lookup %d/%d", done, total)
			}
		},
	})
	if err != nil {
		logf("warning: %v", err)
	}

	if !*noHistory {
		if id, err := history.Save(rep); err != nil {
			logf("warning: history not saved: %v", err)
		} else {
			logf("saved to history as %s", id)
		}
	}

	path := *out
	if path == "" {
		ext := ".html"
		if *format == "json" || *format == "md" {
			ext = "." + *format
		}
		path = "farol-report-" + time.Now().Format("20060102-1504") + ext
	}
	f := report.Format(*format)
	if f == "" {
		f = report.FormatFromPath(path)
	}
	w := os.Stdout
	if path != "-" {
		fh, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer fh.Close()
		w = fh
	}
	if err := report.Write(w, rep, f, language); err != nil {
		return err
	}
	if path != "-" {
		abs, _ := filepath.Abs(path)
		logf("report written to %s", abs)
	}
	printSummary(rep, *quiet)

	if *failOn != "" {
		for _, h := range rep.Hosts {
			if h.Worst() >= failSev && len(h.Findings) > 0 {
				return exitCode(3)
			}
		}
	}
	return nil
}

func printSummary(rep *model.Report, quiet bool) {
	if quiet {
		return
	}
	w := tabwriter.NewWriter(os.Stderr, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "\nHOST\tSTATUS\tCRIT\tHIGH\tMED\tSEC-UPD\tCVE-FIX")
	for _, h := range rep.Hosts {
		status := h.Worst().String()
		if !h.Reachable {
			status = "unreachable"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%d\n", h.Name, status,
			h.CountFindings(model.SevCritical), h.CountFindings(model.SevHigh), h.CountFindings(model.SevMedium),
			h.SecurityUpgrades(), h.FixableVulns(0))
	}
	w.Flush()
}

func defaultKnownHosts() string {
	if p := os.Getenv("FAROL_GUARD_KNOWN_HOSTS"); p != "" {
		return p
	}
	return inventory.ExpandHome("~/.ssh/known_hosts")
}
