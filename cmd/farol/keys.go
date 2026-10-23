package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/dgolveira/farol-guard/internal/history"
	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/keyops"
	"github.com/dgolveira/farol-guard/internal/keys"
	"github.com/dgolveira/farol-guard/internal/sshx"
	"golang.org/x/term"
)

const keysUsage = `Usage:
  farol keys list                       Local keys (~/.config/farol-guard/keys)
  farol keys fleet                      Authorized keys found in the latest report
  farol keys new <name> [--passphrase]  Generate an ed25519 key pair
  farol keys deploy <name> [scope]      Add a key to authorized_keys and verify login
  farol keys rotate <name> [scope]      Deploy a key, verify it, then remove the old one
  farol keys remove <fingerprint> [scope]
  farol keys app-init [scope]           Create and deploy the dedicated farol-app key
  farol keys app-rotate [--from IP]     Replace the app key on every host that has it (latest report)
  farol keys app-protect                Encrypt an existing app key with a passphrase kept in the system keyring
  farol keys pub <name> [--from IP]     Print the authorized_keys line for a key (manual install)

Scope flags: -g group, -H host, --users root,deploy (default: the login user)
Safety flags: --dry-run, --yes (skip confirmation prompts)
`

type keyFlags struct {
	fs         *flag.FlagSet
	cfg        *string
	groups     listFlag
	hosts      listFlag
	users      *string
	from       *string
	dryRun     *bool
	yes        *bool
	knownHosts *string
	acceptNew  *bool
}

func newKeyFlags(name string) *keyFlags {
	k := &keyFlags{fs: flag.NewFlagSet(name, flag.ExitOnError)}
	k.cfg = k.fs.String("c", inventory.DefaultPath(), "inventory path")
	k.fs.Var(&k.groups, "g", "group (repeatable or comma separated)")
	k.fs.Var(&k.hosts, "H", "host (repeatable or comma separated)")
	k.users = k.fs.String("users", "", "target users, comma separated (default: login user of each host)")
	k.from = k.fs.String("from", "", "restrict the key to these source IPs/CIDRs (from= option)")
	k.dryRun = k.fs.Bool("dry-run", false, "show what would change without touching any host")
	k.yes = k.fs.Bool("yes", false, "do not ask for confirmation")
	k.knownHosts = k.fs.String("known-hosts", defaultKnownHosts(), "known_hosts file")
	k.acceptNew = k.fs.Bool("accept-new", false, "trust unknown host keys automatically")
	return k
}

func (k *keyFlags) parse(args []string) []string {
	var pos []string
	for len(args) > 0 {
		k.fs.Parse(args)
		args = k.fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	return pos
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (k *keyFlags) setup() (*inventory.Inventory, []inventory.Host, *sshx.Dialer, error) {
	inv, err := inventory.Load(*k.cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(k.groups) == 0 && len(k.hosts) == 0 {
		return nil, nil, nil, errors.New("select hosts with -g and/or -H (key operations never default to the whole fleet)")
	}
	hosts, err := inv.Select(k.groups, k.hosts)
	if err != nil {
		return nil, nil, nil, err
	}
	d := sshx.NewDialer(sshx.Options{KnownHostsPath: *k.knownHosts, AcceptNew: *k.acceptNew, Interactive: term.IsTerminal(int(os.Stdin.Fd())), PassphraseFor: keys.PassphraseFor})
	return inv, hosts, d, nil
}

func (k *keyFlags) request(hosts []inventory.Host) keyops.Request {
	return keyops.Request{Hosts: hosts, Users: splitList(*k.users), FromIPs: splitList(*k.from), DryRun: *k.dryRun}
}

func ask(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt+" [y/N] ")
	ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes" || ans == "s" || ans == "sim"
}

func describe(hosts []inventory.Host, users []string) string {
	var b strings.Builder
	for _, h := range hosts {
		u := users
		if len(u) == 0 {
			u = []string{h.User}
		}
		fmt.Fprintf(&b, "  %-24s %s:%d  users: %s\n", h.Name, h.Address, h.Port, strings.Join(u, ","))
	}
	return b.String()
}

func printResults(results []keyops.Result) bool {
	ok := true
	for _, r := range results {
		mark := "ok"
		if !r.OK {
			mark = "FAILED"
			ok = false
		}
		fmt.Fprintf(os.Stderr, "%s: %s\n", r.Host, mark)
		for _, e := range r.Events {
			fmt.Fprintf(os.Stderr, "  %-8s %-9s %-8s %s\n", e.User, e.Action, e.Status, e.Message)
		}
	}
	return ok
}

func okHosts(hosts []inventory.Host, results []keyops.Result) []inventory.Host {
	good := map[string]bool{}
	for _, r := range results {
		if r.OK {
			good[r.Host] = true
		}
	}
	var out []inventory.Host
	for _, h := range hosts {
		if good[h.Name] {
			out = append(out, h)
		}
	}
	return out
}

func cmdKeys(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, keysUsage)
		return exitCode(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "list":
		return keysList()
	case "fleet":
		return keysFleet()
	case "new":
		return keysNew(args[1:])
	case "deploy":
		return keysDeploy(ctx, args[1:], false)
	case "rotate":
		return keysDeploy(ctx, args[1:], true)
	case "remove":
		return keysRemove(ctx, args[1:])
	case "app-init":
		return keysAppInit(ctx, args[1:])
	case "app-rotate":
		return keysAppRotate(ctx, args[1:])
	case "pub":
		return keysPub(args[1:])
	case "app-protect":
		k, err := keys.ProtectApp()
		if err != nil {
			return err
		}
		fmt.Printf("%s is protected by the system keyring (%s, fingerprint unchanged)\n", k.Path, k.Fingerprint)
		return nil
	}
	fmt.Fprint(os.Stderr, keysUsage)
	return exitCode(2)
}

func keysList() error {
	list, err := keys.List()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("no keys in", keys.Dir())
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tFINGERPRINT\tENCRYPTED\tCREATED\tPATH")
	for _, k := range list {
		fmt.Fprintf(w, "%s\t%s\t%v\t%s\t%s\n", k.Name, k.Fingerprint, k.Encrypted, k.Created.Format("2006-01-02"), k.Path)
	}
	return w.Flush()
}

func keysFleet() error {
	rep, id, err := history.Latest()
	if err != nil {
		return err
	}
	if rep == nil {
		return errors.New("no report in history yet: run 'farol check' first")
	}
	type use struct {
		label, typ string
		where      []string
	}
	m := map[string]*use{}
	for _, h := range rep.Hosts {
		for _, u := range h.Users {
			for _, k := range u.Keys {
				x, ok := m[k.Fingerprint]
				if !ok {
					x = &use{label: k.Label, typ: k.Type}
					if x.label == "" {
						x.label = k.Comment
					}
					m[k.Fingerprint] = x
				}
				x.where = append(x.where, h.Name+":"+u.Name)
			}
		}
	}
	fps := make([]string, 0, len(m))
	for fp := range m {
		fps = append(fps, fp)
	}
	sort.Slice(fps, func(i, j int) bool { return len(m[fps[i]].where) > len(m[fps[j]].where) })
	fmt.Printf("report %s\n\n", id)
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "FINGERPRINT\tLABEL/COMMENT\tCOUNT\tWHERE")
	for _, fp := range fps {
		x := m[fp]
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", fp, x.label, len(x.where), strings.Join(x.where, " "))
	}
	return w.Flush()
}

func readPassphrase() ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("--passphrase needs an interactive terminal")
	}
	fmt.Fprint(os.Stderr, "New passphrase: ")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	fmt.Fprint(os.Stderr, "Repeat passphrase: ")
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if string(p1) != string(p2) {
		return nil, errors.New("passphrases do not match")
	}
	return p1, nil
}

func keysNew(args []string) error {
	fs := flag.NewFlagSet("keys new", flag.ExitOnError)
	pass := fs.Bool("passphrase", false, "protect the private key with a passphrase")
	comment := fs.String("comment", "", "key comment")
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	fs.Parse(args)
	if name == "" && fs.NArg() > 0 {
		name = fs.Arg(0)
	}
	if name == "" {
		return errors.New("usage: farol keys new <name> [--passphrase] [--comment text]")
	}
	var pp []byte
	if *pass {
		var err error
		if pp, err = readPassphrase(); err != nil {
			return err
		}
	}
	k, err := keys.Generate(name, *comment, pp)
	if err != nil {
		return err
	}
	fmt.Printf("created %s\n  %s\n  %s\n", k.Path, k.Fingerprint, k.PublicLine)
	return nil
}

func keysDeploy(ctx context.Context, args []string, rotate bool) error {
	kf := newKeyFlags("keys deploy")
	removeCur := kf.fs.Bool("remove-current", false, "rotate: remove the key each host currently logs in with")
	removeFP := kf.fs.String("remove", "", "rotate: fingerprint of the old key to remove")
	setIdentity := kf.fs.Bool("set-identity", false, "point the inventory at the new key for these hosts")
	pos := kf.parse(args)
	if len(pos) != 1 {
		return errors.New("usage: farol keys deploy|rotate <key-name> -g group|-H host [flags]")
	}
	key, err := keys.Get(pos[0])
	if err != nil {
		return fmt.Errorf("key %q: %w (create it with 'farol keys new')", pos[0], err)
	}
	if rotate && !*removeCur && *removeFP == "" {
		return errors.New("rotate needs --remove-current or --remove <fingerprint>")
	}
	inv, hosts, d, err := kf.setup()
	if err != nil {
		return err
	}
	req := kf.request(hosts)
	req.NewKey = key

	fmt.Fprintf(os.Stderr, "key %s (%s)\n%s", key.Name, key.Fingerprint, describe(hosts, req.Users))
	if !*kf.dryRun && !*kf.yes && !ask(fmt.Sprintf("Add this key to authorized_keys on %d hosts?", len(hosts))) {
		return errors.New("aborted")
	}
	if !*kf.dryRun {
		if req.NewSigner, err = d.LoadKey(key.Path); err != nil {
			return err
		}
	}
	results, err := keyops.Deploy(ctx, d, req)
	if err != nil {
		return err
	}
	allOK := printResults(results)
	good := okHosts(hosts, results)

	if rotate && len(good) > 0 {
		req.Hosts = good
		req.RemoveCur = *removeCur
		req.RemoveFP = *removeFP
		what := *removeFP
		if *removeCur {
			what = "the key each host currently logs in with"
		}
		if *kf.dryRun || *kf.yes || ask(fmt.Sprintf("New key verified on %d hosts. Remove %s from them now?", len(good), what)) {
			results, err := keyops.Remove(ctx, d, req)
			if err != nil {
				return err
			}
			if !printResults(results) {
				allOK = false
			}
			good = okHosts(good, results)
			*setIdentity = true
		}
	}

	if !*kf.dryRun && len(good) > 0 {
		inv.AddKnownKey(key.Name, key.Fingerprint)
		if *setIdentity {
			inv.SetIdentity(good, key.Path)
			fmt.Fprintf(os.Stderr, "inventory now uses %s for %d hosts\n", key.Path, len(good))
		}
		if err := inv.Save(); err != nil {
			return err
		}
		if key.Encrypted {
			fmt.Fprintf(os.Stderr, "tip: load it in your agent with: ssh-add %s\n", key.Path)
		}
	}
	if !allOK {
		return exitCode(1)
	}
	return nil
}

func keysRemove(ctx context.Context, args []string) error {
	kf := newKeyFlags("keys remove")
	pos := kf.parse(args)
	if len(pos) != 1 || !strings.HasPrefix(pos[0], "SHA256:") {
		return errors.New("usage: farol keys remove SHA256:<fingerprint> -g group|-H host [flags]")
	}
	_, hosts, d, err := kf.setup()
	if err != nil {
		return err
	}
	req := kf.request(hosts)
	req.RemoveFP = pos[0]
	fmt.Fprintf(os.Stderr, "remove %s from:\n%s", pos[0], describe(hosts, req.Users))
	if !*kf.dryRun && !*kf.yes && !ask(fmt.Sprintf("Remove this key on %d hosts?", len(hosts))) {
		return errors.New("aborted")
	}
	results, err := keyops.Remove(ctx, d, req)
	if err != nil {
		return err
	}
	if !printResults(results) {
		return exitCode(1)
	}
	return nil
}

func keysAppInit(ctx context.Context, args []string) error {
	kf := newKeyFlags("keys app-init")
	setDefault := kf.fs.Bool("set-default", false, "make the app key the inventory default identity")
	createOnly := kf.fs.Bool("create-only", false, "only create the app key locally, without connecting to any host")
	kf.parse(args)
	if *createOnly {
		key, err := keys.Get(keys.AppKeyName)
		if err != nil {
			var protected bool
			if key, protected, err = keys.GenerateApp(keys.AppKeyName); err != nil {
				return err
			}
			if !protected {
				fmt.Fprintln(os.Stderr, "WARNING: no system keyring available: the app key was created WITHOUT a passphrase")
			}
			fmt.Fprintf(os.Stderr, "created %s (%s)\n", key.Path, key.Fingerprint)
		} else {
			fmt.Fprintf(os.Stderr, "app key already exists: %s (%s)\n", key.Path, key.Fingerprint)
		}
		fmt.Println(keys.AuthorizedLine(key, splitList(*kf.from)))
		return nil
	}
	key, err := keys.Get(keys.AppKeyName)
	if err != nil {
		if *kf.dryRun {
			fmt.Fprintf(os.Stderr, "[DRY-RUN] would create key %s in %s\n", keys.AppKeyName, keys.Dir())
			key = keys.Placeholder(keys.AppKeyName)
		} else {
			var protected bool
			if key, protected, err = keys.GenerateApp(keys.AppKeyName); err != nil {
				return err
			}
			if !protected {
				fmt.Fprintln(os.Stderr, "WARNING: no system keyring available: the app key was created WITHOUT a passphrase")
			}
			fmt.Fprintf(os.Stderr, "created %s (%s)\n", key.Path, key.Fingerprint)
		}
	}
	inv, hosts, d, err := kf.setup()
	if err != nil {
		return err
	}
	req := kf.request(hosts)
	req.NewKey = key
	fmt.Fprintf(os.Stderr, "app key %s (%s)\n%s", key.Name, key.Fingerprint, describe(hosts, req.Users))
	if !*kf.dryRun && !*kf.yes && !ask(fmt.Sprintf("Install the farol-guard app key on %d hosts?", len(hosts))) {
		return errors.New("aborted")
	}
	if !*kf.dryRun {
		if req.NewSigner, err = d.LoadKey(key.Path); err != nil {
			return err
		}
	}
	results, err := keyops.Deploy(ctx, d, req)
	if err != nil {
		return err
	}
	ok := printResults(results)
	if !*kf.dryRun {
		inv.AddKnownKey(keys.AppKeyName, key.Fingerprint)
		if *setDefault {
			inv.Defaults.Identity = key.Path
		}
		if err := inv.Save(); err != nil {
			return err
		}
	}
	if !ok {
		return exitCode(1)
	}
	return nil
}

func keysAppRotate(ctx context.Context, args []string) error {
	kf := newKeyFlags("keys app-rotate")
	kf.parse(args)
	inv, err := inventory.Load(*kf.cfg)
	if err != nil {
		return err
	}
	app, err := keys.Get(keys.AppKeyName)
	if err != nil {
		return errors.New("there is no app key yet: run 'farol keys app-init' first")
	}
	rep, _, err := history.Latest()
	if err != nil || rep == nil {
		return errors.New("no report in history: run 'farol check' first")
	}
	present := map[string]bool{}
	for _, h := range rep.Hosts {
		for _, u := range h.Users {
			for _, k := range u.Keys {
				if k.Fingerprint == app.Fingerprint && u.Name == h.User {
					present[h.Name] = true
				}
			}
		}
	}
	hosts := keyops.AppKeyHosts(inv, present)
	if len(hosts) == 0 {
		return errors.New("the current app key was not found on any host in the latest report")
	}
	fmt.Fprintf(os.Stderr, "replace app key %s on:\n%s", app.Fingerprint, describe(hosts, nil))
	if !*kf.dryRun && !*kf.yes && !ask(fmt.Sprintf("Generate a new app key, install it on %d hosts and remove the current one?", len(hosts))) {
		return errors.New("aborted")
	}
	d := sshx.NewDialer(sshx.Options{KnownHostsPath: *kf.knownHosts, AcceptNew: *kf.acceptNew, Interactive: term.IsTerminal(int(os.Stdin.Fd())), PassphraseFor: keys.PassphraseFor})
	res, err := keyops.RotateApp(ctx, d, hosts, splitList(*kf.from), *kf.dryRun)
	if err != nil {
		return err
	}
	printResults(res.Deploy)
	printResults(res.Remove)
	if !res.Completed {
		fmt.Fprintln(os.Stderr, "some hosts failed: the current app key was kept; run app-rotate again to resume")
		return exitCode(1)
	}
	if *kf.dryRun {
		return nil
	}
	inv.SetKnownKey(keys.AppKeyName, res.NewFingerprint)
	inv.AddKnownKey(keys.AppKeyName+"-retired", res.OldFingerprint)
	if err := inv.Save(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "app key replaced (%s); old key kept as %s\n", res.NewFingerprint, res.Retired)
	return nil
}

func keysPub(args []string) error {
	fs := flag.NewFlagSet("keys pub", flag.ExitOnError)
	from := fs.String("from", "", "restrict the key to these source IPs/CIDRs")
	var name string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	fs.Parse(args)
	if name == "" {
		return errors.New("usage: farol keys pub <name> [--from IP[,CIDR]]")
	}
	k, err := keys.Get(name)
	if err != nil {
		return err
	}
	fmt.Println(keys.AuthorizedLine(k, splitList(*from)))
	return nil
}
