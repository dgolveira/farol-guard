package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/server"
)

const (
	uiUnit     = "farol-guard-ui.service"
	idleExit   = "20s"
	appWMClass = "farol-guard"
)

var chromiumNames = []string{"edge", "chrome", "chromium", "brave", "vivaldi", "opera"}

func stateDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "farol-guard")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "farol-guard")
}

func tokenPath() string { return filepath.Join(inventory.ConfigDir(), "ui-token") }

func uiToken() (string, error) {
	if t := os.Getenv("FAROL_GUARD_TOKEN"); t != "" {
		return t, nil
	}
	if data, err := os.ReadFile(tokenPath()); err == nil {
		if t := strings.TrimSpace(string(data)); len(t) >= 32 {
			return t, nil
		}
	}
	t := server.NewToken()
	if err := os.MkdirAll(filepath.Dir(tokenPath()), 0o700); err != nil {
		return "", err
	}
	return t, os.WriteFile(tokenPath(), []byte(t+"\n"), 0o600)
}

func dashboardState(listen string) (up bool, err error) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + listen + "/api/meta")
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if strings.Contains(string(body), "farol-guard") {
		return true, nil
	}
	return false, fmt.Errorf("%s is used by another program", listen)
}

func unitInstalled() bool {
	out, err := exec.Command("systemctl", "--user", "list-unit-files", uiUnit, "--no-legend").Output()
	return err == nil && strings.Contains(string(out), uiUnit)
}

func notify(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	if !isTerminal() {
		_ = exec.Command("notify-send", "-a", "farol-guard", "-i", "farol-guard", "farol-guard", msg).Run()
	}
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func cmdOpen(args []string) error {
	fs := flag.NewFlagSet("open", flag.ExitOnError)
	cfg := fs.String("c", inventory.DefaultPath(), "inventory path")
	listen := fs.String("listen", defaultListen, "dashboard address")
	noApp := fs.Bool("no-app", false, "open a normal browser tab instead of an app window")
	fs.Parse(args)

	token, err := uiToken()
	if err != nil {
		notify("cannot create the dashboard token: " + err.Error())
		return err
	}
	up, err := dashboardState(*listen)
	if err != nil {
		notify(err.Error())
		return err
	}
	if !up {
		if err := startDashboard(*cfg, *listen); err != nil {
			notify("cannot start the dashboard: " + err.Error())
			return err
		}
		deadline := time.Now().Add(20 * time.Second)
		for !up && time.Now().Before(deadline) {
			time.Sleep(300 * time.Millisecond)
			up, _ = dashboardState(*listen)
		}
		if !up {
			msg := "the dashboard did not start; see " + filepath.Join(stateDir(), "ui.log")
			notify(msg)
			return errors.New(msg)
		}
	}
	url := fmt.Sprintf("http://%s/?token=%s", *listen, token)
	fmt.Println(url)
	if !*noApp {
		if browser := defaultChromium(); browser != "" {
			return runAppWindow(browser, url, *listen)
		}
	}
	if err := exec.Command("xdg-open", url).Start(); err != nil {
		notify("open this address in the browser: " + url)
	}
	return nil
}

const defaultListen = "127.0.0.1:7380"

func pidPath(listen string) string {
	name := "ui.pid"
	if listen != defaultListen {
		name = "ui-" + strings.NewReplacer(":", "-", ".", "-", "[", "", "]", "").Replace(listen) + ".pid"
	}
	return filepath.Join(stateDir(), name)
}

func appProfileDir() string { return filepath.Join(stateDir(), "browser") }

func runAppWindow(browser, url, listen string) error {
	already := appWindowRunning()
	cmd := exec.Command(browser,
		"--app="+url,
		"--user-data-dir="+appProfileDir(),
		"--class="+appWMClass,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-mode",
		"--window-size=1440,900",
	)
	if err := cmd.Start(); err != nil {
		notify("cannot open the app window: " + err.Error())
		return exec.Command("xdg-open", url).Start()
	}
	if already {
		return nil
	}
	_ = cmd.Wait()
	stopDashboard(listen)
	return nil
}

func appWindowRunning() bool {
	target, err := os.Readlink(filepath.Join(appProfileDir(), "SingletonLock"))
	if err != nil {
		return false
	}
	i := strings.LastIndex(target, "-")
	if i < 0 {
		return false
	}
	pid, err := strconv.Atoi(target[i+1:])
	if err != nil {
		return false
	}
	_, err = os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

func defaultChromium() string {
	if b := os.Getenv("FAROL_GUARD_BROWSER"); b != "" {
		if p, err := exec.LookPath(b); err == nil {
			return p
		}
	}
	out, err := exec.Command("xdg-settings", "get", "default-web-browser").Output()
	if err != nil {
		return ""
	}
	desktop := strings.TrimSpace(string(out))
	if desktop == "" {
		return ""
	}
	execLine := desktopExec(desktop)
	fields := strings.Fields(execLine)
	if len(fields) == 0 {
		return ""
	}
	bin := fields[0]
	if filepath.Base(bin) == "env" || filepath.Base(bin) == "flatpak" {
		return ""
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return ""
	}
	resolved, _ := filepath.EvalSymlinks(path)
	name := strings.ToLower(filepath.Base(path) + " " + filepath.Base(resolved) + " " + desktop)
	for _, c := range chromiumNames {
		if strings.Contains(name, c) {
			return path
		}
	}
	return ""
}

func desktopExec(desktop string) string {
	home, _ := os.UserHomeDir()
	dirs := []string{filepath.Join(home, ".local", "share")}
	if x := os.Getenv("XDG_DATA_DIRS"); x != "" {
		dirs = append(dirs, strings.Split(x, ":")...)
	} else {
		dirs = append(dirs, "/usr/local/share", "/usr/share")
	}
	for _, d := range dirs {
		data, err := os.ReadFile(filepath.Join(d, "applications", desktop))
		if err != nil {
			continue
		}
		inEntry := false
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") {
				inEntry = line == "[Desktop Entry]"
				continue
			}
			if inEntry && strings.HasPrefix(line, "Exec=") {
				return strings.TrimPrefix(line, "Exec=")
			}
		}
	}
	return ""
}

func startDashboard(cfg, listen string) error {
	if listen == defaultListen && unitInstalled() {
		if err := exec.Command("systemctl", "--user", "start", uiUnit).Run(); err == nil {
			return nil
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(stateDir(), "ui.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(exe, "ui", "--no-open", "--listen", listen, "-c", cfg, "--idle-exit", idleExit)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = os.WriteFile(pidPath(listen), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
	return cmd.Process.Release()
}

func cmdStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	listen := fs.String("listen", defaultListen, "dashboard address")
	fs.Parse(args)
	if stopDashboard(*listen) {
		notify("dashboard stopped")
	} else {
		notify("the dashboard was not running")
	}
	return nil
}

func stopDashboard(listen string) bool {
	stopped := false
	if listen == defaultListen && unitInstalled() {
		if out, _ := exec.Command("systemctl", "--user", "is-active", uiUnit).Output(); strings.TrimSpace(string(out)) == "active" {
			if err := exec.Command("systemctl", "--user", "stop", uiUnit).Run(); err == nil {
				stopped = true
			}
		}
	}
	pidFile := pidPath(listen)
	if data, err := os.ReadFile(pidFile); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 1 {
			if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil && strings.Contains(filepath.Base(exe), "farol") {
				if syscall.Kill(pid, syscall.SIGTERM) == nil {
					stopped = true
				}
			}
		}
		os.Remove(pidFile)
	}
	return stopped
}
