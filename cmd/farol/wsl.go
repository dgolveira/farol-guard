package main

import (
	"os"
	"os/exec"
	"strings"
)

func isWSL() bool {
	if os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("WSL_INTEROP") != "" {
		return true
	}
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	return err == nil && strings.Contains(strings.ToLower(string(data)), "microsoft")
}

func winToLinux(path string) string {
	if out, err := exec.Command("wslpath", "-u", path).Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	if len(path) > 2 && path[1] == ':' {
		return "/mnt/" + strings.ToLower(path[:1]) + strings.ReplaceAll(path[2:], `\`, "/")
	}
	return path
}

func winTool(name, fallback string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if p := winToLinux(fallback); fileExists(p) {
		return p
	}
	return ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func winEnv(name string) string {
	cmdExe := winTool("cmd.exe", `C:\Windows\System32\cmd.exe`)
	if cmdExe == "" {
		return ""
	}
	cmd := exec.Command(cmdExe, "/d", "/c", "echo %"+name+"%")
	cmd.Dir = winToLinux(`C:\`)
	out, err := cmd.Output()
	v := strings.TrimSpace(string(out))
	if err != nil || v == "" || v == "%"+name+"%" {
		return ""
	}
	return v
}

func windowsEdge() string {
	if b := os.Getenv("FAROL_GUARD_BROWSER"); b != "" {
		if p, err := exec.LookPath(b); err == nil {
			return p
		}
	}
	for _, p := range []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	} {
		if lp := winToLinux(p); fileExists(lp) {
			return lp
		}
	}
	return ""
}

func startDetached(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func openWSL(url string, noApp bool) error {
	if !noApp {
		if edge := windowsEdge(); edge != "" {
			args := []string{
				"--app=" + url,
				"--no-first-run",
				"--no-default-browser-check",
				"--window-size=1440,900",
			}
			if local := winEnv("LOCALAPPDATA"); local != "" {
				args = append(args, `--user-data-dir=`+local+`\farol-guard\browser`)
			}
			if err := startDetached(edge, args...); err == nil {
				return nil
			}
		}
	}
	if p, err := exec.LookPath("wslview"); err == nil && startDetached(p, url) == nil {
		return nil
	}
	if explorer := winTool("explorer.exe", `C:\Windows\explorer.exe`); explorer != "" && startDetached(explorer, url) == nil {
		return nil
	}
	notify("open this address in the Windows browser: " + url)
	return nil
}
