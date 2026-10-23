package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgolveira/farol-guard/internal/check"
	"github.com/dgolveira/farol-guard/internal/history"
	"github.com/dgolveira/farol-guard/internal/i18n"
	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/keys"
	"github.com/dgolveira/farol-guard/internal/model"
	"github.com/dgolveira/farol-guard/internal/report"
	"github.com/dgolveira/farol-guard/internal/sshx"
)

//go:embed web
var webFS embed.FS

const cookieName = "farol_session"

type Config struct {
	Listen        string
	InventoryPath string
	Version       string
	Token         string
	Dialer        *sshx.Dialer
	AllowedHosts  []string
	IdleExit      time.Duration
}

type Server struct {
	cfg        Config
	mu         sync.Mutex
	opMu       sync.Mutex
	job        *Job
	http       *http.Server
	pagesMu    sync.Mutex
	pages      map[string]time.Time
	emptySince time.Time
}

const (
	pageStale    = 150 * time.Second
	startupGrace = 60 * time.Second
)

type JobHost struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	OS       string `json:"os,omitempty"`
	Duration string `json:"duration"`
	Pending  bool   `json:"pending,omitempty"`
}

type Job struct {
	Running  bool      `json:"running"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
	Total    int       `json:"total"`
	Hosts    []JobHost `json:"hosts"`
	CVEDone  int       `json:"cve_done"`
	CVETotal int       `json:"cve_total"`
	Error    string    `json:"error,omitempty"`
	ReportID string    `json:"report_id,omitempty"`
	Log      []LogLine `json:"-"`
	LogBase  int       `json:"-"`
}

type LogLine struct {
	N    int    `json:"n"`
	Time string `json:"t"`
	Msg  string `json:"m"`
}

const maxLogLines = 2000

func (j *Job) logf(format string, a ...any) {
	n := j.LogBase + len(j.Log)
	j.Log = append(j.Log, LogLine{N: n, Time: time.Now().Format("15:04:05"), Msg: fmt.Sprintf(format, a...)})
	if len(j.Log) > maxLogLines {
		drop := len(j.Log) - maxLogLines
		j.Log = j.Log[drop:]
		j.LogBase += drop
	}
}

func NewToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func New(cfg Config) *Server {
	return &Server{cfg: cfg}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /assets/report.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		fmt.Fprint(w, report.Style)
	})
	mux.HandleFunc("GET /api/meta", s.handleMeta)
	mux.HandleFunc("GET /api/ping", s.handlePing)
	mux.HandleFunc("POST /api/bye", s.handleBye)
	mux.HandleFunc("GET /api/i18n", s.handleI18n)
	mux.HandleFunc("GET /api/inventory", s.handleInventory)
	mux.HandleFunc("GET /api/identities", s.handleIdentities)
	mux.HandleFunc("PUT /api/inventory/hosts", s.handleUpsertHost)
	mux.HandleFunc("DELETE /api/inventory/hosts/{name}", s.handleDeleteHost)
	mux.HandleFunc("POST /api/hosts/{name}/test", s.handleTestHost)
	mux.HandleFunc("POST /api/hosts/{name}/scan", s.handleScanHost)
	mux.HandleFunc("POST /api/hosts/{name}/trust", s.handleTrustHost)
	mux.HandleFunc("GET /api/hostkeys/pending", s.handlePendingHostKeys)
	mux.HandleFunc("GET /api/hosts/status", s.handleHostStatus)
	mux.HandleFunc("POST /api/check", s.handleStartCheck)
	mux.HandleFunc("GET /api/job", s.handleJob)
	mux.HandleFunc("GET /api/reports", s.handleReports)
	mux.HandleFunc("GET /api/reports/{id}", s.handleReportDownload)
	mux.HandleFunc("DELETE /api/reports/{id}", s.handleReportDelete)
	mux.HandleFunc("DELETE /api/reports", s.handleReportsClear)
	s.registerKeyRoutes(mux)
	mux.HandleFunc("GET /ui/fleet", s.handleFleetFragment)
	mux.HandleFunc("GET /ui/host/{name}", s.handleHostFragment)
	return s.guard(mux)
}

func (s *Server) Listen() (net.Listener, error) {
	return net.Listen("tcp", s.cfg.Listen)
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.http = &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if s.cfg.IdleExit > 0 {
		s.pagesMu.Lock()
		s.pages = map[string]time.Time{}
		s.emptySince = time.Now().Add(startupGrace)
		s.pagesMu.Unlock()
		go s.watchIdle(ctx, cancel)
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.http.Shutdown(sctx)
	}()
	err := s.http.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) watchIdle(ctx context.Context, stop context.CancelFunc) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		s.pagesMu.Lock()
		for id, seen := range s.pages {
			if now.Sub(seen) > pageStale {
				delete(s.pages, id)
				if len(s.pages) == 0 {
					s.emptySince = now
				}
			}
		}
		idle := len(s.pages) == 0 && now.Sub(s.emptySince) >= s.cfg.IdleExit
		s.pagesMu.Unlock()
		if idle && !s.busy() {
			log.Printf("no dashboard page open for %s, exiting", s.cfg.IdleExit)
			stop()
			return
		}
	}
}

func (s *Server) busy() bool {
	s.mu.Lock()
	running := s.job != nil && s.job.Running
	s.mu.Unlock()
	if running {
		return true
	}
	if !s.opMu.TryLock() {
		return true
	}
	s.opMu.Unlock()
	return false
}

func pageID(r *http.Request) string {
	id := r.URL.Query().Get("page")
	if len(id) < 8 || len(id) > 64 {
		return ""
	}
	return id
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if id := pageID(r); id != "" && s.cfg.IdleExit > 0 {
		s.pagesMu.Lock()
		s.pages[id] = time.Now()
		s.pagesMu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleBye(w http.ResponseWriter, r *http.Request) {
	if id := pageID(r); id != "" && s.cfg.IdleExit > 0 {
		s.pagesMu.Lock()
		if _, ok := s.pages[id]; ok {
			delete(s.pages, id)
			if len(s.pages) == 0 {
				s.emptySince = time.Now()
			}
		}
		s.pagesMu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")

		if !s.allowedHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if tok := r.URL.Query().Get("token"); tok != "" {
			if subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.Token)) != 1 {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name: cookieName, Value: s.cfg.Token, Path: "/",
				HttpOnly: true, SameSite: http.SameSiteStrictMode,
				Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.cfg.Token)) != 1 {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "farol-guard: open the URL with the session token printed by 'farol ui'.")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-Farol-Request") != "1" {
				http.Error(w, "missing request header", http.StatusForbidden)
				return
			}
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host && o != "https://"+r.Host {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowedHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if host == "localhost" {
		return true
	}
	for _, h := range s.cfg.AllowedHosts {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	lhost, _, _ := net.SplitHostPort(s.cfg.Listen)
	return host == lhost
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func lang(r *http.Request) string { return i18n.Detect(r.URL.Query().Get("lang")) }

func (s *Server) loadInventory() (*inventory.Inventory, error) {
	return inventory.Load(s.cfg.InventoryPath)
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.cfg.Version, "inventory": s.cfg.InventoryPath, "agent": s.cfg.Dialer.HasAgent(),
	})
}

func (s *Server) handleI18n(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, i18n.Dict(lang(r)))
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	inv, err := s.loadInventory()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	var hosts []map[string]any
	for _, h := range inv.Hosts() {
		raw, _ := inv.RawHost(h.Name)
		hosts = append(hosts, map[string]any{
			"name": h.Name, "address": h.Address, "port": h.Port, "user": h.User,
			"identity": inventory.ShortHome(h.Identity), "group": h.Group, "tags": h.Tags,
			"raw": map[string]any{"port": raw.Port, "user": raw.User, "identity": raw.Identity},
		})
	}
	groups := make([]string, 0, len(inv.Groups))
	for g := range inv.Groups {
		groups = append(groups, g)
	}
	groupSettings := map[string]inventory.Settings{}
	for name, g := range inv.Groups {
		groupSettings[name] = g.Settings
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path": inv.Path, "defaults": inv.Defaults, "hosts": hosts, "groups": groups, "group_settings": groupSettings,
	})
}

func (s *Server) handleIdentities(w http.ResponseWriter, r *http.Request) {
	ids := keys.Discover(s.cfg.Dialer.AgentFingerprints())
	if ids == nil {
		ids = []keys.Identity{}
	}
	writeJSON(w, http.StatusOK, ids)
}

func (s *Server) handleUpsertHost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Original string         `json:"original"`
		Host     inventory.Host `json:"host"`
		Group    string         `json:"group"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.Host.Group = req.Group
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, err := s.loadInventory()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := inv.UpsertHost(req.Original, req.Host); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := inv.Save(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, err := s.loadInventory()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !inv.DeleteHost(r.PathValue("name")) {
		writeErr(w, http.StatusNotFound, errors.New("host not found"))
		return
	}
	if err := inv.Save(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) target(name string) (sshx.Target, error) {
	inv, err := s.loadInventory()
	if err != nil {
		return sshx.Target{}, err
	}
	h, ok := inv.Find(name)
	if !ok {
		return sshx.Target{}, errors.New("host not found")
	}
	return sshx.Target{Address: h.Address, Port: h.Port, User: h.User, Identity: h.Identity}, nil
}

func (s *Server) handleTestHost(w http.ResponseWriter, r *http.Request) {
	t, err := s.target(r.PathValue("name"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	client, err := s.cfg.Dialer.Dial(t)
	if err != nil {
		var uh *sshx.UnknownHostError
		if errors.As(err, &uh) {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "unknown_host": true, "fingerprint": uh.Fingerprint, "type": uh.Type, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	out, _, err := sshx.Run(ctx, client, `printf '%s %s ' "$(id -un)" "$(id -u)"; if [ "$(id -u)" = 0 ] || sudo -n true 2>/dev/null; then echo privileged; else echo limited; fi; . /etc/os-release 2>/dev/null; echo "$PRETTY_NAME"`, nil)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	lines := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)
	f := strings.Fields(lines[0])
	res := map[string]any{"ok": true}
	if len(f) == 3 {
		res["user"], res["privileges"] = f[0], f[2]
	}
	if len(lines) == 2 {
		res["os"] = lines[1]
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleScanHost(w http.ResponseWriter, r *http.Request) {
	t, err := s.target(r.PathValue("name"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	key, err := s.cfg.Dialer.ScanHostKey(t)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"type": key.Type(), "fingerprint": sshx.Fingerprint(key)})
}

func (s *Server) handleTrustHost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || req.Fingerprint == "" {
		writeErr(w, http.StatusBadRequest, errors.New("fingerprint required"))
		return
	}
	t, err := s.target(r.PathValue("name"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	captured := ""
	if rep, _, _ := history.Latest(); rep != nil {
		for _, h := range rep.Hosts {
			if h.Name == r.PathValue("name") && h.HostKey != nil && h.HostKey.Fingerprint == req.Fingerprint {
				captured = h.HostKey.Key
			}
		}
	}
	if err := s.cfg.Dialer.TrustHostKey(t, req.Fingerprint, captured); err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleHostStatus(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	rep, _, err := s.loadReport("latest", i18n.EN)
	if err != nil || rep == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	for _, h := range rep.Hosts {
		pending := h.HostKey != nil
		if pending && h.HostKey.Key != "" && s.cfg.Dialer.IsTrusted(sshx.Target{Address: h.Address, Port: h.Port}, h.HostKey.Key) {
			pending = false
		}
		out[h.Name] = map[string]any{"reachable": h.Reachable, "worst": h.Worst().String(), "pending": pending, "address": h.Address, "port": h.Port}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePendingHostKeys(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	rep, _, err := history.Latest()
	if err != nil || rep == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	inv, err := s.loadInventory()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	for _, h := range rep.Hosts {
		if h.HostKey == nil {
			continue
		}
		cur, ok := inv.Find(h.Name)
		if !ok || cur.Address != h.Address || cur.Port != h.Port {
			continue
		}
		if h.HostKey.Key != "" && s.cfg.Dialer.IsTrusted(sshx.Target{Address: cur.Address, Port: cur.Port}, h.HostKey.Key) {
			continue
		}
		out = append(out, map[string]any{
			"name": h.Name, "address": cur.Address, "port": cur.Port,
			"type": h.HostKey.Type, "fingerprint": h.HostKey.Fingerprint,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleStartCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Groups  []string `json:"groups"`
		Hosts   []string `json:"hosts"`
		Refresh bool     `json:"refresh"`
		NoCVE   bool     `json:"no_cve"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	inv, err := s.loadInventory()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	hosts, err := inv.Select(req.Groups, req.Hosts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if len(hosts) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("no hosts selected"))
		return
	}
	s.mu.Lock()
	if s.job != nil && s.job.Running {
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, errors.New("a check is already running"))
		return
	}
	job := &Job{Running: true, Started: time.Now(), Total: len(hosts)}
	job.logf("starting check of %d hosts (apt-get update: %v, CVE lookup: %v)", len(hosts), req.Refresh, !req.NoCVE)
	s.job = job
	s.mu.Unlock()

	go s.runJob(job, inv, hosts, req.Refresh, req.NoCVE)
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

func (s *Server) runJob(job *Job, inv *inventory.Inventory, hosts []inventory.Host, refresh, noCVE bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	prev, _, _ := history.Latest()
	pending := check.PendingFrom(prev, hosts)
	rep, err := check.Run(ctx, inv, hosts, s.cfg.Dialer, check.Options{
		Pending:  pending,
		Parallel: 8, Timeout: 3 * time.Minute, RefreshApt: refresh, NoCVE: noCVE,
		Lang: i18n.EN, Version: s.cfg.Version,
		Log: func(format string, a ...any) {
			s.mu.Lock()
			job.logf(format, a...)
			s.mu.Unlock()
		},
		OnHost: func(h *model.HostReport) {
			s.mu.Lock()
			job.Hosts = append(job.Hosts, JobHost{Name: h.Name, OK: h.Reachable, Error: h.Error, OS: h.OS.Pretty, Duration: h.Duration.Round(time.Millisecond).String(), Pending: h.HostKey != nil})
			s.mu.Unlock()
		},
		OnCVE: func(done, total int) {
			s.mu.Lock()
			job.CVEDone, job.CVETotal = done, total
			s.mu.Unlock()
		},
	})
	id, serr := history.Save(rep)
	s.mu.Lock()
	defer s.mu.Unlock()
	job.Running = false
	job.Finished = time.Now()
	job.ReportID = id
	job.logf("check finished in %s, report %s", job.Finished.Sub(job.Started).Round(time.Second), id)
	switch {
	case serr != nil:
		job.Error = serr.Error()
	case err != nil:
		job.Error = err.Error()
	}
	if err != nil || serr != nil {
		log.Printf("check finished with errors: %v %v", err, serr)
	}
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.job == nil {
		writeJSON(w, http.StatusOK, map[string]any{"running": false})
		return
	}
	since, _ := strconv.Atoi(r.URL.Query().Get("since"))
	var lines []LogLine
	for _, l := range s.job.Log {
		if l.N >= since {
			lines = append(lines, l)
		}
	}
	writeJSON(w, http.StatusOK, struct {
		*Job
		Lines   []LogLine `json:"log"`
		LogNext int       `json:"log_next"`
	}{s.job, lines, s.job.LogBase + len(s.job.Log)})
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	list, err := history.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if list == nil {
		list = []history.Meta{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleReportDelete(w http.ResponseWriter, r *http.Request) {
	if err := history.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleReportsClear(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	running := s.job != nil && s.job.Running
	s.mu.Unlock()
	if running {
		writeErr(w, http.StatusConflict, errors.New("a check is running"))
		return
	}
	n, err := history.Clear(r.URL.Query().Get("keep_latest") == "1")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": n})
}

func (s *Server) loadReport(id, lng string) (*model.Report, string, error) {
	var rep *model.Report
	var err error
	if id == "" || id == "latest" {
		rep, id, err = history.Latest()
	} else {
		rep, err = history.Load(id)
	}
	if err != nil || rep == nil {
		return nil, "", err
	}
	t := inventory.DefaultThresholds
	if inv, err := s.loadInventory(); err == nil {
		t = inv.Thresholds
	}
	check.Finalize(rep, t, lng)
	return rep, id, nil
}

func (s *Server) handleReportDownload(w http.ResponseWriter, r *http.Request) {
	lng := lang(r)
	rep, id, err := s.loadReport(r.PathValue("id"), lng)
	if err != nil || rep == nil {
		writeErr(w, http.StatusNotFound, errors.New("report not found"))
		return
	}
	f := report.Format(r.URL.Query().Get("format"))
	if f == "" {
		f = report.HTML
	}
	var buf bytes.Buffer
	back := ""
	if f == report.HTML && r.URL.Query().Get("download") != "1" {
		back = "/#/"
		if r.URL.Query().Get("from") == "reports" {
			back = "/#/reports"
		}
	}
	if err := report.WriteBack(&buf, rep, f, lng, back); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	ctype := map[report.Format]string{report.HTML: "text/html", report.JSON: "application/json", report.Markdown: "text/markdown"}[f]
	w.Header().Set("Content-Type", ctype+"; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="farol-report-%s.%s"`, id, f))
	}
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) handleFleetFragment(w http.ResponseWriter, r *http.Request) {
	lng := lang(r)
	rep, id, err := s.loadReport(r.URL.Query().Get("report"), lng)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if rep == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var buf bytes.Buffer
	data := map[string]any{"Report": rep, "Summary": report.Summarize(rep), "UI": true}
	if err := report.Fragment(&buf, "summary", data, lng); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := report.Fragment(&buf, "fleet", data, lng); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Report-ID", id)
	w.Header().Set("X-Report-Generated", rep.GeneratedAt.Format(time.RFC3339))
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) handleHostFragment(w http.ResponseWriter, r *http.Request) {
	lng := lang(r)
	rep, _, err := s.loadReport(r.URL.Query().Get("report"), lng)
	if err != nil || rep == nil {
		writeErr(w, http.StatusNotFound, errors.New("no report yet"))
		return
	}
	for _, h := range rep.Hosts {
		if h.Name == r.PathValue("name") {
			var buf bytes.Buffer
			if err := report.Fragment(&buf, "host", map[string]any{"H": h, "R": rep}, lng); err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(buf.Bytes())
			return
		}
	}
	writeErr(w, http.StatusNotFound, errors.New("host not in the latest report"))
}
