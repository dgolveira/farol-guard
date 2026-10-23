package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/dgolveira/farol-guard/internal/history"
	"github.com/dgolveira/farol-guard/internal/i18n"
	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/keyops"
	"github.com/dgolveira/farol-guard/internal/keys"
	"golang.org/x/crypto/ssh"
)

type keyUse struct {
	Host string `json:"host"`
	User string `json:"user"`
}

type fleetKey struct {
	Fingerprint string   `json:"fingerprint"`
	Farol       string   `json:"farol,omitempty"`
	FarolHost   string   `json:"farol_host,omitempty"`
	Label       string   `json:"label"`
	Type        string   `json:"type"`
	Comment     string   `json:"comment"`
	Where       []keyUse `json:"where"`
}

type keyOpRequest struct {
	Key           string   `json:"key"`
	Passphrase    string   `json:"passphrase"`
	Groups        []string `json:"groups"`
	Hosts         []string `json:"hosts"`
	Users         []string `json:"users"`
	From          []string `json:"from"`
	Fingerprint   string   `json:"fingerprint"`
	RemoveCurrent bool     `json:"remove_current"`
	DryRun        bool     `json:"dry_run"`
	SetIdentity   bool     `json:"set_identity"`
	SetDefault    bool     `json:"set_default"`
}

func (s *Server) registerKeyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/keys", s.handleKeys)
	mux.HandleFunc("POST /api/keys", s.handleNewKey)
	mux.HandleFunc("POST /api/keys/deploy", s.handleKeyDeploy)
	mux.HandleFunc("DELETE /api/keys/{name}", s.handleKeyDelete)
	mux.HandleFunc("POST /api/keys/{name}/check-passphrase", s.handleCheckPassphrase)
	mux.HandleFunc("POST /api/keys/remove", s.handleKeyRemove)
	mux.HandleFunc("POST /api/keys/app-init", s.handleAppInit)
	mux.HandleFunc("GET /api/keys/app-hosts", s.handleAppHosts)
	mux.HandleFunc("POST /api/keys/app-protect", s.handleAppProtect)
	mux.HandleFunc("POST /api/keys/app-rotate", s.handleAppRotate)
}

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	local, err := keys.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if local == nil {
		local = []keys.Key{}
	}
	agentFP := s.cfg.Dialer.AgentFingerprints()
	for _, k := range keys.ListSSH() {
		k.InAgent = agentFP[k.Fingerprint]
		local = append(local, k)
	}
	fleet := []*fleetKey{}
	reportID := ""
	if rep, id, err := s.loadReport("latest", i18n.EN); err == nil && rep != nil {
		reportID = id
		m := map[string]*fleetKey{}
		for _, h := range rep.Hosts {
			for _, u := range h.Users {
				for _, k := range u.Keys {
					fk, ok := m[k.Fingerprint]
					if !ok {
						fk = &fleetKey{Fingerprint: k.Fingerprint, Label: k.Label, Type: k.Type, Comment: k.Comment, Farol: k.Farol, FarolHost: k.FarolHost}
						m[k.Fingerprint] = fk
						fleet = append(fleet, fk)
					}
					fk.Where = append(fk.Where, keyUse{Host: h.Name, User: u.Name})
				}
			}
		}
		sort.SliceStable(fleet, func(i, j int) bool { return len(fleet[i].Where) > len(fleet[j].Where) })
	}
	var app *keys.Key
	for i := range local {
		if local[i].Name == keys.AppKeyName {
			app = &local[i]
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"local": local, "fleet": fleet, "app": app, "report_id": reportID, "dir": keys.Dir(),
		"instance": keys.InstanceID(), "secret_store": keys.SecretStoreStatus()})
}

func (s *Server) handleNewKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		Passphrase string `json:"passphrase"`
		Comment    string `json:"comment"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	k, err := keys.Generate(req.Name, req.Comment, []byte(req.Passphrase))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, k)
}

func decodeKeyOp(w http.ResponseWriter, r *http.Request) (*keyOpRequest, bool) {
	var req keyOpRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return nil, false
	}
	if len(req.Groups) == 0 && len(req.Hosts) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("select at least one group or host"))
		return nil, false
	}
	return &req, true
}

func (s *Server) prepareKeyOp(req *keyOpRequest, needKey bool) (*inventory.Inventory, keyops.Request, error) {
	inv, err := s.loadInventory()
	if err != nil {
		return nil, keyops.Request{}, err
	}
	hosts, err := inv.Select(req.Groups, req.Hosts)
	if err != nil {
		return nil, keyops.Request{}, err
	}
	op := keyops.Request{Hosts: hosts, Users: req.Users, FromIPs: req.From, DryRun: req.DryRun,
		RemoveFP: req.Fingerprint, RemoveCur: req.RemoveCurrent}
	if req.Key != "" {
		k, err := keys.Get(req.Key)
		if err != nil {
			return nil, op, fmt.Errorf("key %q: %w", req.Key, err)
		}
		op.NewKey = k
		if !req.DryRun {
			load := func() (ssh.Signer, error) {
				if req.Passphrase == "" {
					return s.cfg.Dialer.LoadKey(k.Path)
				}
				return s.cfg.Dialer.LoadKeyWithPassphrase(k.Path, []byte(req.Passphrase))
			}
			signer, err := load()
			if err != nil {
				return nil, op, fmt.Errorf("unlock %s: %w", k.Name, err)
			}
			op.NewSigner = signer
		}
	} else if needKey {
		return nil, op, errors.New("choose a key")
	}
	return inv, op, nil
}

func goodHosts(hosts []inventory.Host, results []keyops.Result) []inventory.Host {
	ok := map[string]bool{}
	for _, r := range results {
		if r.OK {
			ok[r.Host] = true
		}
	}
	var out []inventory.Host
	for _, h := range hosts {
		if ok[h.Name] {
			out = append(out, h)
		}
	}
	return out
}

func (s *Server) handleKeyDeploy(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeKeyOp(w, r)
	if !ok {
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	inv, op, err := s.prepareKeyOp(req, true)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	results, err := keyops.Deploy(r.Context(), s.cfg.Dialer, op)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !req.DryRun {
		good := goodHosts(op.Hosts, results)
		if len(good) > 0 {
			inv.AddKnownKey(op.NewKey.Name, op.NewKey.Fingerprint)
			if req.SetIdentity {
				inv.SetIdentity(good, op.NewKey.Path)
			}
			if err := inv.Save(); err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) handleKeyRemove(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeKeyOp(w, r)
	if !ok {
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	inv, op, err := s.prepareKeyOp(req, false)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	results, err := keyops.Remove(r.Context(), s.cfg.Dialer, op)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !req.DryRun && op.NewKey != nil {
		if good := goodHosts(op.Hosts, results); len(good) > 0 {
			inv.AddKnownKey(op.NewKey.Name, op.NewKey.Fingerprint)
			inv.SetIdentity(good, op.NewKey.Path)
			if err := inv.Save(); err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) handleAppInit(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeKeyOp(w, r)
	if !ok {
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	willCreate := false
	if _, err := keys.Get(keys.AppKeyName); err != nil {
		willCreate = true
		if !req.DryRun {
			if _, _, err := keys.GenerateApp(keys.AppKeyName); err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
		}
	}
	var inv *inventory.Inventory
	var op keyops.Request
	var err error
	if willCreate && req.DryRun {
		inv, op, err = s.prepareKeyOp(&keyOpRequest{Groups: req.Groups, Hosts: req.Hosts, Users: req.Users, From: req.From, DryRun: true}, false)
		op.NewKey = keys.Placeholder(keys.AppKeyName)
	} else {
		req.Key = keys.AppKeyName
		req.Passphrase = ""
		inv, op, err = s.prepareKeyOp(req, true)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	results, err := keyops.Deploy(r.Context(), s.cfg.Dialer, op)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !req.DryRun {
		inv.AddKnownKey(keys.AppKeyName, op.NewKey.Fingerprint)
		if req.SetDefault {
			inv.Defaults.Identity = op.NewKey.Path
		}
		if err := inv.Save(); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "will_create": willCreate})
}

func (s *Server) appKeyHosts() (*inventory.Inventory, []inventory.Host, error) {
	inv, err := s.loadInventory()
	if err != nil {
		return nil, nil, err
	}
	app, err := keys.Get(keys.AppKeyName)
	if err != nil {
		return inv, nil, nil
	}
	present := map[string]bool{}
	if rep, _, err := history.Latest(); err == nil && rep != nil {
		for _, h := range rep.Hosts {
			for _, u := range h.Users {
				for _, k := range u.Keys {
					if k.Fingerprint == app.Fingerprint && u.Name == h.User {
						present[h.Name] = true
					}
				}
			}
		}
	}
	return inv, keyops.AppKeyHosts(inv, present), nil
}

func (s *Server) handleAppHosts(w http.ResponseWriter, r *http.Request) {
	_, hosts, err := s.appKeyHosts()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	names := []string{}
	for _, h := range hosts {
		names = append(names, h.Name)
	}
	writeJSON(w, http.StatusOK, names)
}

func (s *Server) handleAppRotate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		From   []string `json:"from"`
		DryRun bool     `json:"dry_run"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	inv, hosts, err := s.appKeyHosts()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	res, err := keyops.RotateApp(r.Context(), s.cfg.Dialer, hosts, req.From, req.DryRun)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if res.Completed && !req.DryRun {
		inv.SetKnownKey(keys.AppKeyName, res.NewFingerprint)
		inv.AddKnownKey(keys.AppKeyName+"-retired", res.OldFingerprint)
		if err := inv.Save(); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleCheckPassphrase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	k, err := keys.Get(r.PathValue("name"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	if err := keys.CheckPassphrase(k.Path, []byte(req.Passphrase)); err != nil {
		writeErr(w, http.StatusUnauthorized, errors.New("wrong passphrase"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAppProtect(w http.ResponseWriter, r *http.Request) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	k, err := keys.ProtectApp()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.cfg.Dialer.ForgetKey(k.Path)
	writeJSON(w, http.StatusOK, k)
}

func (s *Server) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	k, err := keys.Get(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	if rep, _, err := s.loadReport("latest", i18n.EN); err == nil && rep != nil && r.URL.Query().Get("force") != "1" {
		for _, h := range rep.Hosts {
			for _, u := range h.Users {
				for _, ak := range u.Keys {
					if ak.Fingerprint == k.Fingerprint {
						writeErr(w, http.StatusConflict, fmt.Errorf("key is still installed on %s:%s; remove it from the hosts first", h.Name, u.Name))
						return
					}
				}
			}
		}
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := keys.Delete(name); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.cfg.Dialer.ForgetKey(k.Path)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
