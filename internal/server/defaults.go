package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/dgolveira/farol-guard/internal/inventory"
	"github.com/dgolveira/farol-guard/internal/sshx"
)

var defaultUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}\$?$`)

type defaultsRequest struct {
	Settings inventory.Settings `json:"settings"`
	Test     bool               `json:"test"`
}

type defaultsImpact struct {
	Name     string `json:"name"`
	Group    string `json:"group"`
	User     string `json:"user"`
	Port     int    `json:"port"`
	Identity string `json:"identity"`
	Tested   bool   `json:"tested"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

func (s *Server) registerDefaultsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/inventory/defaults/check", s.handleDefaultsCheck)
	mux.HandleFunc("PUT /api/inventory/defaults", s.handleDefaultsSave)
}

func decodeDefaults(w http.ResponseWriter, r *http.Request) (*defaultsRequest, bool) {
	var req defaultsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return nil, false
	}
	st := &req.Settings
	st.User = strings.TrimSpace(st.User)
	st.Identity = strings.TrimSpace(st.Identity)
	var err error
	switch {
	case !defaultUserRe.MatchString(st.User):
		err = fmt.Errorf("invalid user name %q", st.User)
	case st.Port < 1 || st.Port > 65535:
		err = fmt.Errorf("invalid port %d", st.Port)
	case st.Identity == "":
		err = errors.New("choose a key")
	}
	if err == nil {
		if _, serr := os.Stat(inventory.ExpandHome(st.Identity)); serr != nil {
			err = fmt.Errorf("key file %s: %w", st.Identity, serr)
		}
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return nil, false
	}
	return &req, true
}

func defaultsImpactOf(inv *inventory.Inventory, next inventory.Settings) []inventory.Host {
	before := map[string]inventory.Host{}
	for _, h := range inv.Hosts() {
		before[h.Name] = h
	}
	sim := *inv
	sim.Defaults = next
	var out []inventory.Host
	for _, h := range sim.Hosts() {
		b := before[h.Name]
		if b.User != h.User || b.Port != h.Port || b.Identity != h.Identity {
			out = append(out, h)
		}
	}
	return out
}

func (s *Server) handleDefaultsCheck(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeDefaults(w, r)
	if !ok {
		return
	}
	inv, err := s.loadInventory()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	hosts := defaultsImpactOf(inv, req.Settings)
	out := make([]defaultsImpact, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, h := range hosts {
		out[i] = defaultsImpact{Name: h.Name, Group: h.Group, User: h.User, Port: h.Port, Identity: inventory.ShortHome(h.Identity)}
		if !req.Test {
			continue
		}
		wg.Add(1)
		go func(i int, h inventory.Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i].Tested = true
			client, err := s.cfg.Dialer.Dial(sshx.Target{Address: h.Address, Port: h.Port, User: h.User, Identity: h.Identity})
			if err != nil {
				out[i].Error, out[i].Reason = err.Error(), sshx.Reason(err.Error())
				return
			}
			client.Close()
			out[i].OK = true
		}(i, h)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
}

func (s *Server) handleDefaultsSave(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeDefaults(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, err := s.loadInventory()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	inv.Defaults = req.Settings
	if err := inv.Save(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
