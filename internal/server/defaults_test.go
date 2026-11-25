package server

import (
	"testing"

	"github.com/dgolveira/farol-guard/internal/inventory"
)

func TestDefaultsImpactOnlyInheritingHosts(t *testing.T) {
	inv := &inventory.Inventory{
		Defaults: inventory.Settings{User: "root", Port: 22, Identity: "/k/old"},
		Groups: map[string]inventory.Group{
			"a": {Hosts: []inventory.Host{{Name: "inherits"}, {Name: "own", Identity: "/k/own"}}},
			"b": {Settings: inventory.Settings{Identity: "/k/group"}, Hosts: []inventory.Host{{Name: "group-key"}}},
		},
	}
	got := defaultsImpactOf(inv, inventory.Settings{User: "root", Port: 22, Identity: "/k/new"})
	if len(got) != 1 || got[0].Name != "inherits" || got[0].Identity != "/k/new" {
		t.Fatalf("unexpected impact: %+v", got)
	}
	if inv.Defaults.Identity != "/k/old" {
		t.Fatal("defaults changed by the preview")
	}
}
