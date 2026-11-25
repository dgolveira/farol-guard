package server

import (
	"testing"

	"github.com/dgolveira/farol-guard/internal/keyops"
)

func TestRemovedPairsSkipsRolledBack(t *testing.T) {
	results := []keyops.Result{
		{Host: "a", Events: []keyops.Event{
			{User: "opc", Action: "remove", Status: keyops.StatusOK},
			{User: "root", Action: "remove", Status: keyops.StatusOK},
			{User: "root", Action: "verify", Status: keyops.StatusFail},
			{User: "root", Action: "rollback", Status: keyops.StatusOK},
		}},
		{Host: "b", Events: []keyops.Event{
			{User: "root", Action: "remove", Status: keyops.StatusSkip},
			{User: "ubuntu", Action: "read", Status: keyops.StatusFail},
		}},
	}
	got := removedPairs(results)
	want := [][2]string{{"a", "opc"}, {"b", "root"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}
