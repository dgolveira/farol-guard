package main

import "testing"

func TestWinToLinuxFallback(t *testing.T) {
	t.Setenv("PATH", "")
	got := winToLinux(`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`)
	want := "/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
