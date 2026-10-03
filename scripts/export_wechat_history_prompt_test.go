//go:build windows

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWaitForWeChatExitNoRunningClient(t *testing.T) {
	checks := 0
	probe := func() ([]runningWeChatClient, error) {
		checks++
		return nil, nil
	}
	var output bytes.Buffer
	if err := waitForWeChatExitWith(probe, strings.NewReader(""), &output, false, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checks != 1 || output.Len() != 0 {
		t.Fatalf("checks=%d output=%q", checks, output.String())
	}
}

func TestWaitForWeChatExitPromptsAndRechecks(t *testing.T) {
	checks := 0
	probe := func() ([]runningWeChatClient, error) {
		checks++
		if checks == 1 {
			return []runningWeChatClient{{Name: "fixture", PID: 42}}, nil
		}
		return nil, nil
	}
	var output bytes.Buffer
	if err := waitForWeChatExitWith(probe, strings.NewReader("\n"), &output, true, map[uint32]bool{42: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checks != 2 {
		t.Fatalf("expected two process checks, got %d", checks)
	}
	text := output.String()
	if !strings.Contains(text, "fixture (PID 42)") || !strings.Contains(text, "press Enter") {
		t.Fatalf("prompt is not actionable: %q", text)
	}
}

func TestWaitForWeChatExitConfigOnlyModeDoesNotRequireLiveKeyAssociation(t *testing.T) {
	checks := 0
	probe := func() ([]runningWeChatClient, error) {
		checks++
		if checks == 1 {
			return []runningWeChatClient{{Name: "WeChat", PID: 77}}, nil
		}
		return nil, nil
	}
	var output bytes.Buffer
	if err := waitForWeChatExitWith(probe, strings.NewReader("\n"), &output, true, nil); err != nil {
		t.Fatalf("config-only shutdown prompt unexpectedly required live-key capture: %v", err)
	}
	if checks != 2 || !strings.Contains(output.String(), "WeChat (PID 77)") {
		t.Fatalf("config-only shutdown prompt did not recheck the client: checks=%d output=%q", checks, output.String())
	}
}

func TestWaitForWeChatExitFailsClearlyWithoutInteractiveInput(t *testing.T) {
	probe := func() ([]runningWeChatClient, error) {
		return []runningWeChatClient{{Name: "fixture", PID: 43}}, nil
	}
	err := waitForWeChatExitWith(probe, strings.NewReader(""), &bytes.Buffer{}, false, map[uint32]bool{43: true})
	if err == nil || !strings.Contains(err.Error(), "interactive prompting is unavailable") ||
		!strings.Contains(err.Error(), "Exit WeChat and rerun") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWaitForWeChatExitReportsProbeFailure(t *testing.T) {
	probe := func() ([]runningWeChatClient, error) {
		return nil, errors.New("probe failed")
	}
	err := waitForWeChatExitWith(probe, strings.NewReader(""), &bytes.Buffer{}, true, nil)
	if err == nil || !strings.Contains(err.Error(), "could not recheck") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWaitForWeChatExitRejectsProcessNotSeenDuringKeyCapture(t *testing.T) {
	probe := func() ([]runningWeChatClient, error) {
		return []runningWeChatClient{{Name: "WeChat", PID: 99}}, nil
	}
	err := waitForWeChatExitWith(
		probe,
		strings.NewReader("\n"),
		&bytes.Buffer{},
		true,
		map[uint32]bool{42: true},
	)
	if err == nil || !strings.Contains(err.Error(), "during live-key capture") ||
		!strings.Contains(err.Error(), "exit it completely") {
		t.Fatalf("unexpected error: %v", err)
	}
}
