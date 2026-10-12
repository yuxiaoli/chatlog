//go:build windows

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type confirmationInput struct{ reads int }

func (input *confirmationInput) Read([]byte) (int, error) {
	input.reads++
	return 0, errors.New("confirmation input must not be read")
}

func TestWaitForWeChatExitNeverReadsConfirmation(t *testing.T) {
	checks := 0
	probe := func() ([]runningWeChatClient, error) {
		checks++
		return []runningWeChatClient{{Name: "WeChat", PID: 42}}, nil
	}
	input := &confirmationInput{}
	var output bytes.Buffer
	err := waitForWeChatExitWith(probe, input, &output, true, map[uint32]bool{42: true})
	if err == nil || !strings.Contains(err.Error(), "Exit WeChat and rerun") || input.reads != 0 || checks != 1 || output.Len() != 0 {
		t.Fatalf("expected a noninteractive process failure: err=%v reads=%d checks=%d output=%q", err, input.reads, checks, output.String())
	}
}

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

func TestWaitForWeChatExitFailsWithoutPromptingWhenClientIsRunning(t *testing.T) {
	checks := 0
	probe := func() ([]runningWeChatClient, error) {
		checks++
		if checks == 1 {
			return []runningWeChatClient{{Name: "fixture", PID: 42}}, nil
		}
		return nil, nil
	}
	var output bytes.Buffer
	err := waitForWeChatExitWith(probe, strings.NewReader("\n"), &output, true, map[uint32]bool{42: true})
	if err == nil || !strings.Contains(err.Error(), "fixture (PID 42)") || checks != 1 || output.Len() != 0 {
		t.Fatalf("expected an actionable failure without confirmation: err=%v checks=%d output=%q", err, checks, output.String())
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
	err := waitForWeChatExitWith(probe, strings.NewReader("\n"), &output, true, nil)
	if err == nil || !strings.Contains(err.Error(), "WeChat (PID 77)") || strings.Contains(err.Error(), "live-key capture") || checks != 1 || output.Len() != 0 {
		t.Fatalf("config-only check incorrectly depended on live keys or confirmation: err=%v checks=%d output=%q", err, checks, output.String())
	}
}

func TestWaitForWeChatExitFailsClearlyWithoutInteractiveInput(t *testing.T) {
	probe := func() ([]runningWeChatClient, error) {
		return []runningWeChatClient{{Name: "fixture", PID: 43}}, nil
	}
	err := waitForWeChatExitWith(probe, strings.NewReader(""), &bytes.Buffer{}, false, map[uint32]bool{43: true})
	if err == nil || !strings.Contains(err.Error(), "Exit WeChat and rerun") {
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
