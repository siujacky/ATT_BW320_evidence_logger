package main

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestShellExecuteInfoLayout: the struct must have SHELLEXECUTEINFOW's size, or ShellExecuteEx
// rejects it (or reads hProcess from the wrong place).
func TestShellExecuteInfoLayout(t *testing.T) {
	want := uintptr(60) // 32-bit
	if unsafe.Sizeof(uintptr(0)) == 8 {
		want = 112
	}
	if got := unsafe.Sizeof(shellExecuteInfo{}); got != want {
		t.Fatalf("shellExecuteInfo is %d bytes, SHELLEXECUTEINFOW %d", got, want)
	}
	if got := unsafe.Offsetof(shellExecuteInfo{}.hProcess); unsafe.Sizeof(uintptr(0)) == 8 && got != 104 {
		t.Fatalf("hProcess at offset %d, want 104", got)
	}
}

// TestShellExecuteWait runs a process the way runElevated does, without asking for elevation,
// and gets its exit code back.
func TestShellExecuteWait(t *testing.T) {
	cmd := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	code, err := shellExecuteWait("open", cmd, []string{"/c", "exit", "7"}, windows.SW_HIDE, seeMaskFlagNoUI)
	if err != nil || code != 7 {
		t.Fatalf("exit code %d, %v", code, err)
	}
	if _, err := shellExecuteWait("open", filepath.Join(t.TempDir(), "missing.exe"), nil, windows.SW_HIDE, seeMaskFlagNoUI); err == nil {
		t.Error("a missing program started")
	}
}
