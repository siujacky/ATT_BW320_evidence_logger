package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The Windows side of the guided setup: elevation, the console, Settings > Apps and the Start
// menu.

var (
	modShell32                = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW       = modShell32.NewProc("ShellExecuteExW")
	modKernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = modKernel32.NewProc("GetConsoleProcessList")
)

// errElevationCancelled: the user answered No to the administrator (UAC) prompt.
var errElevationCancelled = errors.New("administrator permission was not given")

// shellExecuteInfo is SHELLEXECUTEINFOW (Go's alignment matches the C layout on 64-bit Windows).
type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           windows.Handle
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       windows.Handle
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      windows.Handle
	dwHotKey       uint32
	hIconOrMonitor windows.Handle
	hProcess       windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
	seeMaskFlagNoUI       = 0x00000400 // errors are returned instead of shown in a dialog
)

// runElevated starts this program again with administrator rights - Windows shows its UAC
// prompt - in a window of its own, waits for it and returns its exit code.
func runElevated(args []string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	code, err := shellExecuteWait("runas", exe, args, windows.SW_SHOWNORMAL, 0)
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return 0, errElevationCancelled
	}
	return code, err
}

// shellExecuteWait runs file with args through ShellExecuteEx (verb "runas" asks for
// administrator rights), waits for the process and returns its exit code. mask adds
// SEE_MASK_* flags (tests pass seeMaskFlagNoUI so that an error never waits on a dialog).
func shellExecuteWait(verb, file string, args []string, show int32, mask uint32) (int, error) {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	v, err := windows.UTF16PtrFromString(verb)
	if err != nil {
		return 0, err
	}
	f, err := windows.UTF16PtrFromString(file)
	if err != nil {
		return 0, err
	}
	params, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return 0, err
	}
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(file))
	info := shellExecuteInfo{fMask: seeMaskNoCloseProcess | seeMaskNoAsync | mask, lpVerb: v, lpFile: f,
		lpParameters: params, lpDirectory: dir, nShow: show}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if r, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		var errno syscall.Errno
		if errors.As(callErr, &errno) && errno == windows.ERROR_CANCELLED {
			return 0, windows.ERROR_CANCELLED
		}
		return 0, fmt.Errorf("start %s: %w", filepath.Base(file), callErr)
	}
	if info.hProcess == 0 {
		return 0, fmt.Errorf("start %s: no process handle", filepath.Base(file))
	}
	defer windows.CloseHandle(info.hProcess)
	if _, err := windows.WaitForSingleObject(info.hProcess, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &code); err != nil {
		return 0, err
	}
	return int(code), nil
}

// ownConsole reports whether this process has a console window of its own: Windows created it
// because the program was started from Explorer (a double-click) or elevated by runElevated,
// rather than from a terminal. Such a window closes as soon as the program ends.
func ownConsole() bool {
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// stdin is the one buffered reader of standard input (several would lose each other's data).
var stdin = bufio.NewReader(os.Stdin)

func stdinReader() *bufio.Reader { return stdin }

// readHiddenLine reads one line from the console without showing what is typed. When standard
// input is not a console (a pipe), the line is read as it is.
func readHiddenLine() (string, error) {
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil || windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT) != nil {
		return readLine(stdin)
	}
	// Ctrl+C must not leave the console without echo.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			_ = windows.SetConsoleMode(h, mode)
			fmt.Println()
			os.Exit(130)
		case <-done:
		}
	}()
	defer func() {
		close(done)
		signal.Stop(sig)
		_ = windows.SetConsoleMode(h, mode)
	}()
	line, err := readLine(stdin)
	fmt.Println() // the Enter key was not echoed either
	return line, err
}

// openURL opens url in the user's default browser.
func openURL(url string) error {
	verb, _ := windows.UTF16PtrFromString("open")
	u, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, u, nil, nil, windows.SW_SHOWNORMAL)
}

// pauseIfOwnWindow keeps a window of its own open until Enter is pressed, so its last messages
// can be read.
func pauseIfOwnWindow() {
	if !ownConsole() {
		return
	}
	fmt.Print("\nPress Enter to close this window.")
	_, _ = readLine(stdin)
}

// pauseFor keeps a window of its own open for d.
func pauseFor(d time.Duration) {
	if !ownConsole() {
		return
	}
	fmt.Printf("\nThis window closes in %d seconds.\n", int(d/time.Second))
	time.Sleep(d)
}

// ---------------------------------------------------------------- Settings > Apps, Start menu

const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ATTMonitor`

// registerApp lists the program in Settings > Apps, with its uninstaller.
func registerApp(exe, dashboard string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKey, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()
	var size uint32
	if st, err := os.Stat(exe); err == nil {
		size = uint32(st.Size() / 1024)
	}
	strs := map[string]string{
		"DisplayName":     displayName,
		"DisplayVersion":  version,
		"DisplayIcon":     exe,
		"InstallLocation": filepath.Dir(exe),
		"UninstallString": syscall.EscapeArg(exe) + " uninstall --interactive",
		"URLInfoAbout":    repoURL,
		"HelpLink":        dashboard,
		"Comments":        "Evidence logger for an AT&T Fiber connection. Uninstalling keeps the evidence in " + defaultDataDir(""),
	}
	if _, _, err := k.GetStringValue("InstallDate"); err != nil {
		strs["InstallDate"] = time.Now().Format("20060102")
	}
	for name, v := range strs {
		if err := k.SetStringValue(name, v); err != nil {
			return err
		}
	}
	for name, v := range map[string]uint32{"NoModify": 1, "NoRepair": 1, "EstimatedSize": size} {
		if err := k.SetDWordValue(name, v); err != nil {
			return err
		}
	}
	return nil
}

func unregisterApp() error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}

// startMenuShortcut is the all-users Start menu link to the dashboard.
func startMenuShortcut() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs`, "AT&T Internet Monitor.url")
}

func writeStartMenuShortcut(dashboard string) error {
	return os.WriteFile(startMenuShortcut(), []byte("[InternetShortcut]\r\nURL="+dashboard+"\r\n"), 0o644)
}

func removeStartMenuShortcut() error {
	err := os.Remove(startMenuShortcut())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// removeProgramFiles deletes the installed program. A running program cannot delete itself, so
// when this is the installed copy Windows deletes it at the next restart.
func removeProgramFiles(out io.Writer) {
	dir := installDir()
	exe := filepath.Join(dir, "att-monitor.exe")
	self, _ := os.Executable()
	if strings.EqualFold(filepath.Clean(self), filepath.Clean(exe)) {
		e, _ := windows.UTF16PtrFromString(exe)
		d, _ := windows.UTF16PtrFromString(dir)
		if windows.MoveFileEx(e, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT) == nil {
			_ = windows.MoveFileEx(d, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
			fmt.Fprintln(out, "The program files are removed at the next restart of Windows:", dir)
			return
		}
		fmt.Fprintln(out, "Note: delete this folder after a restart:", dir)
		return
	}
	if err := os.Remove(exe); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(out, "Note: could not delete", exe, "-", err)
		return
	}
	_ = os.Remove(exe + ".new")
	_ = os.Remove(dir) // only when empty
	fmt.Fprintln(out, "Program removed:", dir)
}
