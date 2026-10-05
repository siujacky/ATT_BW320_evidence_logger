//go:build windows

package winsvc

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"attmonitor/internal/config"
)

const (
	sidSystem = "S-1-5-18"
	sidAdmins = "S-1-5-32-544"
	sidUsers  = "S-1-5-32-545"

	fileAllAccess  = 0x1f01ff // FA
	readAndExecute = 0x1200a9 // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
	oici           = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
)

type ace struct {
	typ   uint8
	flags uint8
	mask  uint32
	sid   string
}

// readDACL returns the DACL's control flags, SDDL and entries.
func readDACL(t *testing.T, path string) (windows.SECURITY_DESCRIPTOR_CONTROL, string, []ace) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	var out []ace
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &a); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		out = append(out, ace{a.Header.AceType, a.Header.AceFlags, uint32(a.Mask), sid.String()})
	}
	return control, sd.String(), out
}

// restoreAccessOnCleanup gives the current user full control of dir again before the temp
// directory is removed: after SecureDataDir a non-elevated owner can only read, but as owner
// it keeps WRITE_DAC. Must be called after t.TempDir so it runs first.
func restoreAccessOnCleanup(t *testing.T, dir string) {
	t.Helper()
	t.Cleanup(func() {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			t.Logf("restore ACL: %v", err)
			return
		}
		sd, err := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;" + user.User.Sid.String() + ")")
		if err != nil {
			t.Logf("restore ACL: %v", err)
			return
		}
		dacl, _, _ := sd.DACL()
		err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
		if err != nil && !os.IsNotExist(err) {
			t.Logf("restore ACL on %s: %v", dir, err)
		}
	})
}

func TestSecureDataDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "ATTMonitor")
	// Pre-existing content must receive the new inherited entries.
	if err := os.MkdirAll(filepath.Join(dir, "ledger"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "ledger", "ledger-2026-10-05.jsonl")
	if err := os.WriteFile(file, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restoreAccessOnCleanup(t, dir)

	if err := SecureDataDir(dir); err != nil {
		t.Fatalf("SecureDataDir: %v", err)
	}

	control, sddl, entries := readDACL(t, dir)
	t.Logf("data dir DACL: %s", sddl)
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("DACL is not protected (control %#x): it still inherits from the parent", control)
	}
	if want := "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"; sddl != want {
		t.Errorf("SDDL = %s\nwant   %s", sddl, want)
	}
	wantEntries := []ace{
		{windows.ACCESS_ALLOWED_ACE_TYPE, oici, fileAllAccess, sidSystem},
		{windows.ACCESS_ALLOWED_ACE_TYPE, oici, fileAllAccess, sidAdmins},
		{windows.ACCESS_ALLOWED_ACE_TYPE, oici, readAndExecute, sidUsers},
	}
	if !slices.Equal(entries, wantEntries) {
		t.Errorf("entries = %+v\nwant      %+v", entries, wantEntries)
	}

	// Children: exactly the three entries, inherited (no leftovers granting more access).
	for _, child := range []struct {
		path  string
		flags uint8
		sddl  string
	}{
		{filepath.Join(dir, "ledger"), oici | windows.INHERITED_ACE,
			"D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)"},
		{file, windows.INHERITED_ACE, "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)"},
	} {
		_, got, es := readDACL(t, child.path)
		if got != child.sddl {
			t.Errorf("%s: SDDL = %s, want %s", child.path, got, child.sddl)
		}
		want := []ace{
			{windows.ACCESS_ALLOWED_ACE_TYPE, child.flags, fileAllAccess, sidSystem},
			{windows.ACCESS_ALLOWED_ACE_TYPE, child.flags, fileAllAccess, sidAdmins},
			{windows.ACCESS_ALLOWED_ACE_TYPE, child.flags, readAndExecute, sidUsers},
		}
		if !slices.Equal(es, want) {
			t.Errorf("%s: entries = %+v, want %+v", child.path, es, want)
		}
	}

	// Content stays readable for users; idempotent re-application.
	if b, err := os.ReadFile(file); err != nil || string(b) != "{}\n" {
		t.Errorf("read after securing: %q, %v", b, err)
	}
	if err := SecureDataDir(dir); err != nil {
		t.Fatalf("second SecureDataDir: %v", err)
	}
	if _, again, _ := readDACL(t, dir); again != sddl {
		t.Errorf("second application changed the DACL: %s", again)
	}

	if IsAdmin() { // elevated: the owner is moved to Administrators
		sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := sd.Owner()
		if err != nil || owner.String() != sidAdmins {
			t.Errorf("owner = %v, %v; want Administrators", owner, err)
		}
	}
}

func TestSecureDataDirCreatesMissing(t *testing.T) {
	root := t.TempDir()
	top := filepath.Join(root, "new")
	dir := filepath.Join(top, "nested", "ATTMonitor")
	restoreAccessOnCleanup(t, dir)

	if err := SecureDataDir(dir); err != nil {
		t.Fatalf("SecureDataDir: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		t.Fatalf("directory not created: %v", err)
	}
	control, sddl, _ := readDACL(t, dir)
	if control&windows.SE_DACL_PROTECTED == 0 || !strings.HasPrefix(sddl, "D:PAI(") {
		t.Errorf("created directory has %s (control %#x), want a protected DACL", sddl, control)
	}
	// Only the target is protected; the created parents keep normal inheritance.
	if c, _, _ := readDACL(t, top); c&windows.SE_DACL_PROTECTED != 0 {
		t.Error("intermediate directory got a protected DACL")
	}
}

func TestSecurePrivateDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "keys")
	restoreAccessOnCleanup(t, dir)
	if err := SecurePrivateDir(dir); err != nil {
		t.Fatalf("SecurePrivateDir: %v", err)
	}
	control, sddl, entries := readDACL(t, dir)
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("DACL not protected")
	}
	if want := "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"; sddl != want {
		t.Errorf("SDDL = %s, want %s", sddl, want)
	}
	for _, e := range entries {
		if e.sid != sidSystem && e.sid != sidAdmins {
			t.Errorf("unexpected entry for %s", e.sid)
		}
	}
	if !IsAdmin() {
		// A standard user (even the folder's creator) can no longer list it.
		if _, err := os.ReadDir(dir); err == nil {
			t.Error("non-elevated process can still list the private directory")
		}
	}
}

func TestSecureDataDirRejects(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "junction")
	out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput()
	haveJunction := err == nil
	if !haveJunction {
		t.Logf("cannot create a junction (%v: %s); skipping that case", err, out)
	}

	tests := []struct {
		name    string
		path    string
		wantSub string
		skip    bool
	}{
		{"empty path", "", "empty path", false},
		{"regular file", file, "not a directory", false},
		{"junction", junction, "reparse point", !haveJunction},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip {
				t.Skip("junction unavailable")
			}
			err := SecureDataDir(tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("SecureDataDir(%q) = %v, want error containing %q", tc.path, err, tc.wantSub)
			}
		})
	}
	// The junction's target must not have been touched.
	if c, _, _ := readDACL(t, target); c&windows.SE_DACL_PROTECTED != 0 {
		t.Error("ACL was applied through the junction")
	}
}

// isProtected reports whether path's DACL is protected (i.e. a Secure* call changed it).
func isProtected(t *testing.T, path string) bool {
	t.Helper()
	c, _, _ := readDACL(t, path)
	return c&windows.SE_DACL_PROTECTED != 0
}

// SecureDataDir replaces the ACL of the whole tree; pointed at a folder that holds other data
// (e.g. --data C:\Users\me\Documents by mistake) it must refuse and change nothing.
func TestSecureDataDirRefusesForeignContent(t *testing.T) {
	tests := []struct {
		name    string
		files   []string
		dirs    []string
		wantSub []string
	}{
		{name: "one foreign file among layout folders", files: []string{"taxes-2025.pdf"},
			wantSub: []string{`"taxes-2025.pdf"`, "use a new or empty directory"}},
		{name: "many foreign entries are summarized", files: []string{"a", "b", "c", "d", "e", "f", "g"},
			wantSub: []string{`"a"`, `"e"`, "and 2 more"}},
		{name: "foreign folder", dirs: []string{"Projects"}, wantSub: []string{`"Projects"`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "Documents")
			if err := os.MkdirAll(filepath.Join(dir, "ledger"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, f := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, f), []byte("mine"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for _, d := range tc.dirs {
				if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			restoreAccessOnCleanup(t, dir)
			err := SecureDataDir(dir)
			if err == nil {
				t.Fatal("SecureDataDir succeeded on a folder with foreign content")
			}
			for _, sub := range tc.wantSub {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q does not contain %q", err, sub)
				}
			}
			if isProtected(t, dir) {
				t.Error("the ACL was replaced anyway")
			}
		})
	}
}

// Everything the att-monitor layout puts in the data directory (plus a leftover config temp
// file and Explorer's desktop.ini) is accepted.
func TestSecureDataDirAcceptsLayoutEntries(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ATTMonitor")
	paths := config.PathsFor(dir)
	if err := paths.MkdirAll(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{paths.Config, paths.Config + ".tmp", filepath.Join(dir, "Desktop.ini")} {
		if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	restoreAccessOnCleanup(t, dir)
	if err := SecureDataDir(dir); err != nil {
		t.Fatalf("SecureDataDir on a complete data directory: %v", err)
	}
	if !isProtected(t, dir) {
		t.Error("DACL not applied")
	}
}

// dataDirEntries must list every top-level name of the config layout, or SecureDataDir would
// refuse the product's own data directory.
func TestDataDirEntriesMatchConfigLayout(t *testing.T) {
	p := config.PathsFor(`C:\ProgramData\ATTMonitor`)
	for _, path := range []string{p.Config, p.Keys, p.Ledger, p.Blobs, p.Exports, p.Quarantine, p.State, p.Logs} {
		if filepath.Dir(path) != p.Root {
			t.Errorf("%s is not directly inside the data directory; update the content check", path)
		}
		if name := filepath.Base(path); !isDataDirEntry(name) {
			t.Errorf("layout entry %q is not in dataDirEntries", name)
		}
	}
}

// A junction inside the data directory must not carry the new ACL to its target.
func TestSecureDataDirJunctionInsideNotFollowed(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "elsewhere")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(target, "victim.txt")
	if err := os.WriteFile(victim, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "ATTMonitor")
	if err := os.MkdirAll(filepath.Join(dir, "ledger"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(dir, "ledger", "j"), target).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction: %v %s", err, out)
	}
	restoreAccessOnCleanup(t, dir)
	_, beforeT, _ := readDACL(t, target)
	_, beforeV, _ := readDACL(t, victim)
	if err := SecureDataDir(dir); err != nil {
		t.Fatalf("SecureDataDir: %v", err)
	}
	if _, after, _ := readDACL(t, target); after != beforeT {
		t.Errorf("junction target ACL changed:\nbefore %s\nafter  %s", beforeT, after)
	}
	if _, after, _ := readDACL(t, victim); after != beforeV {
		t.Errorf("file behind the junction changed:\nbefore %s\nafter  %s", beforeV, after)
	}
}

func TestCheckNotCritical(t *testing.T) {
	cs := criticalSet{
		trees: []string{`C:\Windows`},
		dirs:  []string{`C:\Program Files`, `C:\ProgramData`, `C:\Users`, `C:\Users\Dell`},
	}
	tests := []struct {
		path    string
		wantSub string // "" = allowed
	}{
		{`C:\`, "root of a volume"},
		{`D:\`, "root of a volume"},
		{`C:\.`, "root of a volume"},
		{`C:\Windows\..`, "root of a volume"},
		{`\\server\share`, "root of a volume"},
		{`\\server\share\`, "root of a volume"},
		{`\\?\C:\`, "root of a volume"},
		{`C:\Windows`, "system folder"},
		{`c:\windows\system32\config`, "system folder"},
		{`C:\WINDOWS\Temp\ATTMonitor`, "system folder"},
		{`C:\WindowsApps`, ""}, // shares a prefix, but is not inside C:\Windows
		{`C:\ProgramData`, "protected folder"},
		{`C:\ProgramData\`, "protected folder"},
		{`C:\ProgramData\ATTMonitor`, ""},
		{`C:\Program Files`, "protected folder"},
		{`C:\Program Files\ATT Monitor`, ""},
		{`C:\Users`, "protected folder"},
		{`C:\users\dell`, "protected folder"},
		{`C:\Users\Dell\..`, "protected folder"}, // cleaned to C:\Users
		{`C:\Users\Dell\ATTMonitor`, ""},
		{`\\server\share\ATTMonitor`, ""},
		{`D:\Evidence\ATTMonitor`, ""},
	}
	for _, tc := range tests {
		err := checkNotCritical(tc.path, cs)
		switch {
		case tc.wantSub == "" && err != nil:
			t.Errorf("checkNotCritical(%q) = %v, want allowed", tc.path, err)
		case tc.wantSub != "" && (err == nil || !strings.Contains(err.Error(), tc.wantSub)):
			t.Errorf("checkNotCritical(%q) = %v, want an error containing %q", tc.path, err, tc.wantSub)
		}
	}
}

func TestPathHelpers(t *testing.T) {
	for _, tc := range []struct {
		path, dir string
		want      bool
	}{
		{`C:\Windows\System32`, `C:\Windows`, true},
		{`c:\windows`, `C:\Windows\`, true},
		{`C:\WindowsApps`, `C:\Windows`, false},
		{`C:\x`, `C:\`, true},
		{`C:\`, `C:\x`, false},
		{`D:\Windows`, `C:\Windows`, false},
	} {
		if got := within(tc.path, tc.dir); got != tc.want {
			t.Errorf("within(%q, %q) = %v, want %v", tc.path, tc.dir, got, tc.want)
		}
	}
	for in, want := range map[string]string{
		`\\?\C:\ProgramData\ATTMonitor`: `C:\ProgramData\ATTMonitor`,
		`\\?\UNC\server\share\dir`:      `\\server\share\dir`,
		`C:\plain`:                      `C:\plain`,
	} {
		if got := trimLongPathPrefix(in); got != want {
			t.Errorf("trimLongPathPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// The real critical set covers the system folders, and the default data directory (and a
// folder in the user's profile) stay allowed. Only the pure check is called here: tests never
// point SecureDataDir at real system folders.
func TestCriticalDirsOnThisSystem(t *testing.T) {
	cs := criticalDirs()
	t.Logf("trees %q\ndirs %q", cs.trees, cs.dirs)
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		t.Skip("SystemRoot not set")
	}
	if !slices.ContainsFunc(cs.trees, func(d string) bool { return strings.EqualFold(d, sysRoot) }) {
		t.Errorf("trees %q lack %s", cs.trees, sysRoot)
	}
	refused := []string{sysRoot, filepath.Join(sysRoot, "System32", "config"), filepath.VolumeName(sysRoot) + `\`}
	allowed := []string{config.DefaultDataDir()}
	for _, env := range []string{"ProgramData", "ProgramFiles", "USERPROFILE", "PUBLIC"} {
		if v := os.Getenv(env); v != "" {
			refused = append(refused, v, filepath.Dir(v))
			if !within(v, sysRoot) { // LocalSystem's profile lives inside the Windows folder
				allowed = append(allowed, filepath.Join(v, "ATTMonitor"))
			}
		}
	}
	for _, p := range refused {
		if err := checkNotCritical(p, cs); err == nil {
			t.Errorf("%s is not refused", p)
		}
	}
	for _, p := range allowed {
		if err := checkNotCritical(p, cs); err != nil {
			t.Errorf("%s is refused: %v", p, err)
		}
	}
}

// useCriticalStandIns makes SecureDataDir treat temporary folders as the system folders.
func useCriticalStandIns(t *testing.T, cs criticalSet) {
	t.Helper()
	old := criticalDirsFunc
	criticalDirsFunc = func() criticalSet { return cs }
	t.Cleanup(func() { criticalDirsFunc = old })
}

// shortPath returns the 8.3 form of an existing path, or the path itself if the volume has
// no short names.
func shortPath(t *testing.T, long string) string {
	t.Helper()
	p, err := windows.UTF16PtrFromString(long)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetShortPathName(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		return long
	}
	return windows.UTF16ToString(buf[:n])
}

func TestSecureDataDirRefusesCriticalFolders(t *testing.T) {
	root := t.TempDir()
	sys := filepath.Join(root, "Long System Folder Name") // stands in for C:\Windows
	profiles := filepath.Join(root, "profiles")
	me := filepath.Join(profiles, "me") // stands in for a user profile
	for _, d := range []string{sys, me} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	useCriticalStandIns(t, criticalSet{trees: []string{sys}, dirs: []string{me}})

	junction := filepath.Join(root, "j")
	haveJunction := exec.Command("cmd", "/c", "mklink", "/J", junction, sys).Run() == nil
	leafLink := filepath.Join(root, "leaf")
	haveLeafLink := exec.Command("cmd", "/c", "mklink", "/J", leafLink, me).Run() == nil
	short := shortPath(t, sys)
	t.Logf("short name of %s: %s", sys, short)

	tests := []struct {
		name       string
		path       string
		skip       bool
		notCreated string // must not exist afterwards
	}{
		{name: "system folder", path: sys},
		{name: "inside the system folder", path: filepath.Join(sys, "new", "ATTMonitor"), notCreated: filepath.Join(sys, "new")},
		{name: "folder containing the system folder", path: root},
		{name: "profile", path: me},
		{name: "folder containing a profile", path: profiles},
		{name: "8.3 short name of the system folder", path: short, skip: short == sys},
		{name: "inside the system folder via its short name", path: filepath.Join(short, "x"), skip: short == sys,
			notCreated: filepath.Join(sys, "x")},
		{name: "junction earlier in the path", path: filepath.Join(junction, "inner"), skip: !haveJunction,
			notCreated: filepath.Join(sys, "inner")},
		{name: "junction to a profile as the data directory", path: leafLink, skip: !haveLeafLink},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip {
				t.Skip("short names or junctions unavailable on this volume")
			}
			if err := SecureDataDir(tc.path); err == nil {
				t.Fatalf("SecureDataDir(%s) succeeded", tc.path)
			} else {
				t.Logf("refused: %v", err)
			}
			if err := SecurePrivateDir(tc.path); err == nil {
				t.Fatalf("SecurePrivateDir(%s) succeeded", tc.path)
			}
			for _, d := range []string{sys, me, profiles, root} {
				if isProtected(t, d) {
					t.Fatalf("ACL of %s was replaced", d)
				}
			}
			if tc.notCreated != "" {
				if _, err := os.Lstat(tc.notCreated); err == nil {
					t.Errorf("%s was created before the request was refused", tc.notCreated)
				}
			}
		})
	}

	// A data directory inside a profile is fine.
	inside := filepath.Join(me, "ATTMonitor")
	restoreAccessOnCleanup(t, inside)
	if err := SecureDataDir(inside); err != nil {
		t.Errorf("SecureDataDir inside a profile: %v", err)
	}
}

// SecurePrivateDir makes a folder admin-only; it accepts only a folder directly inside an
// att-monitor data directory (the keys folder), never e.g. a Documents folder by mistake.
func TestSecurePrivateDirRequiresDataDirParent(t *testing.T) {
	t.Run("keys folder of a data directory", func(t *testing.T) {
		data := filepath.Join(t.TempDir(), "ATTMonitor")
		paths := config.PathsFor(data)
		if err := paths.MkdirAll(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(paths.Keys, "ledger-signing.key"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		restoreAccessOnCleanup(t, paths.Keys)
		if err := SecurePrivateDir(paths.Keys); err != nil {
			t.Fatalf("SecurePrivateDir(keys): %v", err)
		}
		if !isProtected(t, paths.Keys) {
			t.Error("DACL not applied")
		}
	})
	t.Run("folder whose parent holds other data", func(t *testing.T) {
		home := filepath.Join(t.TempDir(), "me")
		docs := filepath.Join(home, "Documents")
		if err := os.MkdirAll(docs, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, "notes.txt"), []byte("mine"), 0o644); err != nil {
			t.Fatal(err)
		}
		restoreAccessOnCleanup(t, docs)
		err := SecurePrivateDir(docs)
		if err == nil || !strings.Contains(err.Error(), "directly inside an att-monitor data directory") ||
			!strings.Contains(err.Error(), `"notes.txt"`) {
			t.Fatalf("SecurePrivateDir = %v, want a refusal naming the foreign entry", err)
		}
		if isProtected(t, docs) {
			t.Error("the ACL was replaced anyway")
		}
	})
}

// The install flow is SecureDataDir(data) then SecurePrivateDir(data\keys), repeated on every
// reinstall: securing the data directory again must leave the private keys folder (and the
// key file in it) private, never re-granting Users read access to the signing key.
func TestSecureDataDirKeepsPrivateKeysFolder(t *testing.T) {
	data := filepath.Join(t.TempDir(), "ATTMonitor")
	paths := config.PathsFor(data)
	if err := paths.MkdirAll(); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(paths.Keys, "ledger-signing.key")
	if err := os.WriteFile(keyFile, []byte(`{"alg":"ed25519"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	restoreAccessOnCleanup(t, data)
	restoreAccessOnCleanup(t, paths.Keys)

	for i := 0; i < 2; i++ { // install, then reinstall
		if err := SecureDataDir(data); err != nil {
			t.Fatalf("round %d: SecureDataDir: %v", i, err)
		}
		if err := SecurePrivateDir(paths.Keys); err != nil {
			t.Fatalf("round %d: SecurePrivateDir: %v", i, err)
		}
	}
	if err := SecureDataDir(data); err != nil { // e.g. a later repair run
		t.Fatalf("SecureDataDir after SecurePrivateDir: %v", err)
	}
	if _, sddl, _ := readDACL(t, paths.Keys); sddl != privateDirSDDL {
		t.Errorf("keys DACL = %s, want %s", sddl, privateDirSDDL)
	}
	_, sddl, entries := readDACL(t, keyFile)
	for _, e := range entries {
		if e.sid != sidSystem && e.sid != sidAdmins {
			t.Errorf("key file grants access to %s: %s", e.sid, sddl)
		}
	}
	if _, sddl, _ := readDACL(t, paths.Ledger); !strings.Contains(sddl, ";;;BU)") {
		t.Errorf("ledger lost the Users read entry: %s", sddl)
	}
}

func TestNTPathName(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{in: `C:\ProgramData\ATTMonitor`, want: `\??\C:\ProgramData\ATTMonitor`},
		{in: `d:\x`, want: `\??\d:\x`},
		{in: `\\server\share\ATTMonitor`, want: `\??\UNC\server\share\ATTMonitor`},
		{in: `\\?\C:\long\path`, want: `\??\C:\long\path`},
		{in: `\??\C:\x`, want: `\??\C:\x`},
		{in: `\\.\PhysicalDrive0`, wantErr: true},
		{in: `relative\dir`, wantErr: true},
		{in: `C:relative`, wantErr: true},
		{in: `1:\x`, wantErr: true},
		{in: ``, wantErr: true},
	}
	for _, tc := range tests {
		got, err := ntPathName(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ntPathName(%q) = %q, %v; want %q (error %v)", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

// A missing directory is reported as such (the NT status is mapped to a Win32 error).
func TestOpenDirNoFollowErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	_, err := openDirNoFollow(missing, windows.READ_CONTROL)
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Errorf("openDirNoFollow(missing) = %v, want ERROR_FILE_NOT_FOUND", err)
	}
	if _, err := openDirNoFollow("relative", windows.READ_CONTROL); err == nil {
		t.Error("openDirNoFollow(relative) succeeded")
	}
}
