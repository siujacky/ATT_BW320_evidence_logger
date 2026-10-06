//go:build windows

package winsvc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Protected DACLs (P = not inherited from the parent, AI = auto-inherited by children,
// OICI = applies to files and subfolders):
//
//	dataDirSDDL:    SYSTEM and Administrators full control, Users read & execute
//	                (0x1200a9 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) — docs/DESIGN.md §5.
//	privateDirSDDL: SYSTEM and Administrators only.
const (
	dataDirSDDL    = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	privateDirSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
)

// dataDirEntries are the top-level names of an att-monitor data directory (docs/DESIGN.md §5,
// config.PathsFor; a test keeps the two in sync), compared case-insensitively. "config.json.*"
// (the temp file of an interrupted config save) and the files Explorer may drop into any
// folder are accepted too. A layout folder missing here makes the installer refuse the data
// directory it has just laid out (SecurePrivateDir checks the keys folder's parent).
var dataDirEntries = []string{
	"config.json", "keys", "ledger", "blobs", "exports", "quarantine", "state", "logs", "syslog",
	"desktop.ini", "thumbs.db",
}

// SecureDataDir creates dir if missing and replaces its DACL with a protected one (no
// inheritance from the parent): SYSTEM and Administrators full control, Users read & execute.
// Inheritable entries are propagated to existing files and subfolders. When the caller is
// elevated, the owner is also set to Administrators, so a non-admin user who pre-created the
// folder (e.g. under C:\ProgramData) keeps no owner rights over the evidence.
//
// Because the change propagates through the whole tree, it refuses (without changing
// anything) a volume root, the Windows folder or anything inside it, Program Files,
// ProgramData, the Users folder, a user profile and any folder containing one of those, and a
// directory that holds entries which do not belong to an att-monitor data directory (for
// example --data pointing at a Documents folder by mistake). These checks also use the
// directory's canonical path, so short (8.3) names and junctions earlier in the path do not
// get around them.
//
// Afterwards non-elevated processes, including the folder's creator, can only read; call it
// from the elevated installer (or the LocalSystem service). Links and other reparse points
// are refused rather than having the ACL applied to their target; the ACL is applied through
// a handle to the checked directory, so the path cannot be swapped for a link in between.
func SecureDataDir(dir string) error { return secureDir(dir, dataDirSDDL, true) }

// SecurePrivateDir is SecureDataDir without the Users entry: only SYSTEM and Administrators
// can open the folder. It is meant for folders holding secrets that are protected with
// machine-scope DPAPI (any local account can decrypt such a blob it can read), i.e. the
// ledger signing key folder. It applies the same location checks as SecureDataDir; instead of
// the content check on dir itself, dir must be directly inside an att-monitor data directory
// (its parent must pass that check), so a mistaken path cannot lock a user out of their files.
func SecurePrivateDir(dir string) error { return secureDir(dir, privateDirSDDL, false) }

func secureDir(dir, sddl string, dataDir bool) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("winsvc: secure directory: empty path")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("winsvc: secure directory %q: %w", dir, err)
	}
	critical := criticalDirsFunc()
	// Check before anything is created, on the path as given and as it resolves on disk...
	if err := checkNotCritical(abs, critical); err != nil {
		return err
	}
	if err := checkNotCritical(resolvedPath(abs), critical); err != nil {
		return err
	}
	if err := createIfMissing(abs); err != nil {
		return err
	}

	elevated := IsAdmin()
	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC)
	if elevated {
		access |= windows.WRITE_OWNER
	}
	h, err := openDirNoFollow(abs, access)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	// ... and on the canonical path of the directory actually opened.
	final, err := finalPath(h)
	if err != nil {
		final = abs // no DOS path (e.g. a volume without a drive letter): checked above
	}
	if err := checkNotCritical(final, critical); err != nil {
		return err
	}
	if dataDir {
		if err := checkDataDirEntries(final); err != nil {
			return err
		}
	} else if err := checkDataDirEntries(filepath.Dir(final)); err != nil {
		return fmt.Errorf("winsvc: a private folder must be directly inside an att-monitor data directory: %w", err)
	}

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("winsvc: parse security descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("winsvc: security descriptor DACL: %w", err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var owner *windows.SID
	if elevated {
		if owner, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err != nil {
			return fmt.Errorf("winsvc: administrators SID: %w", err)
		}
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	// Like SetNamedSecurityInfo, SetSecurityInfo propagates the inheritable entries to the
	// existing children (junctions inside the tree get the entries but are not followed).
	err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
	runtime.KeepAlive(sd) // dacl points into sd
	if err != nil {
		return fmt.Errorf("winsvc: set ACL on %s: %w", abs, err)
	}
	return nil
}

// createIfMissing creates path (and its parents) if nothing exists there.
func createIfMissing(path string) error {
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return fmt.Errorf("winsvc: create %s: %w", path, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("winsvc: %w", err)
	}
	return nil
}

// openDirNoFollow opens path itself (not the target of a link) with exactly access plus
// FILE_READ_ATTRIBUTES, and checks that it is a real directory, not a symbolic link, junction
// or other reparse point.
//
// NtCreateFile is used instead of CreateFile because CreateFile always adds SYNCHRONIZE to the
// requested access: an owner whom the DACL grants nothing (e.g. a non-elevated owner of a
// folder already restricted to SYSTEM and Administrators) has only the implicit READ_CONTROL
// and WRITE_DAC rights and could then not even re-apply the ACL. FILE_READ_ATTRIBUTES is
// granted by NTFS to anyone who may list the parent directory.
func openDirNoFollow(path string, access uint32) (windows.Handle, error) {
	nt, err := ntPathName(path)
	if err != nil {
		return 0, fmt.Errorf("winsvc: %w", err)
	}
	name, err := windows.NewNTUnicodeString(nt)
	if err != nil {
		return 0, fmt.Errorf("winsvc: invalid path %q: %w", path, err)
	}
	oa := windows.OBJECT_ATTRIBUTES{ObjectName: name, Attributes: windows.OBJ_CASE_INSENSITIVE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var (
		h    windows.Handle
		iosb windows.IO_STATUS_BLOCK
	)
	err = windows.NtCreateFile(&h, access|windows.FILE_READ_ATTRIBUTES, &oa, &iosb, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT, 0, 0)
	runtime.KeepAlive(name)
	if err != nil {
		if st, ok := err.(windows.NTStatus); ok {
			err = st.Errno() // e.g. ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND
		}
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return 0, fmt.Errorf("winsvc: open %s to change its ACL: %w (run from an elevated prompt)", path, err)
		}
		return 0, fmt.Errorf("winsvc: open %s: %w", path, err)
	}
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("winsvc: %s: %w", path, err)
	}
	switch {
	case fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		windows.CloseHandle(h)
		return 0, fmt.Errorf("winsvc: %s is a link or reparse point; refusing to change its ACL", path)
	case fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0:
		windows.CloseHandle(h)
		return 0, fmt.Errorf("winsvc: %s is not a directory", path)
	}
	return h, nil
}

// ntPathName converts an absolute Win32 path to the NT namespace without Win32 name
// normalization (like Go's own \\?\ long paths): C:\x → \??\C:\x, \\server\share\x →
// \??\UNC\server\share\x, \\?\C:\x → \??\C:\x.
func ntPathName(p string) (string, error) {
	switch {
	case strings.HasPrefix(p, `\\?\`), strings.HasPrefix(p, `\??\`):
		return `\??\` + p[4:], nil
	case strings.HasPrefix(p, `\\.\`):
		return "", fmt.Errorf("device path %q is not supported", p)
	case strings.HasPrefix(p, `\\`):
		return `\??\UNC\` + p[2:], nil
	case len(p) >= 3 && p[1] == ':' && p[2] == '\\' &&
		(('a' <= p[0] && p[0] <= 'z') || ('A' <= p[0] && p[0] <= 'Z')):
		return `\??\` + p, nil
	}
	return "", fmt.Errorf("not an absolute path: %q", p)
}

// GetFinalPathNameByHandle flags (fileapi.h): FILE_NAME_NORMALIZED | VOLUME_NAME_DOS.
const finalPathNormalizedDOS = 0

// finalPath returns the canonical DOS path of an open file or directory: long names, links
// resolved, without the \\?\ prefix.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	for i := 0; i < 3; i++ {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), finalPathNormalizedDOS)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			return trimLongPathPrefix(windows.UTF16ToString(buf[:n])), nil
		}
		buf = make([]uint16, n) // n includes the terminating NUL when the buffer is too small
	}
	return "", errors.New("winsvc: GetFinalPathNameByHandle: path keeps growing")
}

// trimLongPathPrefix turns \\?\C:\x into C:\x and \\?\UNC\server\share into \\server\share.
func trimLongPathPrefix(p string) string {
	switch {
	case strings.HasPrefix(p, `\\?\UNC\`):
		return `\\` + p[len(`\\?\UNC\`):]
	case strings.HasPrefix(p, `\\?\`):
		return p[len(`\\?\`):]
	}
	return p
}

// canonicalPath returns the final path of an existing file or directory, following links.
func canonicalPath(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	return finalPath(h)
}

// resolvedPath replaces the longest existing prefix of path by its canonical path, so short
// (8.3) names and junctions cannot disguise where a directory that is still to be created
// would end up. It returns path unchanged when no prefix can be resolved.
func resolvedPath(path string) string {
	p := filepath.Clean(path)
	var rest []string
	for {
		if c, err := canonicalPath(p); err == nil {
			return filepath.Join(append([]string{c}, rest...)...)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return path
		}
		rest = append([]string{filepath.Base(p)}, rest...)
		p = parent
	}
}

// criticalSet lists folders whose ACL SecureDataDir must never replace.
type criticalSet struct {
	trees []string // refused: the folder, anything inside it and any folder containing it
	dirs  []string // refused: the folder and any folder containing it
}

// criticalDirsFunc returns the folders to protect (a variable so tests can use temporary
// stand-ins; tests never point SecureDataDir at real system folders).
var criticalDirsFunc = criticalDirs

// criticalDirs collects the Windows folder (a tree) and Program Files, ProgramData, the Users
// folder, the public and current user's profiles (folders), from the known-folder API and the
// environment, each also in canonical form.
func criticalDirs() criticalSet {
	var cs criticalSet
	add := func(list *[]string, p string) {
		p = strings.TrimSpace(p)
		if p == "" || !filepath.IsAbs(p) {
			return
		}
		for _, q := range []string{filepath.Clean(p), resolvedPath(p)} {
			if !slices.ContainsFunc(*list, func(d string) bool { return strings.EqualFold(d, q) }) {
				*list = append(*list, q)
			}
		}
	}
	known := func(id *windows.KNOWNFOLDERID) string {
		p, err := windows.KnownFolderPath(id, 0)
		if err != nil {
			return ""
		}
		return p
	}
	for _, p := range []string{known(windows.FOLDERID_Windows), os.Getenv("SystemRoot"), os.Getenv("windir")} {
		add(&cs.trees, p)
	}
	for _, id := range []*windows.KNOWNFOLDERID{
		windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86, windows.FOLDERID_ProgramData,
		windows.FOLDERID_UserProfiles, windows.FOLDERID_Public, windows.FOLDERID_Profile,
	} {
		add(&cs.dirs, known(id))
	}
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData",
		"ALLUSERSPROFILE", "PUBLIC", "USERPROFILE"} {
		add(&cs.dirs, os.Getenv(env))
	}
	return cs
}

// checkNotCritical refuses a volume root, a critical folder, a folder containing one, and
// anything inside a critical tree.
func checkNotCritical(path string, cs criticalSet) error {
	p := filepath.Clean(path)
	if isVolumeRoot(p) {
		return fmt.Errorf("winsvc: refusing to change the ACL of %s: it is the root of a volume", p)
	}
	for _, d := range cs.trees {
		if within(p, d) || within(d, p) {
			return fmt.Errorf("winsvc: refusing to change the ACL of %s: it is, contains or is inside the system folder %s", p, d)
		}
	}
	for _, d := range cs.dirs {
		if within(d, p) {
			return fmt.Errorf("winsvc: refusing to change the ACL of %s: it is or contains the protected folder %s", p, d)
		}
	}
	return nil
}

// isVolumeRoot reports whether p is "C:\", "\\server\share\" or similar.
func isVolumeRoot(p string) bool {
	vol := filepath.VolumeName(p)
	rest := strings.Trim(p[len(vol):], `\/`)
	return rest == ""
}

// within reports whether path is dir or inside it (case-insensitive, Windows separators).
func within(path, dir string) bool {
	p := strings.ToLower(filepath.Clean(path))
	d := strings.ToLower(filepath.Clean(dir))
	if p == d {
		return true
	}
	if !strings.HasSuffix(d, `\`) {
		d += `\`
	}
	return strings.HasPrefix(p, d)
}

// checkDataDirEntries refuses a directory holding entries that are not part of the
// att-monitor data-directory layout: re-permissioning someone's other files would be
// destructive.
func checkDataDirEntries(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("winsvc: list %s: %w", dir, err)
	}
	var foreign []string
	for _, e := range entries {
		if !isDataDirEntry(e.Name()) {
			foreign = append(foreign, fmt.Sprintf("%q", e.Name()))
		}
	}
	if len(foreign) == 0 {
		return nil
	}
	more := ""
	if len(foreign) > 5 {
		more = fmt.Sprintf(" and %d more", len(foreign)-5)
		foreign = foreign[:5]
	}
	return fmt.Errorf("winsvc: refusing to change the ACL of %s: it holds entries that are not part of "+
		"an att-monitor data directory (%s%s); use a new or empty directory", dir, strings.Join(foreign, ", "), more)
}

func isDataDirEntry(name string) bool {
	n := strings.ToLower(name)
	for _, e := range dataDirEntries {
		if n == e {
			return true
		}
	}
	return strings.HasPrefix(n, "config.json.")
}
