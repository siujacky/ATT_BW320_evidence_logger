//go:build windows

// Package secret wraps Windows DPAPI (CryptProtectData / CryptUnprotectData).
//
// Machine scope (CRYPTPROTECT_LOCAL_MACHINE) lets the LocalSystem service and an elevated
// administrator decrypt the same blob; file ACLs on the data directory restrict who can read it.
package secret

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	cryptprotectUIForbidden  = 0x1
	cryptprotectLocalMachine = 0x4
)

// Protect encrypts data. machine selects machine scope instead of the current user's scope.
func Protect(data, entropy []byte, machine bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("secret: nothing to protect")
	}
	flags := uint32(cryptprotectUIForbidden)
	if machine {
		flags |= cryptprotectLocalMachine
	}
	in := blobOf(data)
	var out windows.DataBlob
	if err := windows.CryptProtectData(in, nil, blobOf(entropy), 0, nil, flags, &out); err != nil {
		return nil, fmt.Errorf("secret: CryptProtectData: %w", err)
	}
	return takeBlob(&out), nil
}

// Unprotect decrypts a blob produced by Protect with the same entropy.
func Unprotect(blob, entropy []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("secret: empty blob")
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blobOf(blob), nil, blobOf(entropy), 0, nil, cryptprotectUIForbidden, &out); err != nil {
		return nil, fmt.Errorf("secret: CryptUnprotectData: %w", err)
	}
	return takeBlob(&out), nil
}

func blobOf(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return nil
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func takeBlob(b *windows.DataBlob) []byte {
	if b.Data == nil {
		return nil
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	out := make([]byte, b.Size)
	copy(out, unsafe.Slice(b.Data, b.Size))
	return out
}
