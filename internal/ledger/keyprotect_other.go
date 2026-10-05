//go:build !windows

package ledger

import "errors"

var errNoDPAPI = errors.New("ledger: DPAPI key protection is only available on Windows (inject KeyProtect/KeyUnprotect)")

func defaultKeyProtect(seed []byte) ([]byte, error) { return nil, errNoDPAPI }

func defaultKeyUnprotect(blob []byte) ([]byte, error) { return nil, errNoDPAPI }
