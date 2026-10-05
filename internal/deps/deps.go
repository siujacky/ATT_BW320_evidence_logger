//go:build tools

// Package deps pins the approved third-party modules (docs/DESIGN.md §4) in go.mod so that
// packages can be developed in parallel without anyone running `go get` / `go mod tidy`.
package deps

import (
	_ "github.com/digitorus/pkcs7"
	_ "github.com/digitorus/timestamp"
	_ "golang.org/x/net/dns/dnsmessage"
	_ "golang.org/x/sys/windows"
	_ "golang.org/x/sys/windows/registry"
	_ "golang.org/x/sys/windows/svc"
	_ "golang.org/x/sys/windows/svc/eventlog"
	_ "golang.org/x/sys/windows/svc/mgr"
)
