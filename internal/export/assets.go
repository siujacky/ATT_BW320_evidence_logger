package export

import _ "embed"

// verifyScript is the standalone third-party verifier copied into every bundle as
// tools/verify_bundle.py (Python >= 3.9, standard library only).
//
//go:embed assets/verify_bundle.py
var verifyScript []byte
