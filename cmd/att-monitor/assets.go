package main

import _ "embed"

// tsaRootsPEM holds the root certificates of the default Time-Stamp Authorities (DigiCert
// Trusted Root G4 and the FreeTSA root CA). It is shipped in every evidence bundle as
// keys/tsa-roots.pem so a third party can run
//
//	openssl ts -verify -attime <genTime> -digest <head_hash> -in blobs/<token> -CAfile keys/tsa-roots.pem
//
// without trusting this software. Both tokens in testdata/tsa verify against it.
//
//go:embed assets/tsa-roots.pem
var tsaRootsPEM []byte
