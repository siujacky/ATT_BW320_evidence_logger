package mongostore

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Defaults for Options.URI and Options.Database.
const (
	DefaultURI      = "mongodb://127.0.0.1:27017"
	DefaultDatabase = "attmonitor"
)

const (
	schemeMongo = "mongodb://"
	schemeSRV   = "mongodb+srv://"
)

// checkURI validates uri without any network access. A "mongodb+srv://" URI is only checked for
// its form: the driver resolves its DNS records while parsing it, which is left to the connection
// attempts (so that a DNS failure is retried instead of failing New).
func checkURI(uri string) error {
	switch {
	case strings.HasPrefix(uri, schemeMongo):
		if err := options.Client().ApplyURI(uri).Validate(); err != nil {
			return uriError(uri, err)
		}
		return nil
	case strings.HasPrefix(uri, schemeSRV):
		host := uri[len(schemeSRV):]
		if i := strings.IndexByte(host, '@'); i >= 0 {
			host = host[i+1:]
		}
		if i := strings.IndexAny(host, "/?"); i >= 0 {
			host = host[:i]
		}
		if host == "" || strings.ContainsAny(host, ",:@") {
			return errors.New("mongostore: a mongodb+srv URI must name exactly one host, without a port")
		}
		return nil
	default:
		return errors.New(`mongostore: the MongoDB URI must start with "mongodb://" or "mongodb+srv://"`)
	}
}

// uriError reports an invalid URI without revealing credentials.
func uriError(uri string, err error) error {
	if hasCredentials(uri) {
		return errors.New("mongostore: invalid MongoDB URI (details withheld because the URI contains credentials)")
	}
	return fmt.Errorf("mongostore: invalid MongoDB URI %s: %v", uri, err)
}

// connectError reports a failure of mongo.Connect without revealing credentials: the driver
// parses the URI there (a mongodb+srv URI only there, after resolving its DNS records), and its
// parse errors quote option values.
func connectError(uri string, err error) error {
	if hasCredentials(uri) {
		return errors.New("the MongoDB URI cannot be used (details withheld because the URI contains credentials)")
	}
	return err
}

// hasCredentials reports whether uri may carry a secret: user information or an option that
// carries a secret.
func hasCredentials(uri string) bool { return strings.Contains(uri, "@") || hasSecretOption(uri) }

// secretOption reports whether a URI option carries a secret.
func secretOption(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.Contains(k, "token") ||
		k == "authmechanismproperties"
}

// isOptionSep reports whether c separates URI options: the driver accepts "&" and ";".
func isOptionSep(c rune) bool { return c == '&' || c == ';' }

// secretPair reports whether the URI option kv ("key=value") carries a secret. The key is
// unescaped as the driver does; a key that cannot be unescaped counts as secret.
func secretPair(kv string) bool {
	k, _, _ := strings.Cut(kv, "=")
	key, err := url.QueryUnescape(k)
	return err != nil || secretOption(key)
}

func hasSecretOption(uri string) bool {
	_, query, ok := strings.Cut(uri, "?")
	if !ok {
		return false
	}
	for _, kv := range strings.FieldsFunc(query, isOptionSep) {
		if secretPair(kv) {
			return true
		}
	}
	return false
}

// RedactURI returns uri with its credentials removed: the user information and the values of
// options that carry secrets (passwords, tokens, authMechanismProperties). A string that is not a
// MongoDB URI is replaced by a placeholder rather than echoed.
func RedactURI(uri string) string {
	var scheme string
	switch {
	case strings.HasPrefix(uri, schemeMongo):
		scheme = schemeMongo
	case strings.HasPrefix(uri, schemeSRV):
		scheme = schemeSRV
	default:
		return "(not a MongoDB URI)"
	}
	rest := uri[len(scheme):]
	// Like the driver, end the user information at the first "@". A malformed URI may hold an
	// unescaped "@" in its password: then the host list (up to the next "/" or "?") would still
	// contain "@", and everything up to the last one there is removed too.
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
		hosts := rest
		if j := strings.IndexAny(hosts, "/?"); j >= 0 {
			hosts = hosts[:j]
		}
		if k := strings.LastIndexByte(hosts, '@'); k >= 0 {
			rest = rest[k+1:]
		}
	}
	base, query, hasQuery := strings.Cut(rest, "?")
	if !hasQuery {
		return scheme + base
	}
	var b strings.Builder
	b.WriteString(scheme + base + "?")
	start := 0
	for i, c := range query + "&" {
		if !isOptionSep(c) {
			continue
		}
		kv := query[start:i]
		if k, _, ok := strings.Cut(kv, "="); ok && secretPair(kv) {
			kv = k + "=***"
		}
		b.WriteString(kv)
		if i < len(query) {
			b.WriteByte(query[i])
		}
		start = i + 1
	}
	return b.String()
}

// checkDatabaseName applies MongoDB's database name rules on Windows.
func checkDatabaseName(name string) error {
	if name == "" || len(name) > 63 || strings.ContainsAny(name, "/\\.\"$*<>:|? \x00") {
		return fmt.Errorf("mongostore: invalid database name %q (1-63 characters without spaces or any of /\\.\"$*<>:|?)", clip(name, 80))
	}
	return nil
}

// clientOptions configures a client: Options.ConnectTimeout bounds connecting and selecting a
// server (so that operations fail fast while MongoDB is down); settings in the URI take
// precedence.
func clientOptions(uri string, timeout time.Duration) *options.ClientOptions {
	return options.Client().
		SetConnectTimeout(timeout).
		SetServerSelectionTimeout(timeout).
		SetAppName("att-monitor").
		ApplyURI(uri)
}
