// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package config reads what an operator sets: every PONS_* variable of
// specs/011-distribution.md, once, at start, into one typed value. No other
// package of the module reads the environment.
//
// A value that does not parse is an error that names its variable and never
// its value: a variable may hold a secret, and PONS_SEALING_KEYS always
// does. The refusals at start that need nothing but the settings are made
// here too, so a server that cannot run says so before it opens anything.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The defaults of the table of specs/011-distribution.md.
const (
	DefaultAddr                   = ":8080"
	DefaultBasePath               = "/v1"
	DefaultAudience               = "pons"
	DefaultClientName             = "Pons"
	DefaultRecordsRetention       = 720 * time.Hour
	DefaultMaxConnectionsPerOwner = 100
	DefaultCreatesPerMinute       = 10
	DefaultMaxInflightPerSubject  = 32
	DefaultMaxInflight            = 1024
	DefaultMaxRequestBytes        = 4 << 20
	DefaultCallHeaderTimeout      = 30 * time.Second
	DefaultStreamIdleTimeout      = 5 * time.Minute
)

// KeySize is the length of a sealing key in bytes.
const KeySize = 32

// Settings are the settings of the process.
type Settings struct {
	Addr string // PONS_ADDR
	// PublicURL is the origin, and the path prefix a proxy in front adds,
	// that other services and browsers reach Pons at, with no trailing
	// slash. Every address Pons hands out starts with it.
	PublicURL string // PONS_PUBLIC_URL
	// BasePath is the prefix of every route of the API: empty, or a path
	// that starts with a slash and does not end with one.
	BasePath string // PONS_BASE_PATH

	// DatabaseURL is the direct endpoint of the database: migrations run
	// over it, because the migrator holds a session lock across its
	// statements. DatabasePoolURL is the endpoint the serving pool opens, a
	// transaction-mode pooler's where an installation has one. Both carry a
	// password and are never logged.
	DatabaseURL     string // PONS_DATABASE_URL
	DatabasePoolURL string // PONS_DATABASE_POOL_URL

	// SealingKeys are the keys a credential is sealed under, the first
	// one wrapping.
	SealingKeys []SealingKey // PONS_SEALING_KEYS

	// OIDCIssuers are the issuers whose tokens are accepted, each without
	// a trailing slash. OIDCAudiences are the audiences a token may be
	// addressed to, the first the primary one.
	OIDCIssuers   []string // PONS_OIDC_ISSUERS
	OIDCAudiences []string // PONS_OIDC_AUDIENCE

	// AuthorizerURL is the endpoint that is asked what a caller may do,
	// and AuthorizerToken the bearer it requires, read once from the file
	// AuthorizerTokenFile names. With no URL the owner policy decides.
	AuthorizerURL       string // PONS_AUTHORIZER_URL
	AuthorizerTokenFile string // PONS_AUTHORIZER_TOKEN_FILE
	AuthorizerToken     Secret

	CatalogFile string   // PONS_CATALOG_FILE
	ReturnURLs  []string // PONS_RETURN_URLS
	ClientName  string   // PONS_CLIENT_NAME
	ClientURI   string   // PONS_CLIENT_URI

	RecordsRetention time.Duration // PONS_RECORDS_RETENTION

	MaxConnectionsPerOwner int // PONS_MAX_CONNECTIONS_PER_OWNER
	CreatesPerMinute       int // PONS_CREATES_PER_MINUTE
	MaxInflightPerSubject  int // PONS_MAX_INFLIGHT_PER_SUBJECT
	MaxInflight            int // PONS_MAX_INFLIGHT

	MaxRequestBytes   int64         // PONS_MAX_REQUEST_BYTES
	CallHeaderTimeout time.Duration // PONS_CALL_HEADER_TIMEOUT
	StreamIdleTimeout time.Duration // PONS_STREAM_IDLE_TIMEOUT

	// OutboundProxy, when set, is the operator's proxy every request of
	// the outside client is tunneled through.
	OutboundProxy *url.URL // PONS_OUTBOUND_PROXY
	// DialAllowPrivate treats every address as public and allows every
	// port, for a server run against stubs on loopback.
	DialAllowPrivate bool // PONS_DIAL_ALLOW_PRIVATE
}

// Durable reports whether the settings name a database. Without one the
// server runs on the memory store.
func (s Settings) Durable() bool { return s.DatabaseURL != "" }

// ServingURL is the URL the serving pool opens: the pooled one when it is
// set, and the direct one otherwise.
func (s Settings) ServingURL() string {
	if s.DatabasePoolURL != "" {
		return s.DatabasePoolURL
	}
	return s.DatabaseURL
}

// Secret is a value that is never printed: a formatted, logged or encoded
// Secret shows a placeholder.
type Secret struct{ value string }

// NewSecret wraps a value.
func NewSecret(v string) Secret { return Secret{value: v} }

// Reveal is the value, for the one call that sends it.
func (s Secret) Reveal() string { return s.value }

// Empty reports whether there is no value.
func (s Secret) Empty() bool { return s.value == "" }

const redacted = "[redacted]"

func (s Secret) String() string { return redacted }

// GoString keeps %#v from printing the value.
func (s Secret) GoString() string { return redacted }

// LogValue keeps a structured log line from printing the value.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// SealingKey is one key of PONS_SEALING_KEYS. It prints as a placeholder.
type SealingKey [KeySize]byte

func (k SealingKey) String() string { return redacted }

// GoString keeps %#v from printing the key.
func (k SealingKey) GoString() string { return redacted }

// LogValue keeps a structured log line from printing the key.
func (k SealingKey) LogValue() slog.Value { return slog.StringValue(redacted) }

// FromEnv reads the settings. getenv is os.Getenv, or a test's own. Every
// problem is reported, each naming its variable and never its value.
func FromEnv(getenv func(string) string) (Settings, error) {
	s := Settings{
		Addr: DefaultAddr, BasePath: DefaultBasePath,
		OIDCAudiences: []string{DefaultAudience}, ClientName: DefaultClientName,
		RecordsRetention:       DefaultRecordsRetention,
		MaxConnectionsPerOwner: DefaultMaxConnectionsPerOwner, CreatesPerMinute: DefaultCreatesPerMinute,
		MaxInflightPerSubject: DefaultMaxInflightPerSubject, MaxInflight: DefaultMaxInflight,
		MaxRequestBytes: DefaultMaxRequestBytes, CallHeaderTimeout: DefaultCallHeaderTimeout,
		StreamIdleTimeout: DefaultStreamIdleTimeout,
	}
	r := reader{getenv: getenv}

	if v := r.text("PONS_ADDR"); v != "" {
		s.Addr = v
	}
	s.PublicURL = r.publicURL("PONS_PUBLIC_URL")
	if v, ok := r.lookup("PONS_BASE_PATH"); ok {
		s.BasePath = r.basePath("PONS_BASE_PATH", v)
	}
	s.DatabaseURL = strings.TrimSpace(getenv("PONS_DATABASE_URL"))
	s.DatabasePoolURL = strings.TrimSpace(getenv("PONS_DATABASE_POOL_URL"))
	s.SealingKeys = r.keys("PONS_SEALING_KEYS")
	s.OIDCIssuers = r.issuers("PONS_OIDC_ISSUERS")
	if v := r.list("PONS_OIDC_AUDIENCE"); len(v) > 0 {
		s.OIDCAudiences = v
	}
	s.AuthorizerURL = r.httpURL("PONS_AUTHORIZER_URL")
	s.AuthorizerTokenFile = r.text("PONS_AUTHORIZER_TOKEN_FILE")
	s.CatalogFile = r.text("PONS_CATALOG_FILE")
	s.ReturnURLs = r.returnURLs("PONS_RETURN_URLS")
	if v := r.text("PONS_CLIENT_NAME"); v != "" {
		s.ClientName = v
	}
	s.ClientURI = r.httpURL("PONS_CLIENT_URI")
	r.duration("PONS_RECORDS_RETENTION", &s.RecordsRetention)
	r.count("PONS_MAX_CONNECTIONS_PER_OWNER", &s.MaxConnectionsPerOwner)
	r.count("PONS_CREATES_PER_MINUTE", &s.CreatesPerMinute)
	r.count("PONS_MAX_INFLIGHT_PER_SUBJECT", &s.MaxInflightPerSubject)
	r.count("PONS_MAX_INFLIGHT", &s.MaxInflight)
	r.size("PONS_MAX_REQUEST_BYTES", &s.MaxRequestBytes)
	r.duration("PONS_CALL_HEADER_TIMEOUT", &s.CallHeaderTimeout)
	r.duration("PONS_STREAM_IDLE_TIMEOUT", &s.StreamIdleTimeout)
	s.OutboundProxy = r.proxy("PONS_OUTBOUND_PROXY")
	s.DialAllowPrivate = r.flag("PONS_DIAL_ALLOW_PRIVATE")

	r.errs = append(r.errs, s.refusals()...)
	if len(r.errs) > 0 {
		return Settings{}, errors.Join(r.errs...)
	}
	if s.AuthorizerURL != "" {
		token, err := readToken(s.AuthorizerTokenFile)
		if err != nil {
			return Settings{}, err
		}
		s.AuthorizerToken = token
	}
	return s, nil
}

// refusals are the cases of specs/011-distribution.md that stop the start
// and need nothing but the settings.
func (s Settings) refusals() []error {
	var errs []error
	if s.PublicURL == "" {
		errs = append(errs, errors.New("PONS_PUBLIC_URL is not set: name the address other services and browsers reach this server at"))
	}
	if len(s.OIDCIssuers) == 0 {
		errs = append(errs, errors.New("PONS_OIDC_ISSUERS is not set: name the issuers whose tokens this server accepts"))
	}
	if s.Durable() {
		if s.PublicURL != "" && !strings.HasPrefix(s.PublicURL, "https://") {
			errs = append(errs, errors.New("PONS_PUBLIC_URL is not https: a server with a database hands out its callback and its addresses, which carry codes and bearers, over https alone"))
		}
		if len(s.SealingKeys) == 0 {
			errs = append(errs, errors.New("PONS_SEALING_KEYS is not set: a server with a database seals every credential it keeps"))
		}
	} else if s.DatabasePoolURL != "" {
		errs = append(errs, errors.New("PONS_DATABASE_POOL_URL is set and PONS_DATABASE_URL is not: the migrations need the direct address"))
	}
	if s.AuthorizerURL == "" && s.AuthorizerTokenFile != "" {
		errs = append(errs, errors.New("PONS_AUTHORIZER_TOKEN_FILE is set and PONS_AUTHORIZER_URL is not: name the endpoint the bearer is for"))
	}
	return errs
}

// readToken reads the authorizer's bearer from its file, once. The error
// names the variable, never the file's content.
func readToken(path string) (Secret, error) {
	if path == "" {
		return Secret{}, errors.New("PONS_AUTHORIZER_TOKEN_FILE is not set: the authorizer at PONS_AUTHORIZER_URL takes a bearer, read from that file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Secret{}, errors.New("PONS_AUTHORIZER_TOKEN_FILE names a file that cannot be read")
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return Secret{}, errors.New("PONS_AUTHORIZER_TOKEN_FILE names an empty file")
	}
	return NewSecret(token), nil
}

// reader reads variables and collects what does not parse.
type reader struct {
	getenv func(string) string
	errs   []error
}

func (r *reader) fail(name, why string) { r.errs = append(r.errs, fmt.Errorf("%s %s", name, why)) }

// lookup is a variable's value, trimmed, and whether it was set at all.
func (r *reader) lookup(name string) (string, bool) {
	raw := r.getenv(name)
	return strings.TrimSpace(raw), raw != ""
}

func (r *reader) text(name string) string {
	v, _ := r.lookup(name)
	return v
}

// list is a comma-separated list, each entry trimmed and empty ones
// dropped.
func (r *reader) list(name string) []string {
	var out []string
	for entry := range strings.SplitSeq(r.text(name), ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, entry)
		}
	}
	return out
}

func (r *reader) count(name string, into *int) {
	v := r.text(name)
	if v == "" {
		return
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		r.fail(name, "is not a whole number above zero")
		return
	}
	*into = n
}

func (r *reader) size(name string, into *int64) {
	v := r.text(name)
	if v == "" {
		return
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 {
		r.fail(name, "is not a whole number of bytes above zero")
		return
	}
	*into = n
}

func (r *reader) duration(name string, into *time.Duration) {
	v := r.text(name)
	if v == "" {
		return
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		r.fail(name, "is not a duration above zero, such as 30s or 720h")
		return
	}
	*into = d
}

func (r *reader) flag(name string) bool {
	v := r.text(name)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		r.fail(name, "is not 1, 0, true or false")
		return false
	}
	return b
}

// absolute parses an absolute http or https URL with a host and no user
// part. The parse error is not kept: it quotes the value.
func absolute(v string) (*url.URL, bool) {
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Opaque != "" {
		return nil, false
	}
	return u, true
}

func (r *reader) httpURL(name string) string {
	v := r.text(name)
	if v == "" {
		return ""
	}
	if _, ok := absolute(v); !ok {
		r.fail(name, "is not an http or https URL with a host and no user part")
		return ""
	}
	return v
}

func (r *reader) publicURL(name string) string {
	v := r.text(name)
	if v == "" {
		return ""
	}
	u, ok := absolute(v)
	if !ok || u.RawQuery != "" || u.Fragment != "" {
		r.fail(name, "is not an http or https URL with a host, and no user part, query or fragment")
		return ""
	}
	return strings.TrimRight(v, "/")
}

func (r *reader) basePath(name, v string) string {
	v = strings.TrimRight(v, "/")
	if v != "" && (!strings.HasPrefix(v, "/") || strings.ContainsAny(v, "?#{}") || strings.Contains(v, "//")) {
		r.fail(name, "is not a path that begins with a slash")
		return DefaultBasePath
	}
	return v
}

func (r *reader) issuers(name string) []string {
	var out []string
	for _, v := range r.list(name) {
		u, ok := absolute(v)
		if !ok || u.RawQuery != "" || u.Fragment != "" {
			r.fail(name, "has an entry that is not an http or https URL with a host")
			return nil
		}
		issuer := strings.TrimRight(v, "/")
		if slices.Contains(out, issuer) {
			r.fail(name, "lists an issuer twice")
			return nil
		}
		out = append(out, issuer)
	}
	return out
}

func (r *reader) returnURLs(name string) []string {
	var out []string
	for _, v := range r.list(name) {
		u, ok := absolute(v)
		if !ok || u.Fragment != "" || strings.Contains(v, "#") {
			r.fail(name, "has an entry that is not an http or https URL with a host and no user part or fragment")
			return nil
		}
		out = append(out, v)
	}
	return out
}

func (r *reader) proxy(name string) *url.URL {
	v := r.text(name)
	if v == "" {
		return nil
	}
	u, ok := absolute(v)
	if !ok {
		// A proxy URL may carry a user and a password, so the check is
		// made again without the user rule and still names no value.
		parsed, err := url.Parse(v)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			r.fail(name, "is not an http or https URL with a host")
			return nil
		}
		u = parsed
	}
	return u
}

// keys reads the sealing keys: a comma list of 32 bytes each, in base64 of
// either alphabet, padded or not. An entry is named by its position and
// never by its value.
func (r *reader) keys(name string) []SealingKey {
	v := r.text(name)
	if v == "" {
		return nil
	}
	var out []SealingKey
	for i, entry := range strings.Split(v, ",") {
		key, ok := decodeKey(strings.TrimSpace(entry))
		if !ok {
			r.fail(name, fmt.Sprintf("has an entry at position %d that is not %d bytes in base64", i+1, KeySize))
			return nil
		}
		if j := slices.Index(out, key); j >= 0 {
			r.fail(name, fmt.Sprintf("lists the key at position %d again at position %d", j+1, i+1))
			return nil
		}
		out = append(out, key)
	}
	return out
}

// decodeKey decodes one key in any of the four forms of base64.
func decodeKey(entry string) (SealingKey, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(entry)
		if err == nil && len(b) == KeySize {
			return SealingKey(b), true
		}
	}
	return SealingKey{}, false
}

// Variables lists every variable FromEnv reads, in the order of the table
// of specs/011-distribution.md.
func Variables() []string {
	var names []string
	seen := map[string]bool{}
	record := func(name string) string {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
		return ""
	}
	// The read fails on the missing required variables, which is what an
	// empty environment is; the names it asked for are the answer.
	_, _ = FromEnv(record)
	return names
}
