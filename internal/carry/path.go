// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"net/http"
	"net/url"
	"strings"
)

// The addresses of a connection of kind http (specs/014-http-forwarding.md).
const (
	// AddressHTTP is the forwarding address, toward the connector's url.
	AddressHTTP = "http"
	// AddressGit is the git address, toward the connector's git.url.
	AddressGit = "git"
)

// The git services a git address serves, which are what its requests name
// as their tool.
const (
	UploadPack  = "git-upload-pack"
	ReceivePack = "git-receive-pack"
)

// MaxPathBytes bounds the path a forwarded request names.
const MaxPathBytes = 2048

// target is where one request is forwarded: the path below the address, in
// its escaped and its decoded form, without its query.
type target struct {
	raw     string // as the caller escaped it, no leading slash
	decoded string
}

// checkPath holds a forwarded path to its connector (specs/014-http-forwarding.md):
// no dot segment, no empty segment, no backslash, no encoded slash,
// backslash or dot segment, no control character, and at most 2048 bytes.
// tail is the escaped path after the address, empty or starting with a
// slash. It answers why not, or "".
func checkPath(tail string) (target, string) {
	raw := strings.TrimPrefix(tail, "/")
	if raw == "" {
		return target{}, ""
	}
	if len(raw) > MaxPathBytes {
		return target{}, "path_too_long"
	}
	var decoded []string
	for seg := range strings.SplitSeq(raw, "/") {
		lower := strings.ToLower(seg)
		switch {
		case seg == "":
			return target{}, "empty_segment"
		case strings.Contains(seg, `\`), strings.Contains(lower, "%2f"), strings.Contains(lower, "%5c"):
			return target{}, "encoded_separator"
		}
		d, err := url.PathUnescape(seg)
		if err != nil {
			return target{}, "not_escaped"
		}
		if d == "." || d == ".." {
			return target{}, "dot_segment"
		}
		for i := range len(d) {
			if d[i] < 0x20 || d[i] == 0x7f {
				return target{}, "control_character"
			}
		}
		decoded = append(decoded, d)
	}
	return target{raw: raw, decoded: strings.Join(decoded, "/")}, ""
}

// join is the connector's base with the path and the query: the base's
// scheme, host and port, its path with the request's below it.
func join(base string, t target, query string) (*url.URL, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	if t.raw != "" {
		u.RawPath = strings.TrimSuffix(u.EscapedPath(), "/") + "/" + t.raw
		u.Path = strings.TrimSuffix(u.Path, "/") + "/" + t.decoded
	}
	u.RawQuery = query
	u.Fragment, u.RawFragment = "", ""
	return u, nil
}

// gitService is the service a request to a git address names: a ref
// advertisement, GET of .../info/refs with service set, or a POST to the
// service itself. Any other request is no request of git's smart HTTP, and
// answers "".
func gitService(r *http.Request, t target) string {
	switch {
	case strings.HasSuffix("/"+t.decoded, "/info/refs") && r.Method == http.MethodGet:
		if s := r.URL.Query().Get("service"); s == UploadPack || s == ReceivePack {
			return s
		}
	case strings.HasSuffix("/"+t.decoded, "/"+UploadPack) && r.Method == http.MethodPost:
		return UploadPack
	case strings.HasSuffix("/"+t.decoded, "/"+ReceivePack) && r.Method == http.MethodPost:
		return ReceivePack
	}
	return ""
}
