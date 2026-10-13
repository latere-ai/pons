// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"net/http"
	"net/url"
	"strings"

	"latere.ai/x/pons/catalog"
)

// The headers that pass toward the connector (specs/014-http-forwarding.md).
// Everything else is removed, the caller's Authorization first. The length
// is the request's own and the body's framing is the transport's.
var (
	towardHTTP = []string{"Accept", "Accept-Encoding", "Content-Type", "If-None-Match", "If-Modified-Since", "Range"}
	towardGit  = []string{"Accept", "Accept-Encoding", "Content-Type", "Git-Protocol"}
)

// back are the headers that pass back to the caller beside a connector's
// pass_back globs. Set-Cookie and WWW-Authenticate never do; Link and
// Location pass rewritten.
var back = []string{"Content-Type", "Content-Length", "Content-Encoding", "Cache-Control", "ETag", "Last-Modified", "Retry-After"}

// neverBack are the headers that never pass back, whatever a glob says.
var neverBack = []string{"Set-Cookie", "Www-Authenticate", "Link", "Location", "Connection", "Keep-Alive",
	"Proxy-Authenticate", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// toward copies the headers a request may carry toward the connector.
func toward(in http.Header, conn catalog.Connector, address, service string) http.Header {
	names := towardHTTP
	if address == AddressGit {
		names = towardGit
		if service == UploadPack {
			// A fetch's body may be compressed by git; a push's never is.
			names = append(names[:len(names):len(names)], "Content-Encoding")
		}
	} else if conn.HTTP != nil {
		names = append(names[:len(names):len(names)], conn.HTTP.Pass...)
	}
	out := http.Header{}
	for _, name := range names {
		if v := in.Values(name); len(v) > 0 {
			out[http.CanonicalHeaderKey(name)] = append([]string(nil), v...)
		}
	}
	if out.Get("Accept-Encoding") == "" {
		// The connector's encoding passes through unread, so nothing is
		// asked of it that the transport would undo on the way.
		out.Set("Accept-Encoding", "identity")
	}
	return out
}

// backward copies the headers of an answer that pass back to the caller.
func backward(dst, src http.Header, conn catalog.Connector) {
	var globs []string
	if conn.HTTP != nil {
		globs = conn.HTTP.PassBack
	}
	for name, values := range src {
		canonical := http.CanonicalHeaderKey(name)
		if containsFold(neverBack, canonical) {
			continue
		}
		if containsFold(back, canonical) || matchFold(globs, canonical) {
			dst[canonical] = append([]string(nil), values...)
		}
	}
}

func containsFold(names []string, name string) bool {
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// matchFold matches a header name against globs without regard to case.
func matchFold(globs []string, name string) bool {
	lower := strings.ToLower(name)
	for _, g := range globs {
		if catalog.Glob(strings.ToLower(g), lower) {
			return true
		}
	}
	return false
}

// under reports whether u is the base or an address below it, at a boundary
// of the path, so a base is not a prefix of another host's name.
func under(u, base string) bool {
	base = strings.TrimSuffix(base, "/")
	if !strings.HasPrefix(u, base) {
		return false
	}
	rest := u[len(base):]
	return rest == "" || strings.ContainsRune("/?#", rune(rest[0]))
}

// moved is u with the base replaced by the address.
func moved(u, base, address string) string {
	return address + strings.TrimPrefix(u, strings.TrimSuffix(base, "/"))
}

// rewriteLinks is a Link header with each URL under the base moved under the
// address, and every other entry dropped: the one change Pons makes to an
// answer, so a caller that follows the next page stays on Pons. It answers
// "" when no entry is left.
func rewriteLinks(values []string, base, address string) string {
	var kept []string
	for _, v := range values {
		for _, entry := range splitLinks(v) {
			lt, gt := strings.IndexByte(entry, '<'), strings.IndexByte(entry, '>')
			if lt != 0 || gt < 0 {
				continue
			}
			u := entry[1:gt]
			if !under(u, base) {
				continue
			}
			kept = append(kept, "<"+moved(u, base, address)+">"+entry[gt+1:])
		}
	}
	return strings.Join(kept, ", ")
}

// splitLinks splits a Link header into its entries: at a comma that is
// outside the angle brackets of a URL and outside a quoted parameter.
func splitLinks(v string) []string {
	var out []string
	inURL, inQuote, start := false, false, 0
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '<' && !inQuote:
			inURL = true
		case c == '>' && !inQuote:
			inURL = false
		case c == '"' && !inURL:
			inQuote = !inQuote
		case c == ',' && !inURL && !inQuote:
			out = append(out, strings.TrimSpace(v[start:i]))
			start = i + 1
		}
	}
	return append(out, strings.TrimSpace(v[start:]))
}

// location is the address a redirect names, resolved against the request it
// answers, moved under the address when it is under the base. ok is false
// for a redirect elsewhere.
func location(raw string, from *url.URL, base, address string) (string, bool) {
	ref, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	abs := from.ResolveReference(ref).String()
	if !under(abs, base) {
		return "", false
	}
	return moved(abs, base, address), true
}
