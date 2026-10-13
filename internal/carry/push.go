// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/internal/apierr"
)

// The bounds of a push's commands (specs/014-http-forwarding.md).
const (
	// MaxCommandBytes bounds what is read of a push before its pack.
	MaxCommandBytes = 64 << 10
	// MaxCommands bounds how many refs one push names.
	MaxCommands = 1000
)

// errCommands is a push whose commands do not parse or run past a bound.
var errCommands = errors.New("carry: the push's commands do not parse")

// command is one ref a push updates: its old and new object ids and its full
// name. A new id of zeros deletes the ref.
type command struct {
	Old, New, Ref string
}

// pushHead is what a git-receive-pack request names before its pack.
type pushHead struct {
	commands []command
	// caps are the capabilities the client asked for after the first
	// command's NUL, such as report-status and side-band-64k.
	caps []string
	// read is every byte read, which the forwarded body begins with again.
	read []byte
}

// refs are the full names of the refs the push updates, in its order.
func (h pushHead) refs() []string {
	out := make([]string, len(h.commands))
	for i, c := range h.commands {
		out[i] = c.Ref
	}
	return out
}

// readCommands reads the commands that begin a git-receive-pack request:
// any shallow lines, one pkt-line per ref, the first followed by a NUL and
// the client's capabilities, then a flush-pkt. It answers the commands, the
// capabilities and every byte it read; the pack after them is not read.
//
// A body that is a flush-pkt and nothing else is git's probe: before a push
// larger than its post buffer, git sends one to learn that the address
// answers, and then the push itself. It names no ref, and is read as no
// commands. A flush-pkt followed by anything is not a probe.
func readCommands(body io.Reader) (pushHead, error) {
	var read bytes.Buffer
	var out []command
	var caps []string
	for {
		if read.Len() > MaxCommandBytes {
			return pushHead{}, errCommands
		}
		var size [4]byte
		if _, err := io.ReadFull(body, size[:]); err != nil {
			return pushHead{}, errCommands
		}
		read.Write(size[:])
		n, err := strconv.ParseUint(string(size[:]), 16, 16)
		if err != nil {
			return pushHead{}, errCommands
		}
		if n == 0 {
			if len(out) == 0 && (read.Len() != len(size) || !atEnd(body)) {
				return pushHead{}, errCommands
			}
			return pushHead{commands: out, caps: caps, read: read.Bytes()}, nil
		}
		if n < 5 || read.Len()+int(n)-4 > MaxCommandBytes {
			return pushHead{}, errCommands
		}
		line := make([]byte, n-4)
		if _, err := io.ReadFull(body, line); err != nil {
			return pushHead{}, errCommands
		}
		read.Write(line)
		text := strings.TrimSuffix(string(line), "\n")
		if len(out) == 0 && strings.HasPrefix(text, "shallow ") {
			if !objectID(strings.TrimPrefix(text, "shallow ")) {
				return pushHead{}, errCommands
			}
			continue
		}
		if len(out) == 0 {
			var asked string
			text, asked, _ = strings.Cut(text, "\x00")
			caps = strings.Fields(asked)
		}
		c, ok := parseCommand(text)
		if !ok || len(out) == MaxCommands {
			return pushHead{}, errCommands
		}
		out = append(out, c)
	}
}

// atEnd reports whether a body has nothing more to read. A byte read, or an
// error other than the end, is not the end.
func atEnd(body io.Reader) bool {
	var one [1]byte
	n, err := io.ReadFull(body, one[:])
	return n == 0 && errors.Is(err, io.EOF)
}

// parseCommand reads "<old id> <new id> <ref name>".
func parseCommand(text string) (command, bool) {
	parts := strings.Split(text, " ")
	if len(parts) != 3 || !objectID(parts[0]) || !objectID(parts[1]) || len(parts[0]) != len(parts[1]) {
		return command{}, false
	}
	ref := parts[2]
	if !strings.HasPrefix(ref, "refs/") || strings.ContainsFunc(ref, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
		return command{}, false
	}
	return command{Old: parts[0], New: parts[1], Ref: ref}, true
}

// objectID reports whether s is an object id of SHA-1 or SHA-256 in
// lowercase hex.
func objectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := range len(s) {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// The side bands of git's protocol a refusal is written in, and the largest
// pkt-line each allows.
const (
	bandData  = 1
	bandError = 3
	// maxPkt is the largest pkt-line of side-band-64k, its length included;
	// maxPktSmall that of side-band.
	maxPkt      = 65520
	maxPktSmall = 1000
	// maxReason bounds the sentence a refusal names its rule in.
	maxReason = 256
)

// The sentences of a refusal. A ref the rule admits in a push that names
// another is refused with it, since Pons sends none of a push or all of it.
const (
	reasonWithTheRest = "not pushed: another ref in this push is refused"
	reasonGeneral     = "this ref may not be pushed by this caller"
)

// refusal is the answer to a push whose refs Refs do not all admit, as a
// git host answers a push it refuses, so stock git prints the reason. A
// client that asked for report-status, which git does whenever the host
// offers it, is answered with "unpack ok" and one "ng <ref> <reason>" per
// command: a ref outside Refs with the rule, any other with
// reasonWithTheRest. A client that asked for none is answered an ERR
// packet. To a client that asked for a side band, the report is carried in
// band 1, and the ERR packet's text in band 3, the band of an error.
func (h pushHead) refusal(l authorizer.Limits) []byte {
	rule := refsRule(l.Refs)
	// packet is the largest pkt-line of the side band asked for, 0 for none.
	var packet int
	switch {
	case slices.Contains(h.caps, "side-band-64k"):
		packet = maxPkt
	case slices.Contains(h.caps, "side-band"):
		packet = maxPktSmall
	}
	var out bytes.Buffer
	if !slices.Contains(h.caps, "report-status") && !slices.Contains(h.caps, "report-status-v2") {
		if packet == 0 {
			writePkt(&out, "ERR "+rule+"\n")
			return out.Bytes()
		}
		writeBands(&out, bandError, []byte(rule+"\n"), packet)
		writePkt(&out, "")
		return out.Bytes()
	}
	var report bytes.Buffer
	writePkt(&report, "unpack ok\n")
	for _, c := range h.commands {
		reason := reasonWithTheRest
		if !l.AdmitsRef(c.Ref) {
			reason = rule
		}
		writePkt(&report, "ng "+c.Ref+" "+reason+"\n")
	}
	writePkt(&report, "")
	if packet == 0 {
		return report.Bytes()
	}
	writeBands(&out, bandData, report.Bytes(), packet)
	writePkt(&out, "")
	return out.Bytes()
}

// refsRule is the one sentence that names the rule of Refs: the branches
// under a prefix when every glob is refs/heads/<prefix>/*, else the globs
// themselves. Globs that would not print on one line, or a sentence past
// maxReason, give reasonGeneral.
func refsRule(globs []string) string {
	if len(globs) == 0 || slices.ContainsFunc(globs, func(g string) bool {
		return strings.ContainsFunc(g, func(r rune) bool { return r < 0x20 || r == 0x7f })
	}) {
		return reasonGeneral
	}
	prefixes := make([]string, 0, len(globs))
	for _, g := range globs {
		p, ok := strings.CutSuffix(g, "*")
		if !ok || !strings.HasPrefix(p, "refs/heads/") || !strings.HasSuffix(p, "/") || strings.Contains(p, "*") {
			prefixes = nil
			break
		}
		prefixes = append(prefixes, p)
	}
	rule := "only refs matching " + either(globs) + " may be pushed by this caller"
	if prefixes != nil {
		rule = "only branches under " + either(prefixes) + " may be pushed by this caller"
	}
	if len(rule) > maxReason {
		return reasonGeneral
	}
	return rule
}

// either joins names as a sentence offers a choice: "a", "a or b", "a, b,
// or c".
func either(names []string) string {
	switch len(names) {
	case 1:
		return names[0]
	case 2:
		return names[0] + " or " + names[1]
	}
	return strings.Join(names[:len(names)-1], ", ") + ", or " + names[len(names)-1]
}

// writePkt writes one pkt-line, and the flush-pkt for an empty line.
func writePkt(b *bytes.Buffer, line string) {
	if line == "" {
		b.WriteString("0000")
		return
	}
	fmt.Fprintf(b, "%04x", len(line)+4)
	b.WriteString(line)
}

// writeBands writes data in one band of the side band, in pkt-lines no
// longer than max.
func writeBands(b *bytes.Buffer, band byte, data []byte, max int) {
	for len(data) > 0 {
		n := min(len(data), max-5)
		fmt.Fprintf(b, "%04x", n+5)
		b.WriteByte(band)
		b.Write(data[:n])
		data = data[n:]
	}
}

// refusePush answers a push its allow's Refs refuse (specs/014-http-forwarding.md).
// None of the push reaches the connector. git reads no answer before it has
// sent its whole request, so the rest of the body, the pack, is read and
// dropped first, bounded as a forwarded body is; then the refusal is
// answered with 200, the status a git host gives a push it refuses. It
// answers refused, the error the record is kept under.
func (c *Carrier) refusePush(w http.ResponseWriter, r *http.Request, call *call, h pushHead, l authorizer.Limits, refused error) error {
	if err := c.drain(w, r, call, int64(len(h.read))); err != nil {
		return err
	}
	answer := h.refusal(l)
	w.Header().Set("Content-Type", "application/x-"+ReceivePack+"-result")
	w.Header().Set("Content-Length", strconv.Itoa(len(answer)))
	w.Header().Set("Cache-Control", "no-cache")
	call.wrote = true
	w.WriteHeader(http.StatusOK)
	n, err := w.Write(answer)
	call.BytesOut = int64(n)
	if err != nil {
		// The caller went away; there is nobody to answer.
		return err
	}
	return refused
}

// drain reads what is left of a request's body and drops it: at most
// PONS_MAX_FORWARD_BYTES in all, read counted already, and each read
// within the idle timeout, so a caller that stops sending is not waited
// for. A body past the bound is 413; one that fails to read leaves nobody
// to answer.
func (c *Carrier) drain(w http.ResponseWriter, r *http.Request, call *call, read int64) error {
	rc := http.NewResponseController(w)
	body := &bounded{r: idleBody{r: r.Body, rc: rc, idle: c.IdleTimeout}, left: c.MaxForwardBytes - read}
	n, err := io.Copy(io.Discard, body)
	call.BytesIn += n
	if derr := readDeadline(rc, time.Time{}); derr != nil && err == nil {
		err = derr
	}
	switch {
	case body.over.Load():
		return apierr.Fail(apierr.CodeRequestTooLarge, "max_forward_bytes="+strconv.FormatInt(c.MaxForwardBytes, 10))
	case err != nil:
		call.wrote = true
		return err
	}
	return nil
}

// idleBody is a request body each read of which returns within idle; zero
// is no bound.
type idleBody struct {
	r    io.Reader
	rc   *http.ResponseController
	idle time.Duration
}

func (b idleBody) Read(p []byte) (int, error) {
	if b.idle > 0 {
		if err := readDeadline(b.rc, time.Now().Add(b.idle)); err != nil {
			return 0, err
		}
	}
	return b.r.Read(p)
}

// readDeadline sets the deadline of the request's reads; a writer that
// holds no connection, as in a test, has none to set.
func readDeadline(rc *http.ResponseController, at time.Time) error {
	if err := rc.SetReadDeadline(at); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	return nil
}
