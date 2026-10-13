// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/internal/store"
)

// probeTimeout bounds the probe of a key, whole.
const probeTimeout = 15 * time.Second

// Probe tries a key against a connector of kind http before it is stored
// (specs/014-http-forwarding.md): one GET of the connector's url with the
// key in its place. A 401 or a 403 refuses the key, 422
// credential_refused; no answer is 422 connector_unreachable; any other
// answer accepts it, since the service answered without refusing it. The
// answer reaches no caller and is kept nowhere. A connector of kind mcp is
// probed by a tools/list, which comes with its address.
func (c *Carrier) Probe(ctx context.Context, conn signin.Connector, secrets store.Secrets, meta store.Meta) error {
	if conn.Kind != catalog.KindHTTP {
		return nil
	}
	o := signin.Opened{Connection: store.Connection{Auth: catalog.AuthToken}, Connector: conn, Secrets: secrets, Meta: meta}
	place, err := c.place(ctx, &call{}, o, AddressHTTP, false)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, conn.URL, nil)
	if err != nil {
		return apierr.Fail(apierr.CodeConnectorUnreachable, dial.SchemeNotHTTPS)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Dial.Do(ctx, dial.Request{HTTP: req, Secrets: place, Ports: conn.Ports(), Timeout: probeTimeout, Forward: true})
	if err != nil {
		name, _, _ := dial.ReasonOf(err)
		return apierr.Fail(apierr.CodeConnectorUnreachable, name)
	}
	closeBody(resp)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return apierr.Fail(apierr.CodeCredentialRefused, "status_"+strconv.Itoa(resp.StatusCode))
	}
	return nil
}
