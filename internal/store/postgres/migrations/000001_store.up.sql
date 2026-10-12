-- SPDX-FileCopyrightText: 2026 Latere AI
-- SPDX-License-Identifier: Apache-2.0

-- The tables of specs/005-store-and-sealing.md. Ids and subjects are text,
-- times timestamptz, hashes and sealed columns bytea, and the json columns
-- jsonb. Each sealed value is five columns: the id of the key that wrapped
-- its data key, the wrapped data key and its nonce, the ciphertext and its
-- nonce.

-- The connectors a person added. A catalog connector has no row.
CREATE TABLE connectors (
    id          text PRIMARY KEY,
    owner       text NOT NULL,
    name        text NOT NULL,
    title       text NOT NULL,
    description text NOT NULL DEFAULT '',
    icon        text NOT NULL DEFAULT '',
    kind        text NOT NULL,
    url         text NOT NULL,
    hosts       jsonb NOT NULL DEFAULT '[]',
    auth        jsonb NOT NULL DEFAULT '{}',
    tools       jsonb NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL,
    UNIQUE (owner, name)
);

CREATE TABLE connections (
    id           text PRIMARY KEY,
    owner        text NOT NULL,
    name         text NOT NULL,
    connector    text NOT NULL,
    kind         text NOT NULL,
    auth         text NOT NULL,
    state        text NOT NULL CHECK (state IN ('pending', 'connected', 'needs_reconnect')),
    reason       text NOT NULL DEFAULT '',
    account      text NOT NULL DEFAULT '',
    scopes       jsonb NOT NULL DEFAULT '[]',
    created_by   text NOT NULL,
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    expires_at   timestamptz,
    UNIQUE (owner, name)
);
-- A list of an owner's connections, newest first by id.
CREATE INDEX connections_owner_id ON connections (owner, id);
-- connector_in_use, when an added connector is removed.
CREATE INDEX connections_connector ON connections (connector);

-- A connection's credential goes with the connection.
CREATE TABLE credentials (
    connection    text PRIMARY KEY REFERENCES connections (id) ON DELETE CASCADE,
    kind          text NOT NULL,
    meta          jsonb NOT NULL DEFAULT '{}',
    key_id        bytea NOT NULL,
    wrapped_key   bytea NOT NULL,
    key_nonce     bytea NOT NULL,
    ciphertext    bytea NOT NULL,
    nonce         bytea NOT NULL,
    version       bigint NOT NULL DEFAULT 1,
    refresh_until timestamptz,
    updated_at    timestamptz NOT NULL
);

-- A sign-in in progress, at most one per connection. state_hash is null
-- once the callback came, and the pending credential is null until then.
CREATE TABLE flows (
    id                      text PRIMARY KEY,
    connection              text NOT NULL UNIQUE REFERENCES connections (id) ON DELETE CASCADE,
    state_hash              bytea UNIQUE,
    issuer                  text NOT NULL DEFAULT '',
    authorization_endpoint  text NOT NULL DEFAULT '',
    token_endpoint          text NOT NULL DEFAULT '',
    revocation_endpoint     text NOT NULL DEFAULT '',
    iss_parameter_supported boolean NOT NULL DEFAULT false,
    client_id               text NOT NULL DEFAULT '',
    redirect_uri            text NOT NULL DEFAULT '',
    resource                text NOT NULL DEFAULT '',
    scopes                  jsonb NOT NULL DEFAULT '[]',
    return_to               text NOT NULL DEFAULT '',
    finish_hash             bytea,
    pending_kind            text NOT NULL DEFAULT '',
    pending_meta            jsonb,
    created_at              timestamptz NOT NULL,
    expires_at              timestamptz NOT NULL,
    verifier_key_id         bytea,
    verifier_wrapped_key    bytea,
    verifier_key_nonce      bytea,
    verifier_ciphertext     bytea,
    verifier_nonce          bytea,
    pending_key_id          bytea,
    pending_wrapped_key     bytea,
    pending_key_nonce       bytea,
    pending_ciphertext      bytea,
    pending_nonce           bytea
);
CREATE INDEX flows_expires_at ON flows (expires_at);

-- What an authorization server issued to Pons, per issuer and redirect
-- address. The secret is null when none was issued.
CREATE TABLE registrations (
    issuer             text NOT NULL,
    redirect_uri       text NOT NULL,
    client_id          text NOT NULL,
    registered_at      timestamptz NOT NULL,
    secret_key_id      bytea,
    secret_wrapped_key bytea,
    secret_key_nonce   bytea,
    secret_ciphertext  bytea,
    secret_nonce       bytea,
    PRIMARY KEY (issuer, redirect_uri)
);

-- That a call happened. No foreign key: a record outlives its connection
-- until its retention passes.
CREATE TABLE calls (
    id          text PRIMARY KEY,
    connection  text NOT NULL,
    owner       text NOT NULL,
    connector   text NOT NULL,
    subject     text NOT NULL,
    session     text NOT NULL DEFAULT '',
    at          timestamptz NOT NULL,
    duration_ms bigint NOT NULL DEFAULT 0,
    method      text NOT NULL DEFAULT '',
    tool        text NOT NULL DEFAULT '',
    effect      text NOT NULL DEFAULT '',
    refs        integer,
    outcome     text NOT NULL,
    status      integer,
    bytes_in    bigint NOT NULL DEFAULT 0,
    bytes_out   bigint NOT NULL DEFAULT 0
);
CREATE INDEX calls_connection_id ON calls (connection, id);
CREATE INDEX calls_at ON calls (at);

-- The row a create writes with the object it makes. It holds no body and no
-- hash of one.
CREATE TABLE idempotency_keys (
    subject    text NOT NULL,
    key        text NOT NULL,
    route      text NOT NULL,
    status     integer NOT NULL,
    object     text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (subject, key)
);
CREATE INDEX idempotency_keys_created_at ON idempotency_keys (created_at);
