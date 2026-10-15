-- SPDX-FileCopyrightText: 2026 Latere AI
-- SPDX-License-Identifier: Apache-2.0

-- Connectors added for others (specs/016-connectors-added-for-others.md):
-- what the add found of how the server signs people in, the authorizer's
-- word that someone looked at the server, a connector its owner turned
-- off, and the secret of a client registered at a vouched-for server, as
-- the five sealed columns, null when it has none.
ALTER TABLE connectors
    ADD COLUMN sign_in                    jsonb NOT NULL DEFAULT '{}',
    ADD COLUMN vouched                    boolean NOT NULL DEFAULT false,
    ADD COLUMN disabled                   boolean NOT NULL DEFAULT false,
    ADD COLUMN client_secret_key_id       bytea,
    ADD COLUMN client_secret_wrapped_key  bytea,
    ADD COLUMN client_secret_key_nonce    bytea,
    ADD COLUMN client_secret_ciphertext   bytea,
    ADD COLUMN client_secret_nonce        bytea;

-- The count of the connectors one owner added, under its lock.
CREATE INDEX connectors_owner ON connectors (owner);
