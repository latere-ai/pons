-- SPDX-FileCopyrightText: 2026 Latere AI
-- SPDX-License-Identifier: Apache-2.0

DROP INDEX IF EXISTS connectors_owner;
ALTER TABLE connectors
    DROP COLUMN IF EXISTS client_secret_nonce,
    DROP COLUMN IF EXISTS client_secret_ciphertext,
    DROP COLUMN IF EXISTS client_secret_key_nonce,
    DROP COLUMN IF EXISTS client_secret_wrapped_key,
    DROP COLUMN IF EXISTS client_secret_key_id,
    DROP COLUMN IF EXISTS disabled,
    DROP COLUMN IF EXISTS vouched,
    DROP COLUMN IF EXISTS sign_in;
