// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package memory_test

import (
	"testing"
	"time"

	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/memory"
	"latere.ai/x/pons/internal/store/storetest"
)

// The memory store passes the one suite.
func TestMemoryStore(t *testing.T) {
	storetest.Run(t, func(_ *testing.T, now func() time.Time) store.Store {
		return memory.New(memory.Options{Now: now})
	})
}
