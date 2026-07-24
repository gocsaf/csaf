// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

package misc //revive:disable-line:var-naming

import "bytes"

const (
	// MinBufSize is the minimal capacity of the pool buffers.
	MinBufSize = 1 * 1024 * 1024
	// MaxBufSize is the maximal capacity of the pool buffers.
	MaxBufSize = 4 * 1024 * 1024
)

// BufferPool is a pool of reusable buffers.
type BufferPool chan (*bytes.Buffer)

// NewBufferPool creates a new pool with max number of items.
func NewBufferPool(items int) BufferPool {
	return make(BufferPool, items)
}

// Get returns a buffer from the pool.
func (bp BufferPool) Get() *bytes.Buffer {
	select {
	case buf := <-bp:
		return buf
	default:
		return bytes.NewBuffer(make([]byte, 0, MinBufSize))
	}
}

// Put stores a buffer into the pool.
func (bp BufferPool) Put(buf *bytes.Buffer) {
	// Throw away if too large.
	if buf != nil && buf.Cap() <= MaxBufSize {
		buf.Reset()
		select {
		case bp <- buf:
		default:
		}
	}
}
