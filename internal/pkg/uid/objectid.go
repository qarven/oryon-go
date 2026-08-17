package uid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	// timestampShift* are the big-endian bit shifts for the 6-byte timestamp.
	timestampShift40 = 40
	timestampShift32 = 32
	timestampShift24 = 24
	timestampShift16 = 16
	timestampShift8  = 8
)

// ErrStableNodeIdentityUnavailable indicates no stable node identity is available.
var ErrStableNodeIdentityUnavailable = errors.New(
	"uid: cannot determine stable node identity (machine-id/hostname unavailable)",
)

// ObjectIDGenerator generates 32-byte distributed-safe IDs (hex output).
type ObjectIDGenerator struct {
	nodeID  [6]byte
	pid     uint16
	counter uint32
}

// NewObjectIDGenerator creates a generator with stable node identity.
func NewObjectIDGenerator() (*ObjectIDGenerator, error) {
	generator := &ObjectIDGenerator{
		nodeID:  [6]byte{},
		pid:     uint16(os.Getpid()),
		counter: 0,
	}

	// stable node identity source: /etc/machine-id OR hostname
	src, err := generator.machineIDOrHostnameStrict()
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256([]byte(src))
	copy(generator.nodeID[:], sum[:6])

	// Seed counter from crypto/rand
	var randomBytes [4]byte

	_, err = rand.Read(randomBytes[:])
	if err != nil {
		return nil, fmt.Errorf("uid: failed to seed counter: %w", err)
	}

	generator.counter = uint32(randomBytes[0])<<24 |
		uint32(randomBytes[1])<<16 |
		uint32(randomBytes[2])<<8 |
		uint32(randomBytes[3])

	return generator, nil
}

// Generate returns a 64-char hex string representing 32 bytes (URL-safe).
func (g *ObjectIDGenerator) Generate() string {
	var raw [32]byte

	// 6-byte timestamp (ms, big-endian)
	timestamp := uint64(time.Now().UnixMilli())
	raw[0] = byte(timestamp >> timestampShift40)
	raw[1] = byte(timestamp >> timestampShift32)
	raw[2] = byte(timestamp >> timestampShift24)
	raw[3] = byte(timestamp >> timestampShift16)
	raw[4] = byte(timestamp >> timestampShift8)
	raw[5] = byte(timestamp)

	// 6-byte node id (stable)
	copy(raw[6:12], g.nodeID[:])

	// 2-byte pid (big-endian)
	raw[12] = byte(g.pid >> timestampShift8)
	raw[13] = byte(g.pid)

	// 4-byte counter
	c := atomic.AddUint32(&g.counter, 1)
	raw[14] = byte(c >> timestampShift24)
	raw[15] = byte(c >> timestampShift16)
	raw[16] = byte(c >> timestampShift8)
	raw[17] = byte(c)

	// 14 random bytes (best effort). If it fails, deterministic fallback.
	_, err := rand.Read(raw[18:])
	if err != nil {
		var seed [18]byte
		copy(seed[0:6], raw[0:6])
		copy(seed[6:12], raw[6:12])
		copy(seed[12:14], raw[12:14])
		copy(seed[14:18], raw[14:18])

		sum := sha256.Sum256(seed[:])
		copy(raw[18:], sum[:14])
	}

	var hexBuf [64]byte
	hex.Encode(hexBuf[:], raw[:])

	return string(hexBuf[:])
}

// machineIDOrHostnameStrict returns a stable identity string or an error.
func (g *ObjectIDGenerator) machineIDOrHostnameStrict() (string, error) {
	// Try /etc/machine-id (Linux)
	b, err := os.ReadFile("/etc/machine-id")
	if err == nil {
		s := strings.TrimSpace(string(b))
		if s != "" {
			return s, nil
		}
	}

	// Fallback hostname
	h, err := os.Hostname()
	if err == nil {
		h = strings.TrimSpace(h)
		if h != "" {
			return h, nil
		}
	}

	return "", ErrStableNodeIdentityUnavailable
}
