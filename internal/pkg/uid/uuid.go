package uid

import (
	"github.com/google/uuid"
)

// UUID generates UUIDv7 identifiers.
type UUID struct{}

// NewUUID returns a UUID generator.
func NewUUID() *UUID {
	return &UUID{}
}

// Generate returns a new UUIDv7 as a string.
// It panics if UUID generation fails.
func (u *UUID) Generate() string {
	idv7, err := uuid.NewV7()
	if err != nil {
		// uuid.NewV7 only fails if the system's random source is broken,
		// which is unrecoverable.
		panic("uid: generate UUIDv7: " + err.Error())
	}

	return idv7.String()
}
