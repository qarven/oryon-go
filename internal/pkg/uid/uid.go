package uid

// ID generates unique UUID identifiers.
type ID interface {
	// Generate generates a new UUIDv7 as a string.
	Generate() string
}
