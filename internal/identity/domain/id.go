package domain

import "github.com/google/uuid"

// ID is a UUIDv7 identifier stored as a string.
type ID string

// String returns the string representation of the ID.
func (id ID) String() string {
	return string(id)
}

// IDFrom converts a string to an ID.
func IDFrom(s string) ID {
	return ID(s)
}

func IDParse(s string) (ID, error) {
	parsed, err := uuid.Parse(s)
	if err != nil {
		return "", err
	}

	return ID(parsed.String()), nil
}
