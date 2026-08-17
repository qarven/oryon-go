package strcase

import (
	"strings"
	"unicode"
)

// ToLowerSnake converts a string to snake_case (initialism-safe).
func ToLowerSnake(input string) string {
	if input == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(input))

	runes := []rune(input)
	for index := range runes {
		currentRune := runes[index]
		if index > 0 && needsSeparator(runes, index) {
			builder.WriteRune('_')
		}

		builder.WriteRune(unicode.ToLower(currentRune))
	}

	return builder.String()
}

// needsSeparator reports whether an underscore is required before runes[index]:
// 1) lower/digit -> upper  (e.g., userID -> user_ID)
// 2) acronym -> word       (e.g., HTTPServer -> HTTP_Server).
func needsSeparator(runes []rune, index int) bool {
	currentRune := runes[index]
	prev := runes[index-1]

	if !unicode.IsUpper(currentRune) {
		return false
	}

	if unicode.IsLower(prev) || unicode.IsDigit(prev) {
		return true
	}

	var next rune

	if index+1 < len(runes) {
		next = runes[index+1]
	}

	return unicode.IsUpper(prev) && next != 0 && unicode.IsLower(next)
}