package stacktrace

import "strings"

// InternalPaths returns internal package stack frames from a raw stack trace.
func InternalPaths(stack []byte) []string {
	lines := strings.Split(string(stack), "\n")

	paths := make([]string, 0, len(lines))
	for i := range len(lines) - 1 {
		line := strings.TrimSpace(lines[i+1])
		if !strings.Contains(line, "/internal/") || !strings.Contains(line, ".go") {
			continue
		}

		idx := strings.Index(line, ".go:")
		if idx == -1 {
			continue
		}

		end := strings.Index(line[idx:], " ")
		if end == -1 {
			end = len(line)
		} else {
			end += idx
		}

		shortPath := line[:end]

		internalIdx := strings.Index(shortPath, "/internal/")
		if internalIdx == -1 {
			continue
		}

		paths = append(paths, shortPath[internalIdx+1:])
	}

	return paths
}