package jsonlimit

import "fmt"

const DefaultMaxDepth = 64

// CheckDepth scans JSON delimiters without allocating a decoded object. It is
// intended to run before json.Unmarshal so deeply nested local input is rejected
// before the standard decoder recursively materializes it.
func CheckDepth(data []byte, maximum int) error {
	if maximum < 1 {
		return fmt.Errorf("maximum JSON nesting depth must be positive")
	}

	depth := 0
	inString := false
	escaped := false
	for index, character := range data {
		if inString {
			switch {
			case escaped:
				escaped = false
			case character == '\\':
				escaped = true
			case character == '"':
				inString = false
			}
			continue
		}

		switch character {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maximum {
				return fmt.Errorf(
					"JSON nesting depth exceeds %d at byte %d",
					maximum,
					index,
				)
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return nil
}
