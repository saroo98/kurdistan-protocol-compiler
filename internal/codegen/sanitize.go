package codegen

import (
	"strings"
	"unicode"
)

func SanitizeIdentifier(value string) string {
	if value == "" {
		return "Generated"
	}
	var b strings.Builder
	capitalize := true
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if capitalize && unicode.IsLetter(r) {
				r = unicode.ToUpper(r)
			}
			b.WriteRune(r)
			capitalize = false
			continue
		}
		capitalize = true
	}
	out := b.String()
	if out == "" {
		return "Generated"
	}
	first := []rune(out)[0]
	if !unicode.IsLetter(first) {
		return "X" + out
	}
	return out
}

func sanitizeModuleSuffix(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "generated"
	}
	return out
}
