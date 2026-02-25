package core

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// maskRunes returns a string of '*' characters whose count equals the rune length of s.
func maskRunes(s string) string {
	return strings.Repeat("*", utf8.RuneCountInString(s))
}

// simplePatterns are PII patterns where the entire regex match is replaced with '*' × runeLen(match).
// ORDER MATTERS: Bearer must come before the standalone JWT pattern so that
// "Bearer eyJ..." is captured as one unit rather than double-masked.
var simplePatterns = []*regexp.Regexp{
	// Bearer / Authorization tokens: mask the whole "Bearer <value>" phrase.
	regexp.MustCompile(`(?i)Bearer\s+\S+`),

	// Standalone JWT tokens: base64url header.payload.signature (starts with eyJ).
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*`),

	// Taiwan National ID: one uppercase letter + digit 1 or 2 + 8 digits (e.g. A123456789).
	regexp.MustCompile(`\b[A-Z][12]\d{8}\b`),

	// Email addresses.
	regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),

	// Taiwan mobile phone: 09xxxxxxxx (10 digits), optionally split by dashes or spaces.
	regexp.MustCompile(`\b09\d{2}[-\s]?\d{3}[-\s]?\d{3}\b`),

	// Taiwan landline with parenthesised area code: (0x)xxxx-xxxx.
	regexp.MustCompile(`\(0\d{1,3}\)\s?\d{3,4}[-\s]?\d{3,4}`),

	// Taiwan landline with dash separator: 0x-xxxx-xxxx.
	regexp.MustCompile(`\b0\d{1,3}-\d{3,4}-?\d{3,4}\b`),

	// Address unit numbers: digits followed by 號, 樓, 室, or 之N.
	regexp.MustCompile(`\d+(?:-\d+)*(?:號|樓|室|之\d+)`),

	// Credit card numbers: 13-16 digits optionally separated by spaces or dashes.
	regexp.MustCompile(`\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}\b`),
}

// namePattern matches a Chinese name keyword followed by a separator and 2–4 CJK characters.
// Capture group 1 = keyword+separator (preserved), group 2 = the name (masked).
var namePattern = regexp.MustCompile(
	`((?:姓名|申請人|使用者|客戶|名字)[：:]\s*)([\x{4E00}-\x{9FFF}]{2,4})`,
)

// MaskPII replaces all detected PII in text with '*' repeated to match the original rune length.
func MaskPII(text string) string {
	// Whole-match patterns.
	for _, p := range simplePatterns {
		text = p.ReplaceAllStringFunc(text, maskRunes)
	}

	// Keyword-anchored Chinese name: preserve the keyword+separator, mask only the name part.
	text = namePattern.ReplaceAllStringFunc(text, func(match string) string {
		subs := namePattern.FindStringSubmatch(match)
		if len(subs) < 3 {
			return maskRunes(match)
		}
		// subs[1] = keyword+separator (e.g. "姓名："), subs[2] = the actual name
		return subs[1] + maskRunes(subs[2])
	})

	return text
}
