package requirements

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// JSONMaxDepth bounds open {/[ nesting, matching the C loader's input contract.
const JSONMaxDepth = 128

// Strict JSON rules; see docs/requirements_format.md section 13.
const (
	JSONRuleSyntax            = "syntax"
	JSONRuleDuplicateKey      = "duplicate_key"
	JSONRuleKeyCase           = "key_case"
	JSONRuleInvalidUTF8       = "invalid_utf8"
	JSONRuleUnpairedSurrogate = "unpaired_surrogate"
	JSONRuleTrailingData      = "trailing_data"
	JSONRuleNestingTooDeep    = "nesting_too_deep"
	JSONRuleNul               = "nul"         // Input strings never have a valid embedded U+0000 (same as the C loader).
	JSONRuleUnknownKey        = "unknown_key" // Key absent from the destination type (DisallowUnknownFields).
	JSONRuleType              = "type"        // Value type incompatible with the destination field.
)

// JSONRules enumerates rules for corpus coverage checks.
var JSONRules = []string{JSONRuleSyntax, JSONRuleDuplicateKey, JSONRuleKeyCase, JSONRuleInvalidUTF8, JSONRuleUnpairedSurrogate, JSONRuleTrailingData, JSONRuleNestingTooDeep, JSONRuleNul, JSONRuleUnknownKey, JSONRuleType}

// CapsRuleKeyNewerFormat rejects loader keys, privileged_queries or query
// names introduced after the recorded caps format (specification section 13).
const CapsRuleKeyNewerFormat = "caps_key_newer_format"

// CapsRules enumerates caps-specific rules, separate from byte-level JSONRules.
var CapsRules = []string{CapsRuleKeyNewerFormat, CapsRuleFormatUnknown}

// CapsRuleFormatUnknown rejects an unknown caps format after byte-level checks
// but before decoding into typed fields. Unknown keys in a newer format are
// therefore diagnosed by format, not as unknown_key.
const CapsRuleFormatUnknown = "caps_format_unknown"

// CapsFormatError carries a named CapsRules rule and its message.
type CapsFormatError struct {
	Rule string
	Msg  string
}

func (e *CapsFormatError) Error() string { return e.Msg }

// keyNewerFormat reports a key introduced after the recorded format.
func keyNewerFormat(format string, args ...any) error {
	return &CapsFormatError{Rule: CapsRuleKeyNewerFormat, Msg: fmt.Sprintf(format, args...)}
}

// JSONError carries the strict rule name and input byte offset.
type JSONError struct {
	Rule   string
	Offset int
	Detail string
}

func (e *JSONError) Error() string {
	return fmt.Sprintf("json: %s at byte %d: %s", e.Rule, e.Offset, e.Detail)
}

// DecodeStrictJSON rejects duplicate/case-mismatched keys, invalid UTF-8 or
// unpaired surrogates, trailing data and excessive nesting before using the
// standard decoder with unknown-field rejection. These forms must not silently
// inherit encoding/json's last-wins, replacement-character or case-fold behavior.
func DecodeStrictJSON(data []byte, v any) error {
	if err := scanStrictJSON(data, v); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var te *json.UnmarshalTypeError
		switch {
		case errors.As(err, &te):
			return &JSONError{JSONRuleType, int(te.Offset), err.Error()}
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			return &JSONError{JSONRuleUnknownKey, int(dec.InputOffset()), strings.TrimPrefix(err.Error(), "json: ")}
		}
		return &JSONError{JSONRuleSyntax, int(dec.InputOffset()), err.Error()}
	}
	return nil
}

// scanStrictJSON checks byte-level rules in specification section 13 order.
// Caps format validation follows this scan but precedes typed decoding
// (unknown_key/type).
func scanStrictJSON(data []byte, v any) error {
	s := &strictScanner{data: data}
	s.skipSpace()
	if err := s.value(reflect.TypeOf(v), 0); err != nil {
		return err
	}
	s.skipSpace()
	if s.pos < len(s.data) {
		return &JSONError{JSONRuleTrailingData, s.pos, "data after the top-level value"}
	}
	return nil
}

type strictScanner struct {
	data []byte
	pos  int
}

func (s *strictScanner) fail(rule, format string, a ...any) error {
	return &JSONError{rule, s.pos, fmt.Sprintf(format, a...)}
}

func (s *strictScanner) skipSpace() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
		default:
			return
		}
	}
}

// elemType unwraps pointers. Nil means unknown type, so key case is not checked.
func elemType(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// structKeys maps JSON names to types, including embedded struct fields as
// encoding/json does.
func structKeys(t reflect.Type, out map[string]reflect.Type) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" && elemType(f.Type).Kind() == reflect.Struct {
			structKeys(elemType(f.Type), out)
			continue
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
}

func (s *strictScanner) value(t reflect.Type, depth int) error {
	if s.pos >= len(s.data) {
		return s.fail(JSONRuleSyntax, "unexpected end")
	}
	t = elemType(t)
	switch c := s.data[s.pos]; {
	case c == '{' || c == '[':
		if depth+1 > JSONMaxDepth {
			return s.fail(JSONRuleNestingTooDeep, "more than %d nested objects / arrays", JSONMaxDepth)
		}
		if c == '{' {
			return s.object(t, depth+1)
		}
		return s.array(t, depth+1)
	case c == '"':
		_, err := s.str()
		return err
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return s.number()
	default:
		return s.fail(JSONRuleSyntax, "unexpected byte %q", c)
	}
}

func (s *strictScanner) object(t reflect.Type, depth int) error {
	s.pos++ // {
	var fields map[string]reflect.Type
	var lower map[string]string
	var valType reflect.Type
	switch {
	case t != nil && t.Kind() == reflect.Struct:
		fields = map[string]reflect.Type{}
		structKeys(t, fields)
		lower = map[string]string{}
		for k := range fields {
			lower[strings.ToLower(k)] = k
		}
	case t != nil && t.Kind() == reflect.Map:
		valType = t.Elem()
	}
	seen := map[string]bool{}
	s.skipSpace()
	if s.pos < len(s.data) && s.data[s.pos] == '}' {
		s.pos++
		return nil
	}
	for {
		s.skipSpace()
		if s.pos >= len(s.data) || s.data[s.pos] != '"' {
			return s.fail(JSONRuleSyntax, "want an object key")
		}
		at := s.pos
		key, err := s.str()
		if err != nil {
			return err
		}
		if seen[key] {
			return &JSONError{JSONRuleDuplicateKey, at, fmt.Sprintf("key %q appears twice in the same object", key)}
		}
		seen[key] = true
		vt := valType
		if fields != nil {
			if ft, ok := fields[key]; ok {
				vt = ft
			} else if exact, ok := lower[strings.ToLower(key)]; ok {
				return &JSONError{JSONRuleKeyCase, at, fmt.Sprintf("key %q differs only in case from %q", key, exact)}
			}
		}
		s.skipSpace()
		if s.pos >= len(s.data) || s.data[s.pos] != ':' {
			return s.fail(JSONRuleSyntax, "want ':'")
		}
		s.pos++
		s.skipSpace()
		if err := s.value(vt, depth); err != nil {
			return err
		}
		s.skipSpace()
		if s.pos >= len(s.data) {
			return s.fail(JSONRuleSyntax, "unexpected end in an object")
		}
		switch s.data[s.pos] {
		case ',':
			s.pos++
		case '}':
			s.pos++
			return nil
		default:
			return s.fail(JSONRuleSyntax, "want ',' or '}'")
		}
	}
}

func (s *strictScanner) array(t reflect.Type, depth int) error {
	s.pos++ // [
	var et reflect.Type
	if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
		et = t.Elem()
	}
	s.skipSpace()
	if s.pos < len(s.data) && s.data[s.pos] == ']' {
		s.pos++
		return nil
	}
	for {
		s.skipSpace()
		if err := s.value(et, depth); err != nil {
			return err
		}
		s.skipSpace()
		if s.pos >= len(s.data) {
			return s.fail(JSONRuleSyntax, "unexpected end in an array")
		}
		switch s.data[s.pos] {
		case ',':
			s.pos++
		case ']':
			s.pos++
			return nil
		default:
			return s.fail(JSONRuleSyntax, "want ',' or ']'")
		}
	}
}

func (s *strictScanner) literal(lit string) error {
	if !bytes.HasPrefix(s.data[s.pos:], []byte(lit)) {
		return s.fail(JSONRuleSyntax, "want %s", lit)
	}
	s.pos += len(lit)
	return nil
}

func (s *strictScanner) digits() int {
	n := 0
	for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
		s.pos++
		n++
	}
	return n
}

// number parses RFC 8259 numbers, rejecting leading '+', leading-zero digits
// and a bare decimal point.
func (s *strictScanner) number() error {
	if s.data[s.pos] == '-' {
		s.pos++
	}
	if s.pos < len(s.data) && s.data[s.pos] == '0' {
		s.pos++
	} else if s.digits() == 0 {
		return s.fail(JSONRuleSyntax, "bad number")
	}
	if s.pos < len(s.data) && s.data[s.pos] == '.' {
		s.pos++
		if s.digits() == 0 {
			return s.fail(JSONRuleSyntax, "bad number")
		}
	}
	if s.pos < len(s.data) && (s.data[s.pos] == 'e' || s.data[s.pos] == 'E') {
		s.pos++
		if s.pos < len(s.data) && (s.data[s.pos] == '+' || s.data[s.pos] == '-') {
			s.pos++
		}
		if s.digits() == 0 {
			return s.fail(JSONRuleSyntax, "bad number")
		}
	}
	return nil
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	return r, true
}

// str decodes strings, requiring valid raw UTF-8 and paired surrogate escapes.
func (s *strictScanner) str() (string, error) {
	s.pos++ // "
	var b strings.Builder
	for {
		if s.pos >= len(s.data) {
			return "", s.fail(JSONRuleSyntax, "unterminated string")
		}
		c := s.data[s.pos]
		switch {
		case c == '"':
			s.pos++
			return b.String(), nil
		case c < 0x20:
			return "", s.fail(JSONRuleSyntax, "control byte in a string")
		case c == '\\':
			if s.pos+1 >= len(s.data) {
				return "", s.fail(JSONRuleSyntax, "unterminated escape")
			}
			e := s.data[s.pos+1]
			switch e {
			case '"', '\\', '/':
				b.WriteByte(e)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				r, ok := hex4(s.data[s.pos+2:])
				if !ok {
					return "", s.fail(JSONRuleSyntax, "bad \\u escape")
				}
				if utf16.IsSurrogate(r) {
					if r >= 0xDC00 {
						return "", s.fail(JSONRuleUnpairedSurrogate, "low surrogate \\u%04X without a high one", r)
					}
					rest := s.data[s.pos+6:]
					r2, ok2 := hex4(rest[min(2, len(rest)):])
					if len(rest) < 6 || rest[0] != '\\' || rest[1] != 'u' || !ok2 || r2 < 0xDC00 || r2 > 0xDFFF {
						return "", s.fail(JSONRuleUnpairedSurrogate, "high surrogate \\u%04X without a low one", r)
					}
					b.WriteRune(utf16.DecodeRune(r, r2))
					s.pos += 12
					continue
				}
				if r == 0 {
					return "", s.fail(JSONRuleNul, "\\u0000 in a string")
				}
				b.WriteRune(r)
				s.pos += 6
				continue
			default:
				return "", s.fail(JSONRuleSyntax, "bad escape \\%c", e)
			}
			s.pos += 2
		case c < utf8.RuneSelf:
			b.WriteByte(c)
			s.pos++
		default:
			r, n := utf8.DecodeRune(s.data[s.pos:])
			if r == utf8.RuneError && n <= 1 {
				return "", s.fail(JSONRuleInvalidUTF8, "invalid UTF-8 byte 0x%02x in a string", c)
			}
			b.WriteRune(r)
			s.pos += n
		}
	}
}
