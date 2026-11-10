package bindrt

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	insnLine    = regexp.MustCompile(`^[0-9]+: \(`)
	summaryLine = regexp.MustCompile(`^processed [0-9]+ insns`)
	// A source position the verifier prints from BTF line_info: "; NAME:LINE"
	// (6.6) or "; NAME:LINE @ NAME:LINE" (6.12, 7.1). LINE has no leading zero.
	sourceLine = regexp.MustCompile(`^; ([A-Za-z0-9_./-]+:[1-9][0-9]*)(?: @ ([A-Za-z0-9_./-]+:[1-9][0-9]*))?$`)
)

// RejectedAt returns the source position ("NAME:LINE") of the instruction the
// verifier rejected, read from a complete verifier log (VerifierError.Log).
//
// The log is complete only when its last non-blank line is the
// "processed N insns" summary and that summary follows the last instruction
// line. The position is the nearest "; " annotation before the last
// instruction; it must have one of the two forms above, and both sides of the
// "@" must agree. Otherwise RejectedAt reports false: it never falls back to an
// older annotation, so a truncated log, a log without line_info or an invalid
// position names no line.
func RejectedAt(log []string) (string, bool) {
	end := len(log) - 1
	for end >= 0 && strings.TrimSpace(log[end]) == "" {
		end--
	}
	if end < 0 || !summaryLine.MatchString(log[end]) {
		return "", false
	}
	last := -1
	for i := end - 1; i >= 0; i-- {
		if insnLine.MatchString(log[i]) {
			last = i
			break
		}
	}
	if last < 0 {
		return "", false
	}
	for i := last - 1; i >= 0; i-- {
		if !strings.HasPrefix(log[i], ";") {
			continue
		}
		m := sourceLine.FindStringSubmatch(log[i])
		if m == nil || (m[2] != "" && m[2] != m[1]) {
			return "", false
		}
		return m[1], true
	}
	return "", false
}

// LoadError is a load error of a generated binding whose verifier log names the
// source line of the rejected instruction. Error appends " (rejected at At)" to
// the original message; Unwrap returns the original error unchanged, so
// errors.As and errors.Is see the same values as before. Program is the program
// name from the original error, empty when it names none.
type LoadError struct {
	Program string
	At      string
	Err     error
}

func (e *LoadError) Error() string {
	return e.Err.Error() + " (rejected at " + e.At + ")"
}

func (e *LoadError) Unwrap() error { return e.Err }

// Format formats the original error with the same verb, flags and width, and
// appends the position for %v and %s. Other verbs format the original error only.
func (e *LoadError) Format(f fmt.State, verb rune) {
	s := fmt.Sprintf(fmt.FormatString(f, verb), e.Err)
	if verb == 'v' || verb == 's' {
		s += " (rejected at " + e.At + ")"
	}
	fmt.Fprint(f, s)
}
