package frontend

import (
	"path/filepath"
	"sync"
)

// An analysis cache inside the test process. About 10 tests re-ran Analyze on every dir in allDirs (testdata and the gate's PKGS)
// (the same analysis of the same source about 10 times per process — most of the 212 s of internal/frontend's tests). **Only read-only tests** use it:
//   - tests that rewrite the tables (TestFailClosed — temporarily removes apiTable rows) call Analyze directly (results under a rewrite never enter the cache, and cached results are not used)
//   - the analysis determinism test (TestGoldenReproducible — byte equality of two Analyze runs) calls Analyze directly
//   - temporary dirs of rewritten source (TestExplicitTypeArgsSameDiagnostics's tmp) call Analyze directly
//
// Callers never modify the results (*Result and its analyzer) — read only. Independence from test order was checked with -shuffle=on.
var (
	analyzeMu   sync.Mutex
	analyzeMemo = map[string]analyzeEntry{}
)

type analyzeEntry struct {
	res *Result
	err error
}

// analyzeCached returns the Analyze result for dir (once per absolute path of dir).
func analyzeCached(dir string) (*Result, error) {
	key, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	analyzeMu.Lock()
	defer analyzeMu.Unlock()
	if e, ok := analyzeMemo[key]; ok {
		return e.res, e.err
	}
	res, err := Analyze(dir)
	analyzeMemo[key] = analyzeEntry{res, err}
	return res, err
}
