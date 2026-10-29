package requirements

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
)

// Recorder records capability queries and answers using RecordedCaps keys.
// It implements optional interfaces by forwarding to the underlying caps;
// QuerySet still reports unavailable queries so wrapping does not change checks.
type Recorder struct {
	under      Capabilities
	mu         sync.Mutex
	queries    map[string]map[string]Answer
	files      map[string]string // Binary paths keyed by program, supplied by SetBinaryPath.
	debugFiles map[string]string
}

// NewRecorder wraps capabilities for recording.
func NewRecorder(caps Capabilities) *Recorder {
	return &Recorder{under: caps, queries: map[string]map[string]Answer{}, files: map[string]string{}, debugFiles: map[string]string{}}
}

// SetBinaryPath supplies the recorded absolute or caps.json-relative binary path.
func (r *Recorder) SetBinaryPath(program, path string) { r.files[program] = path }

// SetUprobeDebugPath supplies the spelling recorded for a query. Relative paths
// explicitly choose the output caps.json directory as replay base.
func (r *Recorder) SetUprobeDebugPath(program string, id []byte, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.debugFiles[UprobeDebugKey(program, id)] = path
}

// Record returns a RecordedCaps snapshot; probedAs identifies probe privileges.
func (r *Recorder) Record(probedAs *ProbedAs, loader LoaderDecl) *RecordedCaps {
	r.mu.Lock()
	defer r.mu.Unlock()
	q := map[string]map[string]Answer{}
	for name, m := range r.queries {
		q[name] = map[string]Answer{}
		for k, a := range m {
			q[name][k] = a
		}
	}
	for _, base := range []string{QueryProgType, QueryHelper, QueryMapType} {
		if q[base] == nil {
			q[base] = map[string]Answer{}
		}
	}
	return &RecordedCaps{Format: RecordedFormat, ProbedAs: probedAs, Queries: q, LoaderD: LoaderJSONOf(loader)} // Include the USDT attach declaration.
}

func (r *Recorder) put(q, key string, a Answer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.queries[q] == nil {
		r.queries[q] = map[string]Answer{}
	}
	r.queries[q][key] = a
}

// answerOf converts a value/error pair into a recorded answer.
func answerOf(err error) (Answer, bool) {
	switch {
	case errors.Is(err, ErrUnknown):
		return Answer{Unknown: err.Error()}, true
	case err != nil:
		return Answer{Error: err.Error()}, true
	}
	return Answer{}, false
}

func (r *Recorder) recBool(q, key string, v bool, err error) (bool, error) {
	a, bad := answerOf(err)
	if !bad {
		a = Answer{Value: &v}
	}
	r.put(q, key, a)
	return v, err
}

func (r *Recorder) recDiffs(q, key string, d []string, err error) ([]string, error) {
	a, bad := answerOf(err)
	if !bad {
		dd := append([]string{}, d...)
		a = Answer{Diffs: &dd}
	}
	r.put(q, key, a)
	return d, err
}

// HasQuery preserves the underlying caps' QuerySet availability.
func (r *Recorder) HasQuery(q string) bool {
	if qs, ok := r.under.(QuerySet); ok && !qs.HasQuery(q) {
		return false
	}
	var ok bool
	switch q {
	case QueryProgType, QueryHelper, QueryMapType:
		ok = true
	case QueryTCX:
		_, ok = r.under.(TCXCaps)
	case QueryFuncSig:
		_, ok = r.under.(KernelFuncSigs)
	case QueryFunc:
		_, ok = r.under.(KernelFuncs)
	case QueryTracepoint, QueryKFields:
		_, ok = r.under.(KernelTypes)
	case QueryFuncArgs:
		_, ok = r.under.(KernelFuncArgs)
	case QueryBTFFeature:
		_, ok = r.under.(BTFFeatureCaps)
	case QueryArgTag:
		_, ok = r.under.(ArgTagCaps)
	case QueryArch:
		_, ok = r.under.(KernelArch)
	case QueryStructField:
		_, ok = r.under.(KernelStructFields)
	case QueryKernelSym:
		_, ok = r.under.(KernelSymbols)
	case QueryFuncParam:
		_, ok = r.under.(KernelFuncParams)
	case QueryUprobeBin:
		_, ok = r.under.(UprobeBinaries)
	case QueryUprobeDebug:
		_, ok = r.under.(UprobeDebugFiles)
	case QueryMapField:
		_, ok = r.under.(MapFieldPolicy)
	case QueryNullableArgs:
		_, ok = r.under.(NullableArgCaps)
	case QueryAttachType:
		_, ok = r.under.(AttachTypeCaps)
	case QueryAttachTarget:
		_, ok = r.under.(AttachTargetCaps)
	case QueryCtxAccess:
		_, ok = r.under.(CtxAccessCaps)
	case QueryTracingHelper:
		_, ok = r.under.(TracingHelperCaps)
	case QueryTracepointFields:
		_, ok = r.under.(TracepointFieldCaps)
	case QueryStructOpsMembers:
		_, ok = r.under.(StructOpsMemberCaps)
	case QueryExtTargets:
		_, ok = r.under.(ExtTargets)
	case QueryKfuncProtos:
		_, ok = r.under.(KernelKfuncs)
	case QuerySyscallArgs:
		_, ok = r.under.(SyscallArgCaps)
	case QueryKfuncLoad:
		_, ok = r.under.(KernelKfuncLoadCaps)
	case QueryTracepointBuffer:
		_, ok = r.under.(TracepointBufferCaps)
	}
	return ok
}

// Loader forwards the declaration, defaulting to Cilium022 as Check does.
func (r *Recorder) Loader() LoaderDecl { return loaderOf(r.under) }

func (r *Recorder) HasProgType(name string, id int64) (bool, error) {
	v, err := r.under.HasProgType(name, id)
	return r.recBool(QueryProgType, name, v, err)
}

func (r *Recorder) HasHelper(pt string, ptID int64, h string, hID int64) (bool, error) {
	v, err := r.under.HasHelper(pt, ptID, h, hID)
	return r.recBool(QueryHelper, pt+"/"+h, v, err)
}

// HasTracingHelper forwards an available query; capsAs checks HasQuery first.
func (r *Recorder) HasTracingHelper(at, h string, hID int64) (bool, error) {
	v, err := r.under.(TracingHelperCaps).HasTracingHelper(at, h, hID)
	return r.recBool(QueryTracingHelper, at+"/"+h, v, err)
}

func (r *Recorder) HasMapType(name string, id int64) (bool, error) {
	v, err := r.under.HasMapType(name, id)
	return r.recBool(QueryMapType, name, v, err)
}

func (r *Recorder) HasTCX() (bool, error) {
	v, err := r.under.(TCXCaps).HasTCX()
	return r.recBool(QueryTCX, "", v, err)
}

func (r *Recorder) CheckFuncSig(name string, nargs int, ret string) ([]string, error) {
	d, err := r.under.(KernelFuncSigs).CheckFuncSig(name, nargs, ret)
	return r.recDiffs(QueryFuncSig, name+"/"+strconv.Itoa(nargs)+"/"+ret, d, err)
}

func (r *Recorder) CheckFunc(name string) ([]string, error) {
	d, err := r.under.(KernelFuncs).CheckFunc(name)
	return r.recDiffs(QueryFunc, name, d, err)
}

func (r *Recorder) CheckTracepoint(name string, args []string) ([]string, error) {
	d, err := r.under.(KernelTypes).CheckTracepoint(name, args)
	return r.recDiffs(QueryTracepoint, name+"("+strings.Join(args, ",")+")", d, err)
}

// CheckFuncArgs forwards the query and records its answer.
func (r *Recorder) CheckFuncArgs(name string, args []string) ([]string, error) {
	d, err := r.under.(KernelFuncArgs).CheckFuncArgs(name, args)
	return r.recDiffs(QueryFuncArgs, name+"("+strings.Join(args, ",")+")", d, err)
}

// CheckKFields records each field independently, joining mismatches in field order.
func (r *Recorder) CheckKFields(kf []KField) ([]string, error) {
	kt := r.under.(KernelTypes)
	var out []string
	for _, k := range kf {
		d, err := kt.CheckKFields([]KField{k})
		if _, err := r.recDiffs(QueryKFields, k.Program+" "+k.Struct+"."+k.Field+" "+k.Type, d, err); err != nil {
			return nil, err
		}
		out = append(out, d...)
	}
	return out, nil
}

func (r *Recorder) HasBTFFeature(f string) (bool, error) {
	v, err := r.under.(BTFFeatureCaps).HasBTFFeature(f)
	return r.recBool(QueryBTFFeature, f, v, err)
}

func (r *Recorder) HasArgTagSemantics(pt string, ptID int64, tag, class string) (bool, error) {
	v, err := r.under.(ArgTagCaps).HasArgTagSemantics(pt, ptID, tag, class)
	return r.recBool(QueryArgTag, pt+"/"+tag+"/"+class, v, err)
}

func (r *Recorder) Arch() (string, error) {
	v, err := r.under.(KernelArch).Arch()
	a, bad := answerOf(err)
	if !bad {
		vv := v
		a = Answer{Text: &vv}
	}
	r.put(QueryArch, "", a)
	return v, err
}

func (r *Recorder) CheckStructField(st, field string, off, size int) ([]string, error) {
	d, err := r.under.(KernelStructFields).CheckStructField(st, field, off, size)
	return r.recDiffs(QueryStructField, st+"."+field+"/"+strconv.Itoa(off)+"/"+strconv.Itoa(size), d, err)
}

func (r *Recorder) HasKernelSymbol(name string) (bool, error) {
	v, err := r.under.(KernelSymbols).HasKernelSymbol(name)
	return r.recBool(QueryKernelSym, name, v, err)
}

func (r *Recorder) CheckFuncParam(name string, n int, typ string) ([]string, error) {
	d, err := r.under.(KernelFuncParams).CheckFuncParam(name, n, typ)
	return r.recDiffs(QueryFuncParam, name+"/"+strconv.Itoa(n)+"/"+typ, d, err)
}

// UprobeBinary forwards the reader but records SetBinaryPath. Without a path,
// record Unknown because replay cannot reopen the binary.
func (r *Recorder) UprobeBinary(program string) (io.ReaderAt, error) {
	b, err := r.under.(UprobeBinaries).UprobeBinary(program)
	a, bad := answerOf(err)
	if !bad {
		if p, ok := r.files[program]; ok {
			a = Answer{File: p}
		} else {
			a = Answer{Unknown: "the binary path was not given to the recorder"}
		}
	}
	r.put(QueryUprobeBin, program, a)
	return b, err
}

func (r *Recorder) UprobeDebugFile(program string, id []byte) (io.ReaderAt, error) {
	b, err := r.under.(UprobeDebugFiles).UprobeDebugFile(program, id)
	a, bad := answerOf(err)
	key := UprobeDebugKey(program, id)
	if !bad {
		r.mu.Lock()
		path := r.debugFiles[key]
		r.mu.Unlock()
		if path == "" {
			if named, ok := b.(interface{ Name() string }); ok {
				path = named.Name()
			}
		}
		if path == "" {
			a = Answer{Unknown: "the separate DWARF path was not given to the recorder"}
		} else {
			a = Answer{File: path}
		}
	}
	r.put(QueryUprobeDebug, key, a)
	return b, err
}

func (r *Recorder) AllowsMapField(pt string, ptID int64, field string) (bool, error) {
	v, err := r.under.(MapFieldPolicy).AllowsMapField(pt, ptID, field)
	return r.recBool(QueryMapField, pt+"/"+field, v, err)
}

func (r *Recorder) MarksNullableTPArgs() (bool, error) {
	v, err := r.under.(NullableArgCaps).MarksNullableTPArgs()
	return r.recBool(QueryNullableArgs, "", v, err)
}

// Forward only available queries, as established by capsAs/HasQuery.
func (r *Recorder) HasAttachType(pt string, ptID int64, at string) (bool, error) {
	v, err := r.under.(AttachTypeCaps).HasAttachType(pt, ptID, at)
	return r.recBool(QueryAttachType, pt+"/"+at, v, err)
}

func (r *Recorder) HasAttachTarget(at, kind, value string) (bool, error) {
	v, err := r.under.(AttachTargetCaps).HasAttachTarget(at, kind, value)
	return r.recBool(QueryAttachTarget, at+"/"+kind+":"+value, v, err)
}

func (r *Recorder) AllowsCtxAccess(pt string, ptID int64, at, st, field, mode string, bytes int) (bool, error) {
	v, err := r.under.(CtxAccessCaps).AllowsCtxAccess(pt, ptID, at, st, field, mode, bytes)
	return r.recBool(QueryCtxAccess, pt+"/"+at+"/"+st+"."+field+"/"+mode+"/"+strconv.Itoa(bytes), v, err)
}

// Forward only available queries, as established by capsAs/HasQuery.
func (r *Recorder) CheckTracepointField(event, field string, offset, bytes int, sign string) ([]string, error) {
	d, err := r.under.(TracepointFieldCaps).CheckTracepointField(event, field, offset, bytes, sign)
	return r.recDiffs(QueryTracepointFields, TPFieldKey(event, field, offset, bytes, sign), d, err)
}

func (r *Recorder) CheckStructOpsMember(strct, member string, nargs int, ret string, args []string) ([]string, error) {
	d, err := r.under.(StructOpsMemberCaps).CheckStructOpsMember(strct, member, nargs, ret, args)
	return r.recDiffs(QueryStructOpsMembers, StructOpsKey(strct, member, nargs, ret, args), d, err)
}

// CheckExtTarget queries the live replacement but records Unknown, not the
// answer: replay alone must block with ext_target_unknown. freplace needs live
// checks supplied with the actual replacement program.
func (r *Recorder) CheckExtTarget(program, fn string, nargs int, ret string, args []string) ([]string, error) {
	d, err := r.under.(ExtTargets).CheckExtTarget(program, fn, nargs, ret, args)
	r.put(QueryExtTargets, ExtTargetKey(program, fn, nargs, ret, args), Answer{Unknown: "the replacement target is a loader input and is not recorded (judge ext with the target program given to a live check)"})
	return d, err
}

// Forward only available queries, as established by capsAs/HasQuery.
func (r *Recorder) CheckKfunc(name, ret string, args []string) ([]string, error) {
	d, err := r.under.(KernelKfuncs).CheckKfunc(name, ret, args)
	return r.recDiffs(QueryKfuncProtos, KfuncKey(name, ret, args), d, err)
}

func (r *Recorder) CheckSyscallArg(name string, n int, typ string) ([]string, error) {
	d, err := r.under.(SyscallArgCaps).CheckSyscallArg(name, n, typ)
	return r.recDiffs(QuerySyscallArgs, SysargKey(name, n, typ), d, err)
}

func (r *Recorder) HasKfuncLoad(profile KfuncProfile, name, ret string, args []string) (bool, error) {
	args = append([]string{}, args...)
	key := KfuncLoadKey(profile, name, ret, args)
	v, err := r.under.(KernelKfuncLoadCaps).HasKfuncLoad(profile, name, ret, args)
	return r.recBool(QueryKfuncLoad, key, v, err)
}

func (r *Recorder) CheckTracepointBuffer(name, pointee string) ([]string, error) {
	d, err := r.under.(TracepointBufferCaps).CheckTracepointBuffer(name, pointee)
	return r.recDiffs(QueryTracepointBuffer, TracepointBufferKey(name, pointee), d, err)
}
