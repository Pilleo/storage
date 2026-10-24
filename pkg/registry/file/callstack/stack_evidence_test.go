package callstack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	types "github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"github.com/stretchr/testify/require"
)

func TestUnifyPreservesUnambiguousPathIdentity(t *testing.T) {
	typed := types.StackFrame{FrameType: 6, Symbol: &types.FrameSymbol{
		SchemaVersion: 1, Provider: "fixture", FunctionName: "route",
	}}
	encoded, err := json.Marshal(typed)
	require.NoError(t, err)
	digest := sha256.Sum256(encoded)
	legacy := types.StackFrame{FileID: "symbol-v1", Lineno: hex.EncodeToString(digest[:]), FrameType: 4}
	evidence := &types.CallStackEvidence{SchemaVersion: 1, Provider: "fixture"}
	for _, tc := range []struct {
		name  string
		paths [][]types.StackFrame
	}{
		{"typed-legacy-namespace", [][]types.StackFrame{{typed}, {legacy}}},
		{"legacy-field-boundary", [][]types.StackFrame{
			{{FileID: "a:b", Lineno: "c"}},
			{{FileID: "a", Lineno: "b:c"}},
		}},
		{"legacy-byte-identity", [][]types.StackFrame{
			{{FileID: "\xff", Lineno: "1"}},
			{{FileID: "\xfe", Lineno: "1"}},
		}},
		{"path-component-boundary", [][]types.StackFrame{
			{{FileID: "a", Lineno: "b/c:d"}},
			{{FileID: "a", Lineno: "b"}, {FileID: "c", Lineno: "d"}},
		}},
	} {
		for _, reverse := range []bool{false, true} {
			order := "forward"
			if reverse {
				order = "reverse"
			}
			t.Run(tc.name+"/"+order, func(t *testing.T) {
				var input []types.IdentifiedCallStack
				for _, path := range tc.paths {
					root := types.CallStackNode{Frame: path[len(path)-1]}
					for i := len(path) - 2; i >= 0; i-- {
						root = types.CallStackNode{Frame: path[i], Children: []types.CallStackNode{root}}
					}
					input = append(input, types.IdentifiedCallStack{
						CallID: "same-call", Evidence: evidence.DeepCopy(), CallStack: types.CallStack{Root: root},
					})
				}
				if reverse {
					input[0], input[1] = input[1], input[0]
				}
				got := UnifyIdentifiedCallStacks(input)
				require.Len(t, got, 1)
				require.Equal(t, types.CallID("same-call"), got[0].CallID)
				require.Equal(t, evidence, got[0].Evidence)
				require.Len(t, got[0].CallStack.Root.Children, 2, "distinct paths must not overwrite each other")
				var paths [][]types.StackFrame
				for _, root := range got[0].CallStack.Root.Children {
					var path []types.StackFrame
					for node := root; ; node = node.Children[0] {
						path = append(path, node.Frame)
						if len(node.Children) == 0 {
							break
						}
						require.Len(t, node.Children, 1)
					}
					paths = append(paths, path)
				}
				require.ElementsMatch(t, tc.paths, paths, "actual frames must survive; identities are not reconstruction data")
			})
		}
	}
}

func TestUnifyRetainsLegacyFrameEqualityAndKeys(t *testing.T) {
	a := types.StackFrame{FileID: "file:/with", Lineno: "line/:", FrameType: 4}
	b := a
	b.FrameType = 6
	require.True(t, framesEqual(a, b), "nil-symbol legacy equality ignores FrameType")
	require.Equal(t, "file:/with:line/:", frameKey(a))
	require.Equal(t, frameKey(a), frameKey(b))
	got := UnifyIdentifiedCallStacks([]types.IdentifiedCallStack{
		{CallID: "legacy", CallStack: types.CallStack{Root: types.CallStackNode{Frame: a}}},
		{CallID: "legacy", CallStack: types.CallStack{Root: types.CallStackNode{Frame: b}}},
	})
	require.Len(t, got, 1)
	require.Len(t, got[0].CallStack.Root.Children, 1)
}

func TestUnifyPreservesDistinctObservedFrames(t *testing.T) {
	a := types.StackFrame{FrameType: 6, Symbol: &types.FrameSymbol{SchemaVersion: 1, FunctionName: "routeA"}}
	b := types.StackFrame{FrameType: 6, Symbol: &types.FrameSymbol{SchemaVersion: 1, FunctionName: "routeB"}}
	input := []types.IdentifiedCallStack{{CallID: "observed", Evidence: &types.CallStackEvidence{SchemaVersion: 1},
		CallStack: types.CallStack{Root: types.CallStackNode{Children: []types.CallStackNode{
			{Frame: a}, {Frame: b},
		}}}}}
	got := UnifyIdentifiedCallStacks(input)
	require.Len(t, got, 1)
	require.Equal(t, input[0].Evidence, got[0].Evidence)
	require.Len(t, got[0].CallStack.Root.Children, 2, "typed paths collapsed")
	names := map[string]bool{}
	for _, n := range got[0].CallStack.Root.Children {
		require.NotNil(t, n.Frame.Symbol, "typed frame lost")
		require.EqualValues(t, 6, n.Frame.FrameType)
		names[n.Frame.Symbol.FunctionName] = true
	}
	require.Equal(t, map[string]bool{"routeA": true, "routeB": true}, names)
}

func TestUnifyPreservesSymbolOnlyRootAndLegacyFrameType(t *testing.T) {
	for _, frame := range []types.StackFrame{
		{FrameType: 6, Symbol: &types.FrameSymbol{FunctionName: "root/with:delimiters"}},
		{FileID: "legacy", Lineno: "9", FrameType: 4},
	} {
		input := []types.IdentifiedCallStack{{CallID: "root", CallStack: types.CallStack{Root: types.CallStackNode{Frame: frame}}}}
		got := UnifyIdentifiedCallStacks(input)
		require.Len(t, got, 1)
		require.Len(t, got[0].CallStack.Root.Children, 1)
		require.Equal(t, frame, got[0].CallStack.Root.Children[0].Frame)
	}
}

func TestUnifyPreservesSymbolContentIdentity(t *testing.T) {
	zero, address := uint32(0), "18446744073709551615"
	base := types.StackFrame{FrameType: 6, Symbol: &types.FrameSymbol{SchemaVersion: 1, FunctionName: "route"}}
	changes := map[string]func(*types.StackFrame){
		"fileID":            func(f *types.StackFrame) { f.FileID = "file" },
		"lineno":            func(f *types.StackFrame) { f.Lineno = "7" },
		"frameType":         func(f *types.StackFrame) { f.FrameType = 7 },
		"schemaVersion":     func(f *types.StackFrame) { f.Symbol.SchemaVersion = 2 },
		"provider":          func(f *types.StackFrame) { f.Symbol.Provider = "provider" },
		"functionName":      func(f *types.StackFrame) { f.Symbol.FunctionName = "other" },
		"sourceFile":        func(f *types.StackFrame) { f.Symbol.SourceFile = "Route.java" },
		"sourceLine":        func(f *types.StackFrame) { f.Symbol.SourceLine = &zero },
		"sourceColumn":      func(f *types.StackFrame) { f.Symbol.SourceColumn = &zero },
		"nativeAddress":     func(f *types.StackFrame) { f.Symbol.NativeAddress = &address },
		"bytecodeIndex":     func(f *types.StackFrame) { f.Symbol.BytecodeIndex = &zero },
		"rawPosition":       func(f *types.StackFrame) { f.Symbol.RawPosition = address },
		"positionDomain":    func(f *types.StackFrame) { f.Symbol.PositionDomain = "jvm" },
		"scopeLookup":       func(f *types.StackFrame) { f.Symbol.ScopeLookup = "method" },
		"scopeWalk":         func(f *types.StackFrame) { f.Symbol.ScopeWalk = "physical" },
		"bciState":          func(f *types.StackFrame) { f.Symbol.BCIState = "observed" },
		"qualityDiagnostic": func(f *types.StackFrame) { f.Symbol.QualityDiagnostic = "partial" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			other := base.DeepCopy()
			change(other)
			input := []types.IdentifiedCallStack{{CallID: "same", CallStack: types.CallStack{Root: types.CallStackNode{
				Children: []types.CallStackNode{{Frame: base}, {Frame: *base.DeepCopy()}, {Frame: *other}},
			}}}}
			got := UnifyIdentifiedCallStacks(input)
			require.Len(t, got, 1)
			require.Len(t, got[0].CallStack.Root.Children, 2, "equal content must merge; changed content must not")
			frames := []types.StackFrame{got[0].CallStack.Root.Children[0].Frame, got[0].CallStack.Root.Children[1].Frame}
			require.ElementsMatch(t, []types.StackFrame{base, *other}, frames)
			require.Equal(t, got, UnifyIdentifiedCallStacks(input), "symbol ordering must be stable")
		})
	}
}

func TestUnifyPreservesIndependentEvidenceGroups(t *testing.T) {
	base := types.CallStackEvidence{SchemaVersion: 1, Provider: "hotspot"}
	changes := map[string]func(*types.CallStackEvidence){
		"schemaVersion":            func(e *types.CallStackEvidence) { e.SchemaVersion = 2 },
		"provider":                 func(e *types.CallStackEvidence) { e.Provider = "other" },
		"runtimeProfile":           func(e *types.CallStackEvidence) { e.RuntimeProfile = "profile" },
		"eventScope":               func(e *types.CallStackEvidence) { e.EventScope = "openat" },
		"identityScope":            func(e *types.CallStackEvidence) { e.IdentityScope = "process" },
		"policyEligibility":        func(e *types.CallStackEvidence) { e.PolicyEligibility = true },
		"globalCollectionComplete": func(e *types.CallStackEvidence) { e.GlobalCollectionComplete = true },
		"jvmBuildID":               func(e *types.CallStackEvidence) { e.JVMBuildID = "build" },
		"jvmSHA256":                func(e *types.CallStackEvidence) { e.JVMSHA256 = "jvm" },
		"gadgetRevision":           func(e *types.CallStackEvidence) { e.GadgetRevision = "gadget" },
		"profilerRevision":         func(e *types.CallStackEvidence) { e.ProfilerRevision = "profiler" },
		"patchSHA256":              func(e *types.CallStackEvidence) { e.PatchSHA256 = "patch" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			other := base.DeepCopy()
			change(other)
			input := []types.IdentifiedCallStack{
				{CallID: "same", Evidence: &base}, {CallID: "same", Evidence: base.DeepCopy()},
				{CallID: "same", Evidence: other}, {CallID: "same"}, {CallID: "same"},
				{CallID: "same", Evidence: &types.CallStackEvidence{}},
			}
			for i := range input {
				input[i].CallStack.Root.Frame = types.StackFrame{FileID: "frame", Lineno: "1"}
			}
			got := UnifyIdentifiedCallStacks(input)
			require.Len(t, got, 4, "nil, zero and conflicting evidence must remain independent")
			var evidence []*types.CallStackEvidence
			for _, stack := range got {
				require.Equal(t, types.CallID("same"), stack.CallID)
				require.Len(t, stack.CallStack.Root.Children, 1)
				evidence = append(evidence, stack.Evidence)
			}
			require.ElementsMatch(t, []*types.CallStackEvidence{&base, other, nil, {}}, evidence)
		})
	}
}

func TestUnifyPreservesOwnedPointers(t *testing.T) {
	line, column, bci, address := uint32(9), uint32(2), uint32(0), "18446744073709551615"
	frame := types.StackFrame{FrameType: 6, Symbol: &types.FrameSymbol{
		SchemaVersion: 1, FunctionName: "route", SourceLine: &line, SourceColumn: &column,
		BytecodeIndex: &bci, NativeAddress: &address,
	}}
	input := []types.IdentifiedCallStack{{CallID: "owned", Evidence: &types.CallStackEvidence{SchemaVersion: 1},
		CallStack: types.CallStack{Root: types.CallStackNode{Frame: frame}}}}
	want := input[0].DeepCopy()
	got := UnifyIdentifiedCallStacks(input)
	require.Len(t, got, 1)
	require.NotNil(t, got[0].Evidence)
	require.Len(t, got[0].CallStack.Root.Children, 1)
	owned := &got[0].CallStack.Root.Children[0].Frame
	require.Equal(t, want.CallStack.Root.Frame, *owned)
	input[0].Evidence.SchemaVersion = 2
	frame.Symbol.FunctionName = "changed"
	line, column, bci, address = 90, 20, 10, "0"
	require.Equal(t, want.Evidence, got[0].Evidence)
	require.Equal(t, want.CallStack.Root.Frame, *owned)
	got[0].Evidence.Provider = "output"
	*owned.Symbol.SourceLine = 3
	require.Empty(t, input[0].Evidence.Provider)
	require.EqualValues(t, 90, *frame.Symbol.SourceLine)
}
