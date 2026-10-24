package v1beta1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	internal "github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"k8s.io/apimachinery/pkg/runtime"
)

func stackEvidenceFixture() *ContainerProfile {
	line, column, bci, address := uint32(19), uint32(3), uint32(7), "18446744073709551615"
	return &ContainerProfile{Spec: ContainerProfileSpec{
		IdentifiedCallStacks: []IdentifiedCallStack{{
			CallID: "observed-stack-a",
			Evidence: &CallStackEvidence{
				SchemaVersion: 1, Provider: "otel-ebpf-profiler-via-gadget",
				RuntimeProfile: "otel_hotspot25_observed_v1", EventScope: "openat_handler_entry",
				IdentityScope:     "otel-observed-provider-frames/v1",
				PolicyEligibility: false, GlobalCollectionComplete: false,
				JVMBuildID: "fixture-jvm-build", JVMSHA256: "fixture-jvm-sha256",
				GadgetRevision: "fixture-gadget", ProfilerRevision: "fixture-profiler", PatchSHA256: "fixture-patch",
			},
			CallStack: CallStack{Root: CallStackNode{Frame: StackFrame{
				// Fixture data, not a provider enum declaration.
				FrameType: 6,
				Symbol: &FrameSymbol{
					SchemaVersion: 1, Provider: "otel-ebpf-profiler-via-gadget",
					FunctionName: "void Fixture.routeA(java.lang.String)", SourceFile: "Fixture.java",
					SourceLine: &line, SourceColumn: &column, BytecodeIndex: &bci, NativeAddress: &address,
					RawPosition: "9007199254740993", PositionDomain: "provider_hotspot_bci_or_fallback",
					ScopeLookup: "fixture-lookup", ScopeWalk: "fixture-walk", BCIState: "fixture-known",
					QualityDiagnostic: "native_metadata_observed",
				},
			}}},
		}},
	}}
}

func TestStackEvidenceSurvivesProtobuf(t *testing.T) {
	want := stackEvidenceFixture()
	raw, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got := &ContainerProfile{}
	if err := got.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want.Spec.IdentifiedCallStacks, got.Spec.IdentifiedCallStacks) {
		t.Fatalf("protobuf lost typed evidence: want %+v, got %+v", want.Spec.IdentifiedCallStacks[0], got.Spec.IdentifiedCallStacks[0])
	}
}

func TestStackEvidenceSurvivesJSON(t *testing.T) {
	want := stackEvidenceFixture()
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`"policyEligibility":false`, `"globalCollectionComplete":false`,
		`"nativeAddress":"18446744073709551615"`, `"rawPosition":"9007199254740993"`,
		`"fileID":""`, `"lineno":""`,
	} {
		if !bytes.Contains(raw, []byte(required)) {
			t.Fatalf("JSON missing %s: %s", required, raw)
		}
	}
	got := &ContainerProfile{}
	if err := json.Unmarshal(raw, got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("JSON lost typed evidence: %s", raw)
	}
}

func TestStackEvidenceOptionalLocations(t *testing.T) {
	zero, max, zeroAddress := uint32(0), ^uint32(0), "0"
	for _, tc := range []struct {
		name   string
		symbol *FrameSymbol
	}{
		{"legacy-nil", nil},
		{"unknown-source", &FrameSymbol{SchemaVersion: 1, Provider: "fixture", RawPosition: "18446744073709551615", PositionDomain: "unknown", BCIState: "unknown"}},
		{"explicit-zero", &FrameSymbol{SourceLine: &zero, SourceColumn: &zero, BytecodeIndex: &zero, NativeAddress: &zeroAddress, RawPosition: "0"}},
		{"max-uint32", &FrameSymbol{SourceLine: &max, SourceColumn: &max, BytecodeIndex: &max}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := stackEvidenceFixture()
			want.Spec.IdentifiedCallStacks[0].CallStack.Root.Frame.Symbol = tc.symbol
			for _, encoding := range []string{"JSON", "protobuf"} {
				t.Run(encoding, func(t *testing.T) {
					got := &ContainerProfile{}
					var raw []byte
					var err error
					if encoding == "JSON" {
						raw, err = json.Marshal(want)
						if err == nil {
							err = json.Unmarshal(raw, got)
						}
					} else {
						raw, err = want.Marshal()
						if err == nil {
							err = got.Unmarshal(raw)
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(want.Spec.IdentifiedCallStacks, got.Spec.IdentifiedCallStacks) {
						t.Fatalf("%s changed nil/zero/source presence: %s", encoding, raw)
					}
				})
			}
		})
	}
}

func TestStackEvidenceDeepCopyOwnsPointers(t *testing.T) {
	want := stackEvidenceFixture()
	before, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	clone := want.DeepCopy()
	if !reflect.DeepEqual(want, clone) {
		t.Fatal("DeepCopy changed typed evidence")
	}
	stack := &clone.Spec.IdentifiedCallStacks[0]
	stack.Evidence.Provider = "changed"
	symbol := stack.CallStack.Root.Frame.Symbol
	symbol.FunctionName = "changed"
	*symbol.SourceLine = 22
	*symbol.SourceColumn = 9
	*symbol.BytecodeIndex = 0
	*symbol.NativeAddress = "0"
	after, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("DeepCopy aliases input: before %s, after %s", before, after)
	}
}

func TestStackEvidenceInternalConversionAndCopy(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := RegisterConversions(scheme); err != nil {
		t.Fatal(err)
	}
	for _, legacy := range []bool{false, true} {
		want := stackEvidenceFixture()
		if legacy {
			want.Spec.IdentifiedCallStacks[0].Evidence = nil
			want.Spec.IdentifiedCallStacks[0].CallStack.Root.Frame.Symbol = nil
		}
		in := &internal.ContainerProfile{}
		if err := scheme.Convert(want, in, nil); err != nil {
			t.Fatal(err)
		}
		got := &ContainerProfile{}
		if err := scheme.Convert(in, got, nil); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("internal conversion lost typed evidence (legacy=%v)", legacy)
		}
		before, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		clone := in.DeepCopy()
		if !reflect.DeepEqual(in, clone) {
			t.Fatal("internal DeepCopy changed evidence")
		}
		if !legacy {
			stack := &clone.Spec.IdentifiedCallStacks[0]
			stack.Evidence.Provider = "changed"
			symbol := stack.CallStack.Root.Frame.Symbol
			symbol.FunctionName = "changed"
			*symbol.SourceLine = 22
			*symbol.SourceColumn = 9
			*symbol.BytecodeIndex = 0
			*symbol.NativeAddress = "0"
		}
		after, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("internal DeepCopy aliases typed evidence")
		}
	}
}

func TestStackEvidenceLegacyBytes(t *testing.T) {
	// Captured from the unmodified storage base, not produced by the new code.
	const oldJSON = `{"callID":"legacy","callStack":{"root":{"children":null,"frame":{"fileID":"123","lineno":"19","frameType":6}}}}`
	const oldProto = "0a066c6567616379120f0a0d120b0a03313233120231391806"
	want := &IdentifiedCallStack{CallID: "legacy", CallStack: CallStack{Root: CallStackNode{Frame: StackFrame{FileID: "123", Lineno: "19", FrameType: 6}}}}
	j, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(j) != oldJSON {
		t.Fatalf("legacy JSON changed: %s", j)
	}
	b, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(b) != oldProto {
		t.Fatalf("legacy protobuf changed: %x", b)
	}
	for _, encoding := range []string{"JSON", "protobuf"} {
		got := &IdentifiedCallStack{}
		if encoding == "JSON" {
			err = json.Unmarshal([]byte(oldJSON), got)
		} else {
			err = got.Unmarshal(b)
		}
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s legacy read changed nil fields: %+v", encoding, got)
		}
	}
}

func TestStackEvidenceInternalLegacyJSON(t *testing.T) {
	const oldJSON = `{"CallID":"legacy","CallStack":{"Root":{"Children":null,"Frame":{"FileID":"123","Lineno":"19","FrameType":6}}}}`
	want := &internal.IdentifiedCallStack{CallID: "legacy", CallStack: internal.CallStack{Root: internal.CallStackNode{Frame: internal.StackFrame{FileID: "123", Lineno: "19", FrameType: 6}}}}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != oldJSON {
		t.Fatalf("internal legacy JSON changed: %s", raw)
	}
	got := &internal.IdentifiedCallStack{}
	if err := json.Unmarshal([]byte(oldJSON), got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("internal legacy read changed nil fields: %+v", got)
	}
}
