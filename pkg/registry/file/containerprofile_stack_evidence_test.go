package file

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/scheme"
	"github.com/kubescape/storage/pkg/generated/openapi"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/kube-openapi/pkg/schemaconv"
	"k8s.io/kube-openapi/pkg/validation/spec"
	smdschema "sigs.k8s.io/structured-merge-diff/v6/schema"
	"sigs.k8s.io/structured-merge-diff/v6/typed"
)

func TestContainerProfileLegacyStackEvidenceStorageCompatibility(t *testing.T) {
	// Produced by actual StorageImpl.Create/Get at v0.0.303 (d963c7941f5b), not current types.
	payload, err := os.ReadFile("testdata/v0.0.303-containerprofile.gob")
	require.NoError(t, err)
	expectedJSON, err := os.ReadFile("testdata/v0.0.303-containerprofile.json")
	require.NoError(t, err)
	want := &softwarecomposition.ContainerProfile{}
	require.NoError(t, json.Unmarshal(expectedJSON, want))
	s, _ := newGuardTestStorage(t, want.Namespace, want.Name)
	key := "/spdx.softwarecomposition.kubescape.io/containerprofiles/" + want.Namespace + "/" + want.Name
	impl := s.(*StorageImpl)
	path := makePayloadPath(filepath.Join(impl.root, key))
	require.NoError(t, impl.appFs.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, afero.WriteFile(impl.appFs, path, payload, 0600))
	got := &softwarecomposition.ContainerProfile{}
	require.NoError(t, s.Get(context.Background(), key, storage.GetOptions{}, got))
	require.Equal(t, want, got, "the original persisted profile must read without migration")
	require.Len(t, got.Spec.IdentifiedCallStacks, 1)
	stack := got.Spec.IdentifiedCallStacks[0]
	require.Nil(t, stack.Evidence)
	require.Nil(t, stack.CallStack.Root.Frame.Symbol)
	require.Nil(t, stack.CallStack.Root.Children[0].Frame.Symbol)
	require.Nil(t, stack.CallStack.Root.Children[0].Children[0].Frame.Symbol)
	// Rewriting a legacy nil-symbol profile must keep the same legacy values.
	rewrite := got.DeepCopy()
	rewrite.ResourceVersion = ""
	rewrite.Name += "-rewrite"
	require.NoError(t, s.Create(context.Background(), key+"-rewrite", rewrite, &softwarecomposition.ContainerProfile{}, 0))
	rewritten := &softwarecomposition.ContainerProfile{}
	require.NoError(t, s.Get(context.Background(), key+"-rewrite", storage.GetOptions{}, rewritten))
	require.Equal(t, want.Spec.IdentifiedCallStacks, rewritten.Spec.IdentifiedCallStacks)
}

func stackEvidenceProfile() *softwarecomposition.ContainerProfile {
	line, column, bci, address := uint32(42), uint32(0), uint32(0), "18446744073709551615"
	evidence := &softwarecomposition.CallStackEvidence{
		SchemaVersion: 1, Provider: "hotspot", RuntimeProfile: "observed",
		EventScope: "selected-openat", IdentityScope: "process-generation",
		PolicyEligibility: false, GlobalCollectionComplete: false,
		JVMBuildID: "build", JVMSHA256: "jvm-sha", GadgetRevision: "gadget-rev",
		ProfilerRevision: "profiler-rev", PatchSHA256: "patch-sha",
	}
	profile := groupedUserCP("kubescape", "stack-evidence")
	profile.Spec.IdentifiedCallStacks = []softwarecomposition.IdentifiedCallStack{{
		CallID: "observed", Evidence: evidence,
		CallStack: softwarecomposition.CallStack{Root: softwarecomposition.CallStackNode{
			Children: []softwarecomposition.CallStackNode{
				{Children: []softwarecomposition.CallStackNode{}, Frame: softwarecomposition.StackFrame{FrameType: 6,
					Symbol: &softwarecomposition.FrameSymbol{
						SchemaVersion: 1, Provider: "hotspot", FunctionName: "routeA", SourceFile: "Route.java",
						SourceLine: &line, SourceColumn: &column, NativeAddress: &address, BytecodeIndex: &bci,
						RawPosition: "18446744073709551615", PositionDomain: "jvm", ScopeLookup: "method",
						ScopeWalk: "physical", BCIState: "observed", QualityDiagnostic: "partial",
					}}},
				{Children: []softwarecomposition.CallStackNode{}, Frame: softwarecomposition.StackFrame{FrameType: 6,
					Symbol: &softwarecomposition.FrameSymbol{SchemaVersion: 1, Provider: "hotspot", FunctionName: "routeB"}}},
			},
		}},
	}}
	conflict := profile.Spec.IdentifiedCallStacks[0].DeepCopy()
	conflict.Evidence.RuntimeProfile = "independent"
	profile.Spec.IdentifiedCallStacks = append(profile.Spec.IdentifiedCallStacks, *conflict)
	profile.Spec.Containers[0].IdentifiedCallStacks = profile.Spec.DeepCopy().IdentifiedCallStacks
	profile.Spec.InitContainers[0].IdentifiedCallStacks = profile.Spec.DeepCopy().IdentifiedCallStacks
	profile.Spec.EphemeralContainers[0].IdentifiedCallStacks = profile.Spec.DeepCopy().IdentifiedCallStacks
	return profile
}

func requireStackEvidence(t *testing.T, want, got []softwarecomposition.IdentifiedCallStack) {
	t.Helper()
	require.Len(t, got, len(want), "independent same-CallID evidence groups must survive")
	byEvidence := make(map[softwarecomposition.CallStackEvidence]softwarecomposition.IdentifiedCallStack)
	for _, stack := range want {
		byEvidence[*stack.Evidence] = stack
	}
	for _, stack := range got {
		require.NotNil(t, stack.Evidence)
		expected, ok := byEvidence[*stack.Evidence]
		require.True(t, ok, "unexpected evidence: %#v", stack.Evidence)
		delete(byEvidence, *stack.Evidence)
		require.Equal(t, expected.CallID, stack.CallID)
		require.Equal(t, expected.CallStack.Root.Frame, stack.CallStack.Root.Frame)
		var wantFrames, gotFrames []softwarecomposition.StackFrame
		for _, child := range expected.CallStack.Root.Children {
			require.Empty(t, child.Children)
			wantFrames = append(wantFrames, child.Frame)
		}
		for _, child := range stack.CallStack.Root.Children {
			require.Empty(t, child.Children)
			gotFrames = append(gotFrames, child.Frame)
		}
		require.ElementsMatch(t, wantFrames, gotFrames)
	}
	require.Empty(t, byEvidence)
}

func TestStackEvidenceGobOptionalZeroPresence(t *testing.T) {
	zero, empty := uint32(0), ""
	want := softwarecomposition.StackFrame{FrameType: 6, Symbol: &softwarecomposition.FrameSymbol{
		SchemaVersion: 1, Provider: "hotspot", FunctionName: "route",
		SourceLine: &zero, SourceColumn: &zero, BytecodeIndex: &zero, NativeAddress: &empty,
	}}
	var payload bytes.Buffer
	require.NoError(t, gob.NewEncoder(&payload).Encode(want))
	var got softwarecomposition.StackFrame
	require.NoError(t, gob.NewDecoder(&payload).Decode(&got))
	require.Equal(t, want, got, "the actual file-storage codec must distinguish present zero from absent metadata")
}

func TestContainerProfileStackEvidenceFileStorageAndConversion(t *testing.T) {
	input := stackEvidenceProfile()
	want := input.DeepCopy()
	s, _ := newGuardTestStorage(t, input.Namespace, input.Name)
	key := "/spdx.softwarecomposition.kubescape.io/containerprofiles/" + input.Namespace + "/" + input.Name
	require.NoError(t, s.Create(context.Background(), key, input, &softwarecomposition.ContainerProfile{}, 0))
	got := &softwarecomposition.ContainerProfile{}
	require.NoError(t, s.Get(context.Background(), key, storage.GetOptions{}, got))
	requireStackEvidence(t, want.Spec.IdentifiedCallStacks, got.Spec.IdentifiedCallStacks)
	require.Len(t, got.Spec.Containers, 1)
	require.Len(t, got.Spec.InitContainers, 1)
	require.Len(t, got.Spec.EphemeralContainers, 1)
	requireStackEvidence(t, want.Spec.Containers[0].IdentifiedCallStacks, got.Spec.Containers[0].IdentifiedCallStacks)
	requireStackEvidence(t, want.Spec.InitContainers[0].IdentifiedCallStacks, got.Spec.InitContainers[0].IdentifiedCallStacks)
	requireStackEvidence(t, want.Spec.EphemeralContainers[0].IdentifiedCallStacks, got.Spec.EphemeralContainers[0].IdentifiedCallStacks)

	versioned := &v1beta1.ContainerProfile{}
	require.NoError(t, scheme.Scheme.Convert(got, versioned, nil))
	back := &softwarecomposition.ContainerProfile{}
	require.NoError(t, scheme.Scheme.Convert(versioned, back, nil))
	require.Equal(t, got, back, "the real Scheme must retain every typed field")

	// Scheme conversions may alias; generated DeepCopy is the ownership boundary.
	internalCopy := got.DeepCopy()
	versionedCopy := versioned.DeepCopy()
	require.Equal(t, got, internalCopy)
	require.Equal(t, versioned, versionedCopy)
	internalCopy.Spec.IdentifiedCallStacks[0].Evidence.Provider = "mutated"
	versionedCopy.Spec.IdentifiedCallStacks[0].Evidence.Provider = "mutated"
	for i := range internalCopy.Spec.IdentifiedCallStacks[0].CallStack.Root.Children {
		symbol := internalCopy.Spec.IdentifiedCallStacks[0].CallStack.Root.Children[i].Frame.Symbol
		symbol.FunctionName = "mutated"
		if symbol.SourceLine != nil {
			*symbol.SourceLine, *symbol.SourceColumn, *symbol.BytecodeIndex, *symbol.NativeAddress = 1, 2, 3, "4"
		}
	}
	for i := range versionedCopy.Spec.IdentifiedCallStacks[0].CallStack.Root.Children {
		symbol := versionedCopy.Spec.IdentifiedCallStacks[0].CallStack.Root.Children[i].Frame.Symbol
		symbol.FunctionName = "mutated"
		if symbol.SourceLine != nil {
			*symbol.SourceLine, *symbol.SourceColumn, *symbol.BytecodeIndex, *symbol.NativeAddress = 5, 6, 7, "8"
		}
	}
	requireStackEvidence(t, want.Spec.IdentifiedCallStacks, got.Spec.IdentifiedCallStacks)
	require.Equal(t, got, back)
	got.Spec.IdentifiedCallStacks[0].Evidence.Provider = "changed-after-read"
	again := &softwarecomposition.ContainerProfile{}
	require.NoError(t, s.Get(context.Background(), key, storage.GetOptions{}, again))
	requireStackEvidence(t, want.Spec.IdentifiedCallStacks, again.Spec.IdentifiedCallStacks)
}

func TestStackEvidencePublishedOpenAPISMDConversion(t *testing.T) {
	defs := openapi.GetOpenAPIDefinitions(func(name string) spec.Ref {
		return spec.MustCreateRef("#/definitions/" + name)
	})
	frameName := v1beta1.StackFrame{}.OpenAPIModelName()
	symbolName := v1beta1.FrameSymbol{}.OpenAPIModelName()
	stackName := v1beta1.IdentifiedCallStack{}.OpenAPIModelName()
	evidenceName := v1beta1.CallStackEvidence{}.OpenAPIModelName()
	symbolProperty := defs[frameName].Schema.Properties["symbol"]
	evidenceProperty := defs[stackName].Schema.Properties["evidence"]
	require.Equal(t, "#/definitions/"+symbolName, symbolProperty.Ref.String())
	require.Equal(t, "#/definitions/"+evidenceName, evidenceProperty.Ref.String())
	require.NotContains(t, defs[frameName].Schema.Required, "symbol")
	require.NotContains(t, defs[stackName].Schema.Required, "evidence")

	models := map[string]*spec.Schema{}
	var addModel func(string)
	addModel = func(name string) {
		if _, ok := models[name]; ok {
			return
		}
		definition, ok := defs[name]
		require.True(t, ok, "missing published definition %s", name)
		models[name] = &definition.Schema
		for _, dependency := range definition.Dependencies {
			addModel(dependency)
		}
	}
	profileName := v1beta1.ContainerProfile{}.OpenAPIModelName()
	addModel(profileName)
	typeSchema, err := schemaconv.ToSchemaFromOpenAPI(models, false)
	require.NoError(t, err)
	parser := typed.Parser{Schema: smdschema.Schema{Types: typeSchema.Types}}
	internal := stackEvidenceProfile()
	require.NoError(t, softwarecomposition.AddToScheme(scheme.Scheme))
	versioned := &v1beta1.ContainerProfile{}
	require.NoError(t, scheme.Scheme.Convert(internal, versioned, nil))
	data, err := json.Marshal(versioned)
	require.NoError(t, err)
	var object map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &object))
	for _, rawStack := range object["spec"].(map[string]interface{})["identifiedCallStacks"].([]interface{}) {
		stack := rawStack.(map[string]interface{})
		evidence := stack["evidence"].(map[string]interface{})
		require.Contains(t, evidence, "policyEligibility")
		require.Contains(t, evidence, "globalCollectionComplete")
		require.Equal(t, false, evidence["policyEligibility"])
		require.Equal(t, false, evidence["globalCollectionComplete"])
	}
	value, err := parser.Type(profileName).FromUnstructured(object)
	require.NoError(t, err, "published ContainerProfile schema must accept typed evidence")
	require.Equal(t, object, value.AsValue().Unstructured(), "SMD must retain all values and absent locations")
	var roundTrip v1beta1.ContainerProfile
	data, err = json.Marshal(value.AsValue().Unstructured())
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &roundTrip))
	require.Equal(t, versioned, &roundTrip)
	for _, stack := range roundTrip.Spec.IdentifiedCallStacks {
		require.False(t, stack.Evidence.PolicyEligibility)
		require.False(t, stack.Evidence.GlobalCollectionComplete)
		for _, child := range stack.CallStack.Root.Children {
			if child.Frame.Symbol.FunctionName == "routeB" {
				require.Nil(t, child.Frame.Symbol.SourceLine)
				require.Nil(t, child.Frame.Symbol.SourceColumn)
				require.Nil(t, child.Frame.Symbol.NativeAddress)
				require.Nil(t, child.Frame.Symbol.BytecodeIndex)
			}
		}
	}
}
