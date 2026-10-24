package openapi

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	v1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/kube-openapi/pkg/validation/spec"
	"k8s.io/kube-openapi/pkg/validation/strfmt"
	"k8s.io/kube-openapi/pkg/validation/validate"
)

func TestStackEvidenceOpenAPI(t *testing.T) {
	ref := func(name string) spec.Ref { return spec.MustCreateRef("#/definitions/" + name) }
	defs := GetOpenAPIDefinitions(ref)
	for _, tc := range []struct {
		parent, field, child string
	}{
		{v1beta1.StackFrame{}.OpenAPIModelName(), "symbol", v1beta1.FrameSymbol{}.OpenAPIModelName()},
		{v1beta1.IdentifiedCallStack{}.OpenAPIModelName(), "evidence", v1beta1.CallStackEvidence{}.OpenAPIModelName()},
	} {
		parent := defs[tc.parent]
		property := parent.Schema.Properties[tc.field]
		if property.Ref.String() != "#/definitions/"+tc.child || !slices.Contains(parent.Dependencies, tc.child) {
			t.Fatalf("published schema lost %s.%s reference to %s", tc.parent, tc.field, tc.child)
		}
		if slices.Contains(parent.Schema.Required, tc.field) {
			t.Fatalf("new field %s.%s breaks legacy absence", tc.parent, tc.field)
		}
	}
	for _, tc := range []struct {
		name       string
		required   []string
		properties map[string]string
		json       string
	}{
		{
			name: v1beta1.FrameSymbol{}.OpenAPIModelName(), required: []string{"schemaVersion", "provider"},
			properties: map[string]string{
				"schemaVersion": "integer", "provider": "string", "functionName": "string", "sourceFile": "string",
				"sourceLine": "integer", "sourceColumn": "integer", "nativeAddress": "string", "bytecodeIndex": "integer",
				"rawPosition": "string", "positionDomain": "string", "scopeLookup": "string", "scopeWalk": "string",
				"bciState": "string", "qualityDiagnostic": "string",
			},
			json: `{"schemaVersion":1,"provider":"fixture","functionName":"routeA","sourceFile":"Fixture.java","sourceLine":4294967295,"sourceColumn":0,"nativeAddress":"18446744073709551615","bytecodeIndex":7,"rawPosition":"9007199254740993","positionDomain":"fixture","scopeLookup":"observed","scopeWalk":"observed","bciState":"known","qualityDiagnostic":"native_metadata_observed"}`,
		},
		{
			name:     v1beta1.CallStackEvidence{}.OpenAPIModelName(),
			required: []string{"schemaVersion", "provider", "runtimeProfile", "eventScope", "identityScope", "policyEligibility", "globalCollectionComplete"},
			properties: map[string]string{
				"schemaVersion": "integer", "provider": "string", "runtimeProfile": "string", "eventScope": "string",
				"identityScope": "string", "policyEligibility": "boolean", "globalCollectionComplete": "boolean",
				"jvmBuildID": "string", "jvmSHA256": "string", "gadgetRevision": "string", "profilerRevision": "string", "patchSHA256": "string",
			},
			json: `{"schemaVersion":1,"provider":"fixture","runtimeProfile":"observed","eventScope":"openat_handler_entry","identityScope":"fixture/v1","policyEligibility":false,"globalCollectionComplete":false,"jvmBuildID":"build","jvmSHA256":"sha","gadgetRevision":"gadget","profilerRevision":"profiler","patchSHA256":"patch"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			schema := defs[tc.name].Schema
			if !reflect.DeepEqual(schema.Required, tc.required) || len(schema.Properties) != len(tc.properties) {
				t.Fatalf("incomplete published schema: %+v", schema)
			}
			for name, typ := range tc.properties {
				property, ok := schema.Properties[name]
				if !ok || !reflect.DeepEqual(property.Type, spec.StringOrArray{typ}) {
					t.Fatalf("schema lost typed property %s: %+v", name, property)
				}
				if typ == "integer" && property.Format != "int64" {
					t.Fatalf("uint32 property %s must accommodate values above MaxInt32", name)
				}
				if !slices.Contains(tc.required, name) && property.Default != nil {
					t.Fatalf("missing %s must not become a fabricated default", name)
				}
			}
			var value map[string]interface{}
			if err := json.Unmarshal([]byte(tc.json), &value); err != nil {
				t.Fatal(err)
			}
			if err := validate.AgainstSchema(&schema, value, strfmt.Default); err != nil {
				t.Fatalf("published schema rejects complete typed values: %v", err)
			}
			for name := range value {
				if !slices.Contains(tc.required, name) {
					delete(value, name)
				}
			}
			if err := validate.AgainstSchema(&schema, value, strfmt.Default); err != nil {
				t.Fatalf("published schema rejects absent unknown locations/revisions: %v", err)
			}
		})
	}
}
