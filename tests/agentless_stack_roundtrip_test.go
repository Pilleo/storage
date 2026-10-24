//go:build agentless_hotspot_integration

package tests

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	v1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const stackNamespace = "agentless-hotspot-test"

// This gate is deliberately excluded from unmodified make test. It never skips.
func TestStackEvidenceAPIRoundTrip(t *testing.T) {
	prereqs, err := stackPreflight(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	// Inspect only the explicitly supplied file, never implicit local context.
	kube, err := clientcmd.LoadFromFile(prereqs.kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	if kube.CurrentContext != prereqs.context || kube.Contexts[prereqs.context] == nil {
		t.Fatal("explicit kubeconfig current-context must equal AGENTLESS_HOTSPOT_CONTEXT")
	}
	baseConfig, err := clientcmd.BuildConfigFromFlags("", prereqs.kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(prereqs.output, "stack-api-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("owned live API body/media receipts: %s", dir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var failures []error
	for i, media := range []string{runtime.ContentTypeJSON, runtime.ContentTypeProtobuf} {
		mediaDir := filepath.Join(dir, fmt.Sprintf("%d", i))
		if err := os.Mkdir(mediaDir, 0700); err != nil {
			failures = append(failures, err)
			continue
		}
		failures = append(failures, stackAPIRoundTrip(ctx, baseConfig, media, mediaDir))
	}
	// Both per-format functions have returned, joining UID cleanup before this receipt.
	err = errors.Join(failures...)
	receipt, marshalErr := json.MarshalIndent(struct {
		Kind   string `json:"kind"`
		Passed bool   `json:"passed"`
	}{"live-api-gate-after-cleanup", err == nil}, "", "  ")
	err = errors.Join(err, marshalErr, os.WriteFile(filepath.Join(dir, "result.json"), receipt, 0600))
	if err != nil {
		t.Fatal(err)
	}
}

func stackAPIRoundTrip(ctx context.Context, base *rest.Config, media, dir string) (err error) {
	rc := rest.CopyConfig(base)
	rc.ContentType, rc.AcceptContentTypes, rc.Timeout = media, media, 30*time.Second
	recorder := &stackBodyRecorder{dir: dir, media: media}
	rc.Wrap(recorder.wrap)
	defer func() { err = errors.Join(err, recorder.check()) }()
	api, err := versioned.NewForConfig(rc)
	if err != nil {
		return err
	}
	profiles := api.SpdxV1beta1().ContainerProfiles(stackNamespace)
	want := stackAPIFixture()
	created, err := profiles.Create(ctx, want, metav1.CreateOptions{})
	if created != nil && created.Name != "" && created.UID != "" && created.Namespace == stackNamespace {
		defer func() { err = errors.Join(err, stackCleanup(profiles, created)) }()
	}
	if err != nil {
		return fmt.Errorf("%s Create: %w", media, err)
	}
	if created == nil || created.Name == "" || created.UID == "" || created.Namespace != stackNamespace {
		return fmt.Errorf("%s Create lacks acquired name/UID/namespace; inspect response for unresolved ownership", media)
	}
	if err := stackCompareTyped(want, created); err != nil {
		return fmt.Errorf("%s Create: %w", media, err)
	}
	got, err := profiles.Get(ctx, created.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("%s Get: %w", media, err)
	}
	if got.UID != created.UID || got.Namespace != stackNamespace || got.Name != created.Name {
		return fmt.Errorf("%s Get changed object identity", media)
	}
	return stackCompareTyped(want, got)
}

func stackAPIFixture() *v1beta1.ContainerProfile {
	zero, max, address := uint32(0), ^uint32(0), "18446744073709551615"
	zeroAddress := "0"
	full := &v1beta1.FrameSymbol{
		SchemaVersion: 1, Provider: "otel-ebpf-profiler-via-gadget",
		FunctionName: "void Fixture.routeA(java.lang.String)", SourceFile: "Fixture.java",
		SourceLine: &zero, SourceColumn: &max, BytecodeIndex: &zero, NativeAddress: &address,
		RawPosition: "9007199254740993", PositionDomain: "provider_hotspot_bci_or_fallback",
		ScopeLookup: "fixture-lookup", ScopeWalk: "fixture-walk", BCIState: "fixture-known",
		QualityDiagnostic: "native_metadata_observed",
	}
	evidence := &v1beta1.CallStackEvidence{
		SchemaVersion: 1, Provider: "otel-ebpf-profiler-via-gadget",
		RuntimeProfile: "otel_hotspot25_observed_v1", EventScope: "openat_handler_entry",
		IdentityScope: "otel-observed-provider-frames/v1", PolicyEligibility: false, GlobalCollectionComplete: false,
		JVMBuildID: "fixture-jvm-build", JVMSHA256: "fixture-jvm-sha256", GadgetRevision: "fixture-gadget",
		ProfilerRevision: "fixture-profiler", PatchSHA256: "fixture-patch",
	}
	root := v1beta1.CallStackNode{Frame: v1beta1.StackFrame{FrameType: 6, Symbol: full}, Children: []v1beta1.CallStackNode{
		{Frame: v1beta1.StackFrame{Symbol: &v1beta1.FrameSymbol{SchemaVersion: 1, Provider: full.Provider, FunctionName: "unknown-source", RawPosition: address}}},
		{Frame: v1beta1.StackFrame{Symbol: &v1beta1.FrameSymbol{SchemaVersion: 1, Provider: full.Provider, SourceLine: &max, SourceColumn: &zero, BytecodeIndex: &max, NativeAddress: &zeroAddress, RawPosition: "0"}}},
	}}
	return &v1beta1.ContainerProfile{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1beta1.SchemeGroupVersion.String(), Kind: "ContainerProfile"},
		ObjectMeta: metav1.ObjectMeta{GenerateName: "typed-stack-", Namespace: stackNamespace, Annotations: map[string]string{"kubescape.io/managed-by": "User"}},
		Spec: v1beta1.ContainerProfileSpec{Architectures: []string{"amd64"}, IdentifiedCallStacks: []v1beta1.IdentifiedCallStack{
			{CallID: "typed-a", Evidence: evidence, CallStack: v1beta1.CallStack{Root: root}},
			{CallID: "legacy-nil", CallStack: v1beta1.CallStack{Root: v1beta1.CallStackNode{Frame: v1beta1.StackFrame{FileID: "123", Lineno: "19", FrameType: 6}}}},
		}},
	}
}

// These are local helper tests, not API acceptance or simulated API receipts.
func TestStackEvidenceHelpersPreflight(t *testing.T) {
	for _, env := range []map[string]string{
		{},
		{"KUBECONFIG": "/explicit/config"},
		{"KUBECONFIG": "/explicit/config", "AGENTLESS_HOTSPOT_CONTEXT": "approved"},
		{"KUBECONFIG": "relative", "AGENTLESS_HOTSPOT_CONTEXT": "approved", "AGENTLESS_HOTSPOT_OUTPUT_DIR": "/receipts"},
		{"KUBECONFIG": "/one:/two", "AGENTLESS_HOTSPOT_CONTEXT": "approved", "AGENTLESS_HOTSPOT_OUTPUT_DIR": "/receipts"},
	} {
		if _, err := stackPreflight(func(k string) string { return env[k] }); err == nil {
			t.Fatalf("missing/ambiguous explicit prerequisites accepted: %v", env)
		}
	}
	env := map[string]string{"KUBECONFIG": "/explicit/config", "AGENTLESS_HOTSPOT_CONTEXT": "approved", "AGENTLESS_HOTSPOT_OUTPUT_DIR": "/receipts"}
	if _, err := stackPreflight(func(k string) string { return env[k] }); err != nil {
		t.Fatal(err)
	}
}

type stackTransportFunc func(*http.Request) (*http.Response, error)

func (f stackTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStackEvidenceHelpersBodiesAndNegotiation(t *testing.T) {
	for _, media := range []string{"application/json", "application/vnd.kubernetes.protobuf"} {
		t.Run(media, func(t *testing.T) {
			dir := t.TempDir()
			recorder := &stackBodyRecorder{dir: dir, media: media}
			requestBody, responseBody := []byte{0, 1, 255}, []byte{4, 0, 254}
			if media == runtime.ContentTypeJSON {
				var err error
				responseBody, err = json.Marshal(stackAPIFixture())
				if err != nil {
					t.Fatal(err)
				}
			}
			next := stackTransportFunc(func(r *http.Request) (*http.Response, error) {
				raw, err := io.ReadAll(r.Body)
				if err != nil || !bytes.Equal(raw, requestBody) {
					t.Fatalf("recorder changed outgoing body: %x, %v", raw, err)
				}
				return &http.Response{StatusCode: 201, Header: http.Header{"Content-Type": {media + "; charset=binary"}, "Set-Cookie": {"SECRET"}}, Body: io.NopCloser(bytes.NewReader(responseBody))}, nil
			})
			req, _ := http.NewRequest(http.MethodPost, "https://unused.invalid", bytes.NewReader(requestBody))
			req.Header.Set("Content-Type", media)
			req.Header.Set("Accept", media)
			req.Header.Set("Authorization", "SECRET")
			resp, err := recorder.wrap(next).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			raw, err := io.ReadAll(resp.Body)
			if err != nil || !bytes.Equal(raw, responseBody) {
				t.Fatalf("changed incoming body: %x, %v", raw, err)
			}
			if err := recorder.check(); err != nil {
				t.Fatal(err)
			}
			for name, want := range map[string][]byte{"001-request.body": requestBody, "001-response.body": responseBody} {
				got, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("receipt %s: %x, %v", name, got, err)
				}
			}
			meta, err := os.ReadFile(filepath.Join(dir, "001-media.json"))
			if err != nil || bytes.Contains(meta, []byte("SECRET")) || !bytes.Contains(meta, []byte(media)) {
				t.Fatalf("unsafe/missing media receipt: %s, %v", meta, err)
			}
		})
	}
}

// Exercise the actual generated client's request encoder, then deliberately fail
// locally: no server response, synthetic API success, or live receipt is produced.
func TestStackEvidenceHelpersGeneratedClientNegotiation(t *testing.T) {
	for _, media := range []string{runtime.ContentTypeJSON, runtime.ContentTypeProtobuf} {
		t.Run(media, func(t *testing.T) {
			r := &stackBodyRecorder{dir: t.TempDir(), media: media}
			stopped := errors.New("local helper stopped before network")
			called := false
			rc := &rest.Config{Host: "https://unused.invalid", ContentConfig: rest.ContentConfig{ContentType: media, AcceptContentTypes: media}}
			rc.WrapTransport = func(_ http.RoundTripper) http.RoundTripper {
				return r.wrap(stackTransportFunc(func(req *http.Request) (*http.Response, error) {
					called = true
					raw, err := io.ReadAll(req.Body)
					if err != nil {
						t.Fatal(err)
					}
					obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(raw, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					if err := stackCompareTyped(stackAPIFixture(), obj.(*v1beta1.ContainerProfile)); err != nil {
						t.Fatal(err)
					}
					return nil, stopped
				}))
			}
			api, err := versioned.NewForConfig(rc)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = api.SpdxV1beta1().ContainerProfiles(stackNamespace).Create(ctx, stackAPIFixture(), metav1.CreateOptions{})
			if !called || !errors.Is(err, stopped) {
				t.Fatalf("generated-client request failed before local boundary: %v", err)
			}
		})
	}
}

func TestStackEvidenceHelpersFailurePaths(t *testing.T) {
	for _, tc := range []string{"wrong-response-media", "wrong-accept", "write-failure", "transport-failure"} {
		t.Run(tc, func(t *testing.T) {
			dir := t.TempDir()
			if tc == "write-failure" {
				dir = filepath.Join(dir, "not-created")
			}
			r := &stackBodyRecorder{dir: dir, media: "application/vnd.kubernetes.protobuf"}
			sentinel := errors.New("original transport error")
			called := false
			next := stackTransportFunc(func(req *http.Request) (*http.Response, error) {
				called = true
				if tc == "transport-failure" {
					return nil, sentinel
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader([]byte("body")))}, nil
			})
			req, _ := http.NewRequest(http.MethodGet, "https://unused.invalid", nil)
			req.Header.Set("Accept", r.media)
			if tc == "wrong-accept" {
				req.Header.Set("Accept", "*/*")
			}
			resp, err := r.wrap(next).RoundTrip(req)
			if resp != nil {
				resp.Body.Close()
			}
			if tc == "transport-failure" && !errors.Is(err, sentinel) {
				t.Fatalf("lost original error: %v", err)
			}
			if (tc == "wrong-accept" || tc == "write-failure") && called {
				t.Fatal("unsafe request reached transport")
			}
			if errors.Join(err, r.check()) == nil {
				t.Fatal("receipt/negotiation failure accepted")
			}
		})
	}
}

func TestStackEvidenceHelpersReceiptFailureMustNotBlockCleanup(t *testing.T) {
	r := &stackBodyRecorder{dir: filepath.Join(t.TempDir(), "missing"), media: runtime.ContentTypeJSON}
	called := false
	next := stackTransportFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {runtime.ContentTypeJSON}}, Body: io.NopCloser(strings.NewReader("cleanup response"))}, nil
	})
	req, _ := http.NewRequest(http.MethodDelete, "https://unused.invalid", nil)
	req.Header.Set("Accept", runtime.ContentTypeJSON)
	resp, err := r.wrap(next).RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	if !called || err != nil {
		t.Fatalf("receipt storage failure prevented cleanup: called=%v err=%v", called, err)
	}
	if r.check() == nil {
		t.Fatal("receipt failure was lost")
	}
}

func TestStackEvidenceHelpersJSONFalsePresence(t *testing.T) {
	cases := []struct{ method, field, mutation string }{{mutation: "explicit-false"}}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		cases = append(cases, struct{ method, field, mutation string }{method, "evidence", "case-alias"})
		for _, field := range []string{"policyEligibility", "globalCollectionComplete"} {
			for _, mutation := range []string{"omitted", "case-alias", "null"} {
				cases = append(cases, struct{ method, field, mutation string }{method, field, mutation})
			}
		}
	}
	for _, tc := range cases {
		t.Run(tc.method+"/"+tc.field+"/"+tc.mutation, func(t *testing.T) {
			profile := stackAPIFixture()
			profile.Name, profile.UID, profile.ResourceVersion = "typed-stack-owned", "server-uid", "1"
			original, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			changed := original
			if tc.field != "" {
				var object map[string]interface{}
				if err := json.Unmarshal(original, &object); err != nil {
					t.Fatal(err)
				}
				stacks := object["spec"].(map[string]interface{})["identifiedCallStacks"].([]interface{})
				evidence := stacks[0].(map[string]interface{})["evidence"].(map[string]interface{})
				fields := evidence
				if tc.field == "evidence" {
					fields = stacks[0].(map[string]interface{})
				}
				delete(fields, tc.field)
				switch tc.mutation {
				case "case-alias":
					value := interface{}(false)
					if tc.field == "evidence" {
						value = evidence
					}
					fields[strings.ToUpper(tc.field[:1])+tc.field[1:]] = value
				case "null":
					fields[tc.field] = nil
				}
				object["unrelated"] = map[string]interface{}{"policyEligibility": false, "globalCollectionComplete": false}
				changed, err = json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
			}
			var calls []string
			deleted := false
			rc := &rest.Config{Host: "https://unused.invalid"}
			rc.WrapTransport = func(_ http.RoundTripper) http.RoundTripper {
				return stackTransportFunc(func(req *http.Request) (*http.Response, error) {
					calls = append(calls, req.Method)
					path := "/namespaces/" + stackNamespace + "/containerprofiles"
					if req.Method != http.MethodPost {
						path += "/" + profile.Name
					}
					if !strings.HasSuffix(req.URL.Path, path) {
						t.Fatalf("unexpected generated-client route: %s", req.URL.Path)
					}
					body, status := original, http.StatusOK
					switch req.Method {
					case http.MethodPost:
						status = http.StatusCreated
					case http.MethodGet:
					case http.MethodDelete:
						var options metav1.DeleteOptions
						if err := json.NewDecoder(req.Body).Decode(&options); err != nil {
							t.Fatal(err)
						}
						if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != profile.UID {
							t.Fatal("wire validation failure lost the acquired UID-preconditioned cleanup")
						}
						if req.Context().Err() != nil {
							t.Fatal("cleanup context is already cancelled")
						}
						deleted = true
						body = []byte(`{"kind":"Status","apiVersion":"v1","status":"Success"}`)
					default:
						t.Fatalf("unexpected method %s", req.Method)
					}
					if req.Method == tc.method {
						body = changed
					}
					return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {runtime.ContentTypeJSON}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
				})
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = stackAPIRoundTrip(ctx, rc, runtime.ContentTypeJSON, t.TempDir())
			wantCalls := "POST GET DELETE"
			if tc.method == http.MethodPost && tc.field == "evidence" {
				wantCalls = "POST DELETE" // The scheme decoder prunes this alias, so typed Create comparison fails first.
			}
			if !deleted || strings.Join(calls, " ") != wantCalls {
				t.Fatalf("Create/Get must acquire and clean up the actual UID before wire rejection: calls=%v deleted=%v err=%v", calls, deleted, err)
			}
			if tc.field == "" {
				if err != nil {
					t.Fatal("explicit false response rejected", err)
				}
			} else if err == nil {
				t.Fatalf("original %s JSON accepted %s %s despite unrelated nested false keys", tc.method, tc.mutation, tc.field)
			}
		})
	}
}

func TestStackEvidenceHelpersRejectPruning(t *testing.T) {
	want := stackAPIFixture()
	if err := stackCompareTyped(want, want.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*v1beta1.ContainerProfile){
		func(p *v1beta1.ContainerProfile) { p.Spec.IdentifiedCallStacks[0].Evidence = nil },
		func(p *v1beta1.ContainerProfile) { p.Spec.IdentifiedCallStacks[0].Evidence.PolicyEligibility = true },
		func(p *v1beta1.ContainerProfile) {
			p.Spec.IdentifiedCallStacks[0].Evidence.GlobalCollectionComplete = true
		},
		func(p *v1beta1.ContainerProfile) {
			p.Spec.IdentifiedCallStacks[0].CallStack.Root.Frame.Symbol.SourceLine = nil
		},
		func(p *v1beta1.ContainerProfile) {
			*p.Spec.IdentifiedCallStacks[0].CallStack.Root.Frame.Symbol.NativeAddress = "18446744073709551614"
		},
		func(p *v1beta1.ContainerProfile) {
			p.Spec.IdentifiedCallStacks[0].CallStack.Root.Children[0].Frame.Symbol.BytecodeIndex = new(uint32)
		},
	} {
		got := want.DeepCopy()
		mutate(got)
		if err := stackCompareTyped(want, got); err == nil {
			t.Fatal("unchanged CallID hid typed pruning/change")
		}
	}
}

func TestStackEvidenceHelpersCanonicalTreeKeepsTypedPaths(t *testing.T) {
	want := stackAPIFixture()
	canonical := want.DeepCopy()
	// Storage aggregates beneath an explicit dummy root and may reorder groups/siblings.
	for i := range canonical.Spec.IdentifiedCallStacks {
		root := canonical.Spec.IdentifiedCallStacks[i].CallStack.Root
		canonical.Spec.IdentifiedCallStacks[i].CallStack.Root = v1beta1.CallStackNode{Children: []v1beta1.CallStackNode{root}}
	}
	canonical.Spec.IdentifiedCallStacks[0], canonical.Spec.IdentifiedCallStacks[1] = canonical.Spec.IdentifiedCallStacks[1], canonical.Spec.IdentifiedCallStacks[0]
	children := canonical.Spec.IdentifiedCallStacks[1].CallStack.Root.Children[0].Children
	children[0], children[1] = children[1], children[0]
	if err := stackCompareTyped(want, canonical); err != nil {
		t.Fatal("equivalent observed paths rejected after storage's canonical tree reconstruction", err)
	}
	for _, mutate := range []func(*v1beta1.ContainerProfile){
		func(p *v1beta1.ContainerProfile) {
			p.Spec.IdentifiedCallStacks[1].CallStack.Root.Children[0].Frame.Symbol.SourceLine = nil
		},
		func(p *v1beta1.ContainerProfile) {
			p.Spec.IdentifiedCallStacks[1].CallStack.Root.Children[0].Children = nil
		},
		func(p *v1beta1.ContainerProfile) {
			p.Spec.IdentifiedCallStacks[0].Evidence = p.Spec.IdentifiedCallStacks[1].Evidence.DeepCopy()
		},
		func(p *v1beta1.ContainerProfile) {
			root := &p.Spec.IdentifiedCallStacks[1].CallStack.Root.Children[0]
			root.Frame, root.Children[0].Frame = root.Children[0].Frame, root.Frame
		},
	} {
		changed := canonical.DeepCopy()
		mutate(changed)
		if err := stackCompareTyped(want, changed); err == nil {
			t.Fatal("changed optional field, missing path/evidence or reversed caller order admitted")
		}
	}
}

func stackCompareTyped(want, got *v1beta1.ContainerProfile) error {
	wantPaths, err := stackTypedPaths(want)
	if err != nil {
		return err
	}
	gotPaths, err := stackTypedPaths(got)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(wantPaths, gotPaths) {
		return errors.New("pruned or changed typed stacks, symbols, evidence or optional-field presence")
	}
	return nil
}

// Compare complete typed caller paths independently of storage's dummy root/group ordering.
func stackTypedPaths(profile *v1beta1.ContainerProfile) ([]string, error) {
	var groups []string
	for _, stack := range profile.Spec.IdentifiedCallStacks {
		var paths []string
		var visit func(v1beta1.CallStackNode, []v1beta1.StackFrame) error
		visit = func(node v1beta1.CallStackNode, prefix []v1beta1.StackFrame) error {
			path := append(append([]v1beta1.StackFrame(nil), prefix...), node.Frame)
			if len(node.Children) == 0 {
				data, err := json.Marshal(path)
				if err != nil {
					return err
				}
				paths = append(paths, string(data))
			}
			for _, child := range node.Children {
				if err := visit(child, path); err != nil {
					return err
				}
			}
			return nil
		}
		root := stack.CallStack.Root
		if root.Frame == (v1beta1.StackFrame{}) && len(root.Children) > 0 {
			for _, child := range root.Children {
				if err := visit(child, nil); err != nil {
					return nil, err
				}
			}
		} else if err := visit(root, nil); err != nil {
			return nil, err
		}
		sort.Strings(paths)
		data, err := json.Marshal(struct {
			CallID   v1beta1.CallID
			Evidence *v1beta1.CallStackEvidence
			Paths    []string
		}{stack.CallID, stack.Evidence, paths})
		if err != nil {
			return nil, err
		}
		groups = append(groups, string(data))
	}
	sort.Strings(groups)
	return groups, nil
}

type stackDeleteFunc func(context.Context, string, metav1.DeleteOptions) error

func (f stackDeleteFunc) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return f(ctx, name, opts)
}

func TestStackEvidenceHelpersCleanup(t *testing.T) {
	sentinel := errors.New("delete denied")
	called := false
	deleter := stackDeleteFunc(func(ctx context.Context, name string, opts metav1.DeleteOptions) error {
		called = true
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second || ctx.Err() != nil {
			t.Fatal("cleanup lacks its own bounded live context")
		}
		if name != "typed-stack-owned" || opts.Preconditions == nil || opts.Preconditions.UID == nil || *opts.Preconditions.UID != "server-uid" {
			t.Fatal("cleanup not scoped to acquired UID")
		}
		return sentinel
	})
	owned := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: "typed-stack-owned", Namespace: "agentless-hotspot-test", UID: "server-uid"}}
	if err := stackCleanup(deleter, owned); !errors.Is(err, sentinel) {
		t.Fatalf("lost cleanup failure: %v", err)
	}
	if !called {
		t.Fatal("owned profile leaked")
	}
	for _, invalid := range []*v1beta1.ContainerProfile{nil, {}, {ObjectMeta: metav1.ObjectMeta{Name: owned.Name}}, {ObjectMeta: metav1.ObjectMeta{Name: owned.Name, UID: owned.UID, Namespace: "other"}}} {
		called = false
		if err := stackCleanup(deleter, invalid); err == nil || called {
			t.Fatal("cleanup attempted without acquired namespace/name/UID")
		}
	}
}

func stackCleanup(profiles interface {
	Delete(context.Context, string, metav1.DeleteOptions) error
}, created *v1beta1.ContainerProfile) error {
	if created == nil || created.Name == "" || created.UID == "" || created.Namespace != stackNamespace {
		return errors.New("refusing cleanup without acquired namespace/name/UID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := profiles.Delete(ctx, created.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &created.UID}}); err != nil {
		return fmt.Errorf("cleanup %s UID %s: %w", created.Name, created.UID, err)
	}
	return nil
}

type stackPrerequisites struct{ kubeconfig, context, output string }

func stackPreflight(getenv func(string) string) (stackPrerequisites, error) {
	p := stackPrerequisites{getenv("KUBECONFIG"), getenv("AGENTLESS_HOTSPOT_CONTEXT"), getenv("AGENTLESS_HOTSPOT_OUTPUT_DIR")}
	if !filepath.IsAbs(p.kubeconfig) || strings.ContainsRune(p.kubeconfig, os.PathListSeparator) || strings.TrimSpace(p.context) == "" || !filepath.IsAbs(p.output) {
		return p, errors.New("before any API call: require explicit single absolute KUBECONFIG, approved AGENTLESS_HOTSPOT_CONTEXT and absolute AGENTLESS_HOTSPOT_OUTPUT_DIR")
	}
	return p, nil
}

func stackJSONFalseFields(body []byte) error {
	var profile map[string]interface{}
	if err := json.Unmarshal(body, &profile); err != nil {
		return fmt.Errorf("decode original JSON response: %w", err)
	}
	spec, ok := profile["spec"].(map[string]interface{})
	if !ok {
		return errors.New("original JSON lacks canonical spec object")
	}
	stacks, ok := spec["identifiedCallStacks"].([]interface{})
	if !ok {
		return errors.New("original JSON lacks canonical spec.identifiedCallStacks array")
	}
	for i, rawStack := range stacks {
		stack, ok := rawStack.(map[string]interface{})
		if !ok {
			return fmt.Errorf("original JSON stack %d is not an object", i)
		}
		for key := range stack {
			if key != "evidence" && strings.EqualFold(key, "evidence") {
				return fmt.Errorf("original JSON stack %d uses noncanonical evidence key", i)
			}
		}
		rawEvidence := stack["evidence"]
		if rawEvidence == nil {
			continue // Legacy stacks may omit evidence; typed comparison checks expected evidence.
		}
		evidence, ok := rawEvidence.(map[string]interface{})
		if !ok {
			return fmt.Errorf("original JSON stack %d evidence is not an object", i)
		}
		for _, field := range []string{"policyEligibility", "globalCollectionComplete"} {
			value, present := evidence[field].(bool)
			if !present || value {
				return fmt.Errorf("original JSON spec.identifiedCallStacks[%d].evidence.%s must be explicitly false", i, field)
			}
		}
	}
	return nil
}

// Only body bytes and allowlisted media evidence are recorded; never full headers or config.
type stackBodyRecorder struct {
	dir, media string
	sequence   int
	errors     []error
}

func (r *stackBodyRecorder) check() error { return errors.Join(r.errors...) }

func (r *stackBodyRecorder) wrap(next http.RoundTripper) http.RoundTripper {
	return stackTransportFunc(func(req *http.Request) (*http.Response, error) {
		r.sequence++
		prefix := filepath.Join(r.dir, fmt.Sprintf("%03d", r.sequence))
		if req.Header.Get("Accept") != r.media || (req.Body != nil && req.Header.Get("Content-Type") != r.media) {
			return nil, errors.New("request did not use exact required content negotiation")
		}
		var requestBody []byte
		if req.Body != nil {
			body, err := io.ReadAll(req.Body)
			closeErr := req.Body.Close()
			if err = errors.Join(err, closeErr); err != nil {
				return nil, err
			}
			requestBody = body
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		if err := os.WriteFile(prefix+"-request.body", requestBody, 0600); err != nil {
			if req.Method != http.MethodDelete {
				return nil, err
			}
			// Receipt failures fail the gate, but must not strand an acquired object.
			r.errors = append(r.errors, err)
		}
		resp, err := next.RoundTrip(req)
		if err != nil {
			return resp, err
		}
		body, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		r.errors = append(r.errors, readErr, closeErr, os.WriteFile(prefix+"-response.body", body, 0600))
		if r.media == runtime.ContentTypeJSON && (req.Method == http.MethodPost || req.Method == http.MethodGet) && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			r.errors = append(r.errors, stackJSONFalseFields(body))
		}
		media, _, parseErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if parseErr != nil || media != r.media {
			r.errors = append(r.errors, fmt.Errorf("response media %q does not match %q", resp.Header.Get("Content-Type"), r.media))
		}
		meta, marshalErr := json.MarshalIndent(struct {
			RequestContentType  string `json:"requestContentType"`
			Accept              string `json:"accept"`
			ResponseContentType string `json:"responseContentType"`
			Status              int    `json:"status"`
			BodyComplete        bool   `json:"bodyComplete"`
		}{req.Header.Get("Content-Type"), req.Header.Get("Accept"), resp.Header.Get("Content-Type"), resp.StatusCode, readErr == nil}, "", "  ")
		r.errors = append(r.errors, marshalErr, os.WriteFile(prefix+"-media.json", meta, 0600))
		// Preserve a decodable Create response so ownership is acquired even when receipts/negotiation fail.
		return resp, nil
	})
}

// Local generated-scheme serialization only: these examples are NOT API/server evidence.
func TestStackEvidenceWireExamples(t *testing.T) {
	dir := t.TempDir()
	if parent := os.Getenv("AGENTLESS_HOTSPOT_EXAMPLE_DIR"); parent != "" {
		var err error
		dir, err = os.MkdirTemp(parent, "local-wire-")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("local-only generated wire examples: %s", dir)
	}
	want := stackAPIFixture()
	for _, media := range []string{runtime.ContentTypeJSON, runtime.ContentTypeProtobuf} {
		info, ok := runtime.SerializerInfoForMediaType(scheme.Codecs.SupportedMediaTypes(), media)
		if !ok {
			t.Fatalf("no generated-scheme serializer for %s", media)
		}
		raw, err := runtime.Encode(scheme.Codecs.EncoderForVersion(info.Serializer, v1beta1.SchemeGroupVersion), want)
		if err != nil {
			t.Fatal(err)
		}
		obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(raw, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := obj.(*v1beta1.ContainerProfile)
		if !ok || !reflect.DeepEqual(want.Spec.IdentifiedCallStacks, got.Spec.IdentifiedCallStacks) {
			t.Fatal("local serializer lost typed values")
		}
		name := "request.json"
		if media == runtime.ContentTypeProtobuf {
			name = "request.pb"
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if media == runtime.ContentTypeProtobuf {
			if err := os.WriteFile(filepath.Join(dir, "request.pb.base64"), []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
		} else {
			for _, field := range []string{`"policyEligibility":false`, `"globalCollectionComplete":false`, `"nativeAddress":"18446744073709551615"`, `"bytecodeIndex":0`} {
				if !bytes.Contains(raw, []byte(field)) {
					t.Fatalf("local JSON lacks %s", field)
				}
			}
		}
	}
}
