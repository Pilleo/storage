# Agentless HotSpot typed stack evidence: schema and rollout gate

**Status: historical local-only JSON/protobuf Create/Get pass, 2026-10-19;
the disposable environment is retired.**
That operator-approved kind environment ran exact committed source
`46c8444a4d9a0c78ca82058ee7d9563a00605ced`, including the separately approved full
ContainerProfile Create response. The [dated historical record](agentless-stack-evidence-live-api.md)
describes the actual image graph, six exchanges, retained first failed run and
subsequent checked retirement; it is not current-server acceptance.
No published storage module, pushed image or node-agent/end-to-end acceptance is
claimed. The original incomplete `build/hotspot-schema-handoff.json` and separate
`build/hotspot-schema-handoff-live-20261019.json` are nonpublic operator-custody
references, not files or evidence links in this source publication. The latter
records explicit `releaseReady:false` and no invented module version. Commit,
toolchain and example identities below describe the retained 2026-10-19 history,
not the current contribution or a release identity. No protected receipt was
reopened to make this publication-facing clarification.

## Additive contract

The served API remains `spdx.softwarecomposition.kubescape.io/v1beta1` in module
`github.com/kubescape/storage` (Go floor `1.25.8`). Schema/storage implementation
commit: `1e9d93afd297f035fa78bc7624f8c136a22109fc`. This checkout is a main module
with no reported module version; that commit is not a published release or image
pin. The gate/docs preparation commit must be recorded separately by the operator
when selecting the exact reviewed server source.

- `StackFrame.symbol` is an optional `FrameSymbol`, protobuf field **4**;
  `IdentifiedCallStack.evidence` is optional `CallStackEvidence`, field **3**.
  Nil retains legacy JSON/protobuf behavior; missing data stays absent. Existing
  `fileID`, `lineno` and numeric `frameType` keep their original meanings. Never
  hide rendered function text in `fileID` or substitute BCI for `lineno`.
- `FrameSymbol` protobuf fields 1–14 are `schemaVersion`, `provider`,
  `functionName`, `sourceFile`, `sourceLine`, `sourceColumn`, `nativeAddress`,
  `bytecodeIndex`, `rawPosition`, `positionDomain`, `scopeLookup`, `scopeWalk`,
  `bciState`, `qualityDiagnostic`. Schema version is **1** for this contract.
  Source line/column and BCI are optional uint32 pointers: absent, present zero
  and present `4294967295` are distinct. Native address is an optional unsigned
  decimal string; raw position is also a decimal string. Preserve
  `18446744073709551615` and `9007199254740993` exactly, without a floating-point
  conversion or invented source coordinates.
- `CallStackEvidence` fields 1–12 are `schemaVersion`, `provider`,
  `runtimeProfile`, `eventScope`, `identityScope`, `policyEligibility`,
  `globalCollectionComplete`, `jvmBuildID`, `jvmSHA256`, `gadgetRevision`,
  `profilerRevision`, `patchSHA256`. Version **1**, provider
  `otel-ebpf-profiler-via-gadget`, runtime profile `otel_hotspot25_observed_v1`,
  event scope `openat_handler_entry`, identity scope
  `otel-observed-provider-frames/v1`. The booleans serialize explicitly **false**:
  observations do not establish policy eligibility or complete global coverage.
  Physical drain, selected-stream accounting and whole-session completeness
  remain separate claims. Fixture provenance strings below are not real JVM,
  profiler, gadget or patch identities.
- Aggregation preserves actual typed frame values and distinct evidence groups;
  internal file persistence preserves optional pointer presence. B1/B2 local
  serialization, generated schema and persistence checks were separately
  approved. They do not replace this real API gate.
- Older clients may read legacy portions but can drop unknown typed fields on
  read-modify-write. There is **no lossless old-client roundtrip promise**.
  Deploy the reviewed server schema first; only then admit a compatible optional
  collector. The node-agent capability probe must reject old/pruning storage
  before starting that collector. This storage preparation does not implement
  or certify that probe; legacy node-agent behavior remains valid.

## Explicit operator prerequisites and live invocation

These are mandatory operator prerequisites. The initial preparation did not
authorize them; a later explicit operator decision selected the now-retired local
environment. A new invocation needs new exact selections and authority; neither
that historical approval nor an approved context authorizes a different cluster:

1. Approve the exact reviewed storage server source, build/deployment procedure,
   API server/context and integration environment. Record the actual selected
   source commit, module version/publication status and deployed image digest;
   unknowns must remain unknown, never future release pins.
2. Supply one explicit absolute `KUBECONFIG` file. Its `current-context` must
   already equal the explicitly approved `AGENTLESS_HOTSPOT_CONTEXT`; the gate
   does not switch contexts or search implicit configuration. Approved
   credentials need ContainerProfile Create/Get/Delete permissions. No
   kubeconfig, auth header, token or credential belongs in evidence files.
3. The approved setup must already have provisioned **`agentless-hotspot-test`**
   and the reviewed storage API. The gate neither discovers a cluster nor creates
   a namespace. A missing namespace, denial, unsupported negotiation or field
   pruning fails the gate.
4. Provision an absolute, private, writable receipt parent directory and run:

```bash
KUBECONFIG=/absolute/operator-approved/config \
AGENTLESS_HOTSPOT_CONTEXT=operator-approved-context \
AGENTLESS_HOTSPOT_OUTPUT_DIR=/absolute/private/receipt-parent \
go test -tags=agentless_hotspot_integration ./tests \
  -run '^TestStackEvidenceAPIRoundTrip$' -count=1 -v
```

The explicit **`agentless_hotspot_integration` build tag** is required because
unmodified `make test` runs `go test ./...` and must remain host-safe. Invoking
the tagged gate without its explicit prerequisites **fails, never skips**, before
configuration loading, client construction, network calls or resource mutation.

The [gate](../tests/agentless_stack_roundtrip_test.go) uses the generated clientset
and scheme, explicit `clientcmd.BuildConfigFromFlags`, `rest.CopyConfig`, and
exact `ContentType`/`AcceptContentTypes` for JSON and Kubernetes protobuf. An
owned 30-second context bounds Create/Get across both formats. It compares the
complete typed caller paths/evidence in both Create and Get, not only CallID:
all symbol/evidence values, false flags, nil symbols/evidence, optional nil/zero/
max locations, decimal addresses and raw positions. Name/namespace/UID must also
match the acquired object. Storage's canonical dummy root and group/sibling order
do not change caller paths; comparison ignores only these representations, never
caller order, missing frames, symbol/evidence values or optional pointer presence.
Response media type must match the requested format;
a silently negotiated JSON fallback fails the protobuf gate.

Each invocation creates a unique private `stack-api-*` directory, with `0/`
(JSON) and `1/` (protobuf). Each exchange writes numbered `*-request.body`,
`*-response.body` and allowlisted `*-media.json` evidence (Content-Type, Accept,
status and body-read completeness only). Bodies are the application bytes seen
by the HTTP transport; bodies are not remarshalings of decoded objects. Failed
exchanges may leave incomplete evidence, which is a gate failure. No full headers,
URLs, kubeconfig or credentials are copied. Retain the directory and command
output under operator custody; do not publish it automatically.

After acquiring server-issued name/namespace/UID, cleanup runs even on comparison
or receipt failure. Each Delete has its own background context bounded to five
seconds and a UID precondition; no invented ownership token or namespace deletion
is used. Receipt-write failure cannot block an owned Delete. Original errors and
cleanup errors are joined before `result.json` is written and the test reports
its final outcome. A successful HTTP Create whose response is lost or cannot
yield a trustworthy UID remains ambiguous: the test fails, retains available
bodies, and requires operator reconciliation; it cannot invent ownership to
delete an unknown object. Delete denial/UID mismatch/timeout also fails the gate.

### ContainerProfile Create response contract

The first approved local live invocation against source61f0be2 failed in both
formats: its Create response contained metadata only. It remains failed evidence,
not field-preservation acceptance. The operator explicitly chose full Create
objects rather than weakening the gate to metadata-only acquisition.

ContainerProfile Create therefore returns its persisted full object after the
normal processor/save steps. This adds one bounded payload read under the existing
write lock; a read error is returned with its original cause, not as metadata-only
success. Such an error can follow a persisted Create and needs the same ownership
reconciliation as any lost Create response. Other resource Create responses and
metadata-only watches/LISTs remain unchanged. Update response behavior is unchanged.
Host regressions cover full persisted values, response independence, unchanged
metadata watches and the failed-read case. The live gate still requires both
formats, exact media negotiation, full caller paths, unchanged budgets and cleanup.

## Host-safe local checks and example provenance

```bash
go test -tags=agentless_hotspot_integration ./tests \
  -run '^TestStackEvidence(Helpers|WireExamples)' -count=1 -v
go test -tags=agentless_hotspot_integration ./tests -run '^$' -count=1
make test
```

Helper tests use explicitly local fake transports for opaque body/negotiation
checks, including deliberate transport failure at the actual generated-client
request boundary. They produce no successful API response or API acceptance
receipt. Local examples use the same generated scheme's JSON/protobuf encoders
and decode/compare all typed stacks. To retain new examples, set
`AGENTLESS_HOTSPOT_EXAMPLE_DIR` to an existing private parent for the local checks;
the test creates a unique `local-wire-*` child. This is independent of the live
gate receipt parent and requires no kubeconfig or API.

The historical examples below were produced by `TestStackEvidenceWireExamples`
on 2026-10-19, Go `go1.26.8 linux/amd64`, with the API/storage source commit above:

- Custody: `build/hotspot-task3-20261019/local-wire-1856552715/` (local unstaged
  evidence); command output: `build/hotspot-task3-20261019/13-final-local.log`.
  These are nonpublic operator-custody references, not package-relative links or
  included publication artifacts; the recorded bytes/hashes were not revalidated.
- `request.json`: 2068 bytes, SHA-256
  `fcb5a5afbac6f667e4f043c5f18e558a16c74b62b7ffa800f847d1c1e03e084e`.
- `request.pb`: 890 bytes, SHA-256
  `c77f25f17d81a6f93d40b14b4e3c7009003e414e5a5afe72c45646fc8e212bd0`.
- JSON is reindented below for readability; hashes refer to actual encoder output
  including its terminating newline. The protobuf example is exact base64 of the
  Kubernetes `k8s\x00` envelope, **not** a bare gogo message or relabeled JSON.
  Neither example is a live server request/response receipt. FrameType 6 and
  `fixture-*` strings are test data, not provider enum or release assertions.

### Test-produced JSON (`application/json`)

```json
{
  "kind": "ContainerProfile",
  "apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
  "metadata": {
    "generateName": "typed-stack-",
    "namespace": "agentless-hotspot-test",
    "annotations": {"kubescape.io/managed-by": "User"}
  },
  "spec": {
    "architectures": ["amd64"],
    "capabilities": null,
    "execs": null,
    "opens": null,
    "syscalls": null,
    "seccompProfile": {"spec": {"defaultAction": ""}},
    "endpoints": null,
    "imageID": "",
    "imageTag": "",
    "rulePolicies": null,
    "identifiedCallStacks": [
      {
        "callID": "typed-a",
        "callStack": {
          "root": {
            "children": [
              {
                "children": null,
                "frame": {
                  "fileID": "", "lineno": "", "frameType": 0,
                  "symbol": {
                    "schemaVersion": 1,
                    "provider": "otel-ebpf-profiler-via-gadget",
                    "functionName": "unknown-source",
                    "rawPosition": "18446744073709551615"
                  }
                }
              },
              {
                "children": null,
                "frame": {
                  "fileID": "", "lineno": "", "frameType": 0,
                  "symbol": {
                    "schemaVersion": 1,
                    "provider": "otel-ebpf-profiler-via-gadget",
                    "sourceLine": 4294967295,
                    "sourceColumn": 0,
                    "nativeAddress": "0",
                    "bytecodeIndex": 4294967295,
                    "rawPosition": "0"
                  }
                }
              }
            ],
            "frame": {
              "fileID": "", "lineno": "", "frameType": 6,
              "symbol": {
                "schemaVersion": 1,
                "provider": "otel-ebpf-profiler-via-gadget",
                "functionName": "void Fixture.routeA(java.lang.String)",
                "sourceFile": "Fixture.java",
                "sourceLine": 0,
                "sourceColumn": 4294967295,
                "nativeAddress": "18446744073709551615",
                "bytecodeIndex": 0,
                "rawPosition": "9007199254740993",
                "positionDomain": "provider_hotspot_bci_or_fallback",
                "scopeLookup": "fixture-lookup",
                "scopeWalk": "fixture-walk",
                "bciState": "fixture-known",
                "qualityDiagnostic": "native_metadata_observed"
              }
            }
          }
        },
        "evidence": {
          "schemaVersion": 1,
          "provider": "otel-ebpf-profiler-via-gadget",
          "runtimeProfile": "otel_hotspot25_observed_v1",
          "eventScope": "openat_handler_entry",
          "identityScope": "otel-observed-provider-frames/v1",
          "policyEligibility": false,
          "globalCollectionComplete": false,
          "jvmBuildID": "fixture-jvm-build",
          "jvmSHA256": "fixture-jvm-sha256",
          "gadgetRevision": "fixture-gadget",
          "profilerRevision": "fixture-profiler",
          "patchSHA256": "fixture-patch"
        }
      },
      {
        "callID": "legacy-nil",
        "callStack": {"root": {"children": null, "frame": {"fileID": "123", "lineno": "19", "frameType": 6}}}
      }
    ],
    "ingress": null,
    "egress": null
  },
  "status": {}
}
```

### Test-produced Kubernetes protobuf (`application/vnd.kubernetes.protobuf`)

Decode this base64 to recover the exact 890-byte `request.pb` body:

```text
azhzAApBCi1zcGR4LnNvZnR3YXJlY29tcG9zaXRpb24ua3ViZXNjYXBlLmlvL3YxYmV0YTESEENvbnRhaW5lclByb2ZpbGUSrAYKUwoAEgx0eXBlZC1zdGFjay0aFmFnZW50bGVzcy1ob3RzcG90LXRlc3QiACoAMgA4AEIAYh8KF2t1YmVzY2FwZS5pby9tYW5hZ2VkLWJ5EgRVc2VyEtIFCgVhbWQ2NDISCgASABoMCgIIABIAGgAqADIAQgBKAFqOBQoHdHlwZWQtYRKuAwqrAwpdElsKABIAGAAiUwgBEh1vdGVsLWVicGYtcHJvZmlsZXItdmlhLWdhZGdldBoOdW5rbm93bi1zb3VyY2UiAEoUMTg0NDY3NDQwNzM3MDk1NTE2MTVSAFoAYgBqAHIACk0SSwoAEgAYACJDCAESHW90ZWwtZWJwZi1wcm9maWxlci12aWEtZ2FkZ2V0GgAiACj/////DzAAOgEwQP////8PSgEwUgBaAGIAagByABL6AQoAEgAYBiLxAQgBEh1vdGVsLWVicGYtcHJvZmlsZXItdmlhLWdhZGdldBoldm9pZCBGaXh0dXJlLnJvdXRlQShqYXZhLmxhbmcuU3RyaW5nKSIMRml4dHVyZS5qYXZhKAAw/////w86FDE4NDQ2NzQ0MDczNzA5NTUxNjE1QABKEDkwMDcxOTkyNTQ3NDA5OTNSIHByb3ZpZGVyX2hvdHNwb3RfYmNpX29yX2ZhbGxiYWNrWg5maXh0dXJlLWxvb2t1cGIMZml4dHVyZS13YWxrag1maXh0dXJlLWtub3duchhuYXRpdmVfbWV0YWRhdGFfb2JzZXJ2ZWQa0QEIARIdb3RlbC1lYnBmLXByb2ZpbGVyLXZpYS1nYWRnZXQaGm90ZWxfaG90c3BvdDI1X29ic2VydmVkX3YxIhRvcGVuYXRfaGFuZGxlcl9lbnRyeSogb3RlbC1vYnNlcnZlZC1wcm92aWRlci1mcmFtZXMvdjEwADgAQhFmaXh0dXJlLWp2bS1idWlsZEoSZml4dHVyZS1qdm0tc2hhMjU2Ug5maXh0dXJlLWdhZGdldFoQZml4dHVyZS1wcm9maWxlcmINZml4dHVyZS1wYXRjaFodCgpsZWdhY3ktbmlsEg8KDRILCgMxMjMSAjE5GAaqBgAaABoAIgA=
```

## Remaining acceptance/handoff gate

Only an operator-authorized execution against the reviewed deployed server can
supply the actual JSON and protobuf Create/Get persistence, negotiation and
checked cleanup receipts. After that execution, independently review the exact
source/deployed-image relationship and populate actual handoff identities and
check outputs. Publication, tagging, pushing, image builds and deployment need
separate authorization. Local checks do not complete B3 or enable the collector.
