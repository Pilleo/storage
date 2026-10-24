package softwarecomposition

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFrameSymbolGobOptionalPresence(t *testing.T) {
	zero, max, nonzero := uint32(0), ^uint32(0), uint32(42)
	empty, zeroAddress, maxAddress, nonzeroAddress := "", "0", "18446744073709551615", "123"
	numbers := []*uint32{nil, &zero, &max, &nonzero}
	addresses := []*string{nil, &empty, &zeroAddress, &maxAddress, &nonzeroAddress}
	for i, line := range numbers {
		for j, column := range numbers {
			for k, bci := range numbers {
				for l, address := range addresses {
					t.Run(fmt.Sprintf("%d/%d/%d/%d", i, j, k, l), func(t *testing.T) {
						want := StackFrame{FileID: "file", Lineno: "19", FrameType: 6, Symbol: &FrameSymbol{
							SchemaVersion: 1, Provider: "hotspot", FunctionName: "route", SourceFile: "Route.java",
							SourceLine: line, SourceColumn: column, BytecodeIndex: bci, NativeAddress: address,
							RawPosition: maxAddress, PositionDomain: "jvm", ScopeLookup: "method",
							ScopeWalk: "physical", BCIState: "observed", QualityDiagnostic: "partial",
						}}
						var payload bytes.Buffer
						require.NoError(t, gob.NewEncoder(&payload).Encode(want))
						var got StackFrame
						require.NoError(t, gob.NewDecoder(&payload).Decode(&got))
						require.Equal(t, want, got)
						if got.Symbol.SourceLine != nil {
							*got.Symbol.SourceLine = 7
							require.NotEqual(t, *got.Symbol.SourceLine, *want.Symbol.SourceLine)
						}
					})
				}
			}
		}
	}
	for _, symbol := range []*FrameSymbol{nil, {}} {
		want := StackFrame{FileID: "legacy", Lineno: "1", FrameType: 4, Symbol: symbol}
		var payload bytes.Buffer
		require.NoError(t, gob.NewEncoder(&payload).Encode(want))
		var got StackFrame
		require.NoError(t, gob.NewDecoder(&payload).Decode(&got))
		require.Equal(t, want, got, "nil and present-empty symbols must remain distinct")
	}
}

func TestFrameSymbolGobDecodeRejectsMalformedWithoutMutation(t *testing.T) {
	for _, payload := range []string{
		"", "{", "null", "[]", "42", `{"Provider":"changed","SourceLine":-1}`,
		`{"Provider":"changed","SourceColumn":4294967296}`,
		`{"Provider":"changed","BytecodeIndex":"bad"}`,
		`{"Provider":"changed","NativeAddress":123}`,
		`{"Provider":"changed"} trailing`,
	} {
		t.Run(payload, func(t *testing.T) {
			line, address := uint32(19), "123"
			got := FrameSymbol{SchemaVersion: 1, Provider: "original", SourceLine: &line, NativeAddress: &address}
			want := got.DeepCopy()
			decoder, ok := any(&got).(gob.GobDecoder)
			require.True(t, ok, "FrameSymbol must provide the actual gob decoding hook")
			require.Error(t, decoder.GobDecode([]byte(payload)))
			require.Equal(t, want, &got, "decode errors must not partially mutate the receiver")
			require.Same(t, &line, got.SourceLine)
			require.Same(t, &address, got.NativeAddress)
		})
	}
}

func TestFrameSymbolGobDecodeReplacesReceiver(t *testing.T) {
	line := uint32(19)
	got := FrameSymbol{SchemaVersion: 1, Provider: "old", SourceLine: &line}
	decoder, ok := any(&got).(gob.GobDecoder)
	require.True(t, ok)
	require.NoError(t, decoder.GobDecode([]byte(`{"SchemaVersion":1,"Provider":"new","BytecodeIndex":0}`)))
	zero := uint32(0)
	require.Equal(t, FrameSymbol{SchemaVersion: 1, Provider: "new", BytecodeIndex: &zero}, got)
	require.EqualValues(t, 19, line, "decoding must not reuse the caller's old optional storage")
}
