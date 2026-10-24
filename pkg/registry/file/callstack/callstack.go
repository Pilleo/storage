package callstack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	types "github.com/kubescape/storage/pkg/apis/softwarecomposition"
)

// framesEqual checks if two StackFrames are equal
func framesEqual(f1, f2 types.StackFrame) bool {
	if f1.Symbol == nil || f2.Symbol == nil {
		return f1.Symbol == nil && f2.Symbol == nil && f1.FileID == f2.FileID && f1.Lineno == f2.Lineno
	}
	return frameKey(f1) == frameKey(f2)
}

// isEmptyFrame checks if a StackFrame is empty
func isEmptyFrame(frame types.StackFrame) bool {
	return frame.FileID == "" && frame.Lineno == "" && frame.Symbol == nil
}

// frameKey returns a string key representing a stack frame
func frameKey(frame types.StackFrame) string {
	if frame.Symbol == nil {
		return frame.FileID + ":" + frame.Lineno
	}
	b, err := json.Marshal(frame)
	if err != nil {
		panic(err) // Closed scalar/pointer API type; marshaling has no failure input.
	}
	h := sha256.Sum256(b)
	return "symbol-v1:" + hex.EncodeToString(h[:])
}

// pathKey tags and byte-length-prefixes components without reserving any legacy string values.
func pathKey(nodes []types.CallStackNode) string {
	var key strings.Builder
	for _, node := range nodes {
		frame := node.Frame
		if frame.Symbol == nil {
			fmt.Fprintf(&key, "l%d:%s%d:%s", len(frame.FileID), frame.FileID, len(frame.Lineno), frame.Lineno)
		} else {
			symbol := frameKey(frame)
			fmt.Fprintf(&key, "s%d:%s", len(symbol), symbol)
		}
	}
	return key.String()
}

// getCallStackPaths returns all complete paths in a call stack
func getCallStackPaths(cs types.CallStack) [][]types.CallStackNode {
	var paths [][]types.CallStackNode
	var traverse func(node types.CallStackNode, currentPath []types.CallStackNode)

	traverse = func(node types.CallStackNode, currentPath []types.CallStackNode) {
		path := append([]types.CallStackNode{}, currentPath...)
		path = append(path, node)

		if len(node.Children) == 0 {
			paths = append(paths, path)
			return
		}
		for _, child := range node.Children {
			traverse(child, path)
		}
	}

	if isEmptyFrame(cs.Root.Frame) {
		for _, child := range cs.Root.Children {
			traverse(child, nil)
		}
	} else {
		traverse(cs.Root, nil)
	}

	return paths
}

// reconstructCallStack builds a CallStack from owned frame paths.
func reconstructCallStack(paths map[string][]types.StackFrame) types.CallStack {
	allPaths := make([][]types.StackFrame, 0, len(paths))
	for _, frames := range paths {
		allPaths = append(allPaths, frames)
	}

	// Sort paths by length (longest first) then by content
	sort.Slice(allPaths, func(i, j int) bool {
		if len(allPaths[i]) != len(allPaths[j]) {
			return len(allPaths[i]) > len(allPaths[j])
		}
		// If same length, sort by content for consistency
		for k := 0; k < len(allPaths[i]); k++ {
			if allPaths[i][k].FileID != allPaths[j][k].FileID {
				return allPaths[i][k].FileID < allPaths[j][k].FileID
			}
			if allPaths[i][k].Lineno != allPaths[j][k].Lineno {
				return allPaths[i][k].Lineno < allPaths[j][k].Lineno
			}
			if ki, kj := frameKey(allPaths[i][k]), frameKey(allPaths[j][k]); ki != kj {
				return ki < kj
			}
		}
		return false
	})

	result := types.CallStack{
		Root: types.CallStackNode{
			Children: make([]types.CallStackNode, 0),
			Frame:    types.StackFrame{},
		},
	}

	// Helper function to find or create a node
	getNode := func(parent *types.CallStackNode, frame types.StackFrame) *types.CallStackNode {
		for i := range parent.Children {
			if framesEqual(parent.Children[i].Frame, frame) {
				return &parent.Children[i]
			}
		}
		parent.Children = append(parent.Children, types.CallStackNode{
			Frame:    frame,
			Children: make([]types.CallStackNode, 0),
		})
		return &parent.Children[len(parent.Children)-1]
	}

	// Build tree from sorted paths
	for _, path := range allPaths {
		current := &result.Root
		for _, frame := range path {
			current = getNode(current, frame)
		}
	}

	return result
}

// UnifyIdentifiedCallStacks takes a list of IdentifiedCallStack and returns a list of unified CallStacks
func UnifyIdentifiedCallStacks(stacks []types.IdentifiedCallStack) []types.IdentifiedCallStack {
	type groupKey struct {
		callID      types.CallID
		hasEvidence bool
		evidence    types.CallStackEvidence
	}
	stacksByGroup := make(map[groupKey][]types.CallStack)
	for _, stack := range stacks {
		key := groupKey{callID: stack.CallID, hasEvidence: stack.Evidence != nil}
		if stack.Evidence != nil {
			key.evidence = *stack.Evidence
		}
		stacksByGroup[key] = append(stacksByGroup[key], stack.CallStack)
	}

	var result []types.IdentifiedCallStack
	for key, groupStacks := range stacksByGroup {
		pathsByKey := make(map[string][]types.StackFrame)
		for _, cs := range groupStacks {
			paths := getCallStackPaths(cs)
			for _, path := range paths {
				frames := make([]types.StackFrame, len(path))
				for i, node := range path {
					frames[i] = node.Frame
					frames[i].Symbol = node.Frame.Symbol.DeepCopy()
				}
				pathsByKey[pathKey(path)] = frames
			}
		}

		var evidence *types.CallStackEvidence
		if key.hasEvidence {
			evidence = key.evidence.DeepCopy()
		}
		result = append(result, types.IdentifiedCallStack{
			CallID:    key.callID,
			CallStack: reconstructCallStack(pathsByKey),
			Evidence:  evidence,
		})
	}

	return result
}
