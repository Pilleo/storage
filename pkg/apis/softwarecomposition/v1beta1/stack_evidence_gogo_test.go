//go:build kubernetes_protomessage_one_more_release

package v1beta1

import (
	"reflect"
	"testing"

	"github.com/gogo/protobuf/proto"
)

func TestStackEvidenceGogoProtobuf(t *testing.T) {
	want := stackEvidenceFixture()
	raw, err := proto.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got := &ContainerProfile{}
	if err := proto.Unmarshal(raw, got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want.Spec.IdentifiedCallStacks, got.Spec.IdentifiedCallStacks) {
		t.Fatalf("gogo protobuf lost typed evidence: %+v", got.Spec.IdentifiedCallStacks)
	}
}
