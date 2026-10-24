package file

import (
	"bytes"
	"context"
	"encoding/gob"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage"
)

func TestContainerProfileCreateReturnsOwnedPersistedPayload(t *testing.T) {
	input := stackEvidenceProfile()
	s, key := newGuardTestStorage(t, input.Namespace, input.Name)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := &softwarecomposition.ContainerProfile{}
	metadataWatch, err := s.Watch(ctx, "/", storage.ListOptions{})
	require.NoError(t, err)
	defer metadataWatch.Stop()
	require.NoError(t, s.Create(ctx, key, input, out, 0))
	stored := &softwarecomposition.ContainerProfile{}
	require.NoError(t, s.Get(ctx, key, storage.GetOptions{}, stored))
	require.NotEmpty(t, out.ResourceVersion)
	require.NotEmpty(t, out.Annotations)
	require.Equal(t, stored, out, "Create must return the actual persisted ContainerProfile, not metadata only")
	requireStackEvidence(t, stackEvidenceProfile().Spec.IdentifiedCallStacks, out.Spec.IdentifiedCallStacks)
	select {
	case event := <-metadataWatch.ResultChan():
		metadata := event.Object.(*softwarecomposition.ContainerProfile)
		require.Equal(t, out.ResourceVersion, metadata.ResourceVersion)
		require.Empty(t, metadata.Spec.IdentifiedCallStacks, "Create response must not expand metadata watches")
		require.Empty(t, metadata.Spec.Containers)
	case <-ctx.Done():
		t.Fatal("missing metadata watch event", ctx.Err())
	}
	out.Spec.IdentifiedCallStacks[0].Evidence.Provider = "changed-response"
	out.Spec.Containers[0].IdentifiedCallStacks[0].Evidence.Provider = "changed-subtype-response"
	require.NotEqual(t, "changed-response", input.Spec.IdentifiedCallStacks[0].Evidence.Provider)
	require.NotEqual(t, "changed-subtype-response", input.Spec.Containers[0].IdentifiedCallStacks[0].Evidence.Provider)
	again := &softwarecomposition.ContainerProfile{}
	require.NoError(t, s.Get(ctx, key, storage.GetOptions{}, again))
	require.Equal(t, stored, again, "mutating a Create response must not mutate storage")
}

type deniedCreateReadFS struct{ afero.Fs }

func (f deniedCreateReadFS) OpenFile(name string, flag int, mode os.FileMode) (afero.File, error) {
	if flag&(os.O_WRONLY|os.O_RDWR) == 0 && strings.HasSuffix(name, GobExt) {
		return nil, syscall.EACCES
	}
	return f.Fs.OpenFile(name, flag, mode)
}

func TestContainerProfileCreateRetainsPersistedReadFailure(t *testing.T) {
	for _, full := range []bool{false, true} {
		name, version := "metadata", ""
		if full {
			name, version = "full", softwarecomposition.ResourceVersionFullSpec
		}
		t.Run(name, func(t *testing.T) {
			input := stackEvidenceProfile()
			s, key := newGuardTestStorage(t, input.Namespace, input.Name)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			w, err := s.Watch(ctx, "/", storage.ListOptions{ResourceVersion: version})
			require.NoError(t, err)
			defer w.Stop()
			impl := s.(*StorageImpl)
			original := impl.appFs
			impl.appFs = deniedCreateReadFS{original}
			err = s.Create(ctx, key, input, &softwarecomposition.ContainerProfile{}, 0)
			require.ErrorIs(t, err, syscall.EACCES, "failed persisted read must not return metadata as a successful full response")
			impl.appFs = original
			stored := &softwarecomposition.ContainerProfile{}
			require.NoError(t, s.Get(ctx, key, storage.GetOptions{}, stored))
			require.NotEmpty(t, stored.Spec.IdentifiedCallStacks, "failed response does not undo a persisted Create; caller must reconcile")
			require.NotEmpty(t, stored.ResourceVersion)
			select {
			case event := <-w.ResultChan():
				require.Equal(t, watch.Added, event.Type)
				got := event.Object.(*softwarecomposition.ContainerProfile)
				require.Equal(t, stored.ResourceVersion, got.ResourceVersion)
				if full {
					// Persisted Gob normalizes empty slices to nil; compare the full payload through that codec.
					var payload bytes.Buffer
					require.NoError(t, gob.NewEncoder(&payload).Encode(got))
					persisted := &softwarecomposition.ContainerProfile{}
					require.NoError(t, gob.NewDecoder(&payload).Decode(persisted))
					require.Equal(t, stored, persisted, "full watch must retain the saved payload despite response failure")
				} else {
					require.Equal(t, softwarecomposition.ContainerProfileSpec{}, got.Spec, "metadata watch must not expand")
				}
			case <-ctx.Done():
				t.Fatal("persisted Create lost its Added event after response-read failure", ctx.Err())
			}
		})
	}
}
