package operations

import (
	"fmt"
	"testing"

	"github.com/ncw/rclone/fs"
	"github.com/ncw/rclone/fstest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultithreadCalculateChunks(t *testing.T) {
	for _, test := range []struct {
		size         int64
		streams      int
		wantPartSize int64
		wantStreams  int
	}{
		{size: 1, streams: 10, wantPartSize: multithreadChunkSize, wantStreams: 1},
		{size: 1 << 20, streams: 1, wantPartSize: 1 << 20, wantStreams: 1},
		{size: 1 << 20, streams: 2, wantPartSize: 1 << 19, wantStreams: 2},
		{size: (1 << 20) + 1, streams: 2, wantPartSize: (1 << 19) + multithreadChunkSize, wantStreams: 2},
		{size: (1 << 20) - 1, streams: 2, wantPartSize: (1 << 19), wantStreams: 2},
	} {
		t.Run(fmt.Sprintf("%+v", test), func(t *testing.T) {
			mc := &multiThreadCopyState{
				size:    test.size,
				streams: test.streams,
			}
			mc.calculateChunks()
			assert.Equal(t, test.wantPartSize, mc.partSize)
			assert.Equal(t, test.wantStreams, mc.streams)
		})
	}
}

func TestMultithreadCopy(t *testing.T) {
	r := fstest.NewRun(t)
	defer r.Finalise()

	for _, test := range []struct {
		size    int
		streams int
	}{
		{size: multithreadChunkSize*2 - 1, streams: 2},
		{size: multithreadChunkSize * 2, streams: 2},
		{size: multithreadChunkSize*2 + 1, streams: 2},
	} {
		t.Run(fmt.Sprintf("%+v", test), func(t *testing.T) {
			contents := fstest.RandomString(test.size)
			t1 := fstest.Time("2001-02-03T04:05:06.499999999Z")
			file1 := r.WriteObject("file1", contents, t1)
			fstest.CheckItems(t, r.Fremote, file1)
			fstest.CheckItems(t, r.Flocal)

			src, err := r.Fremote.NewObject("file1")
			require.NoError(t, err)

			dst, err := multiThreadCopy(r.Flocal, "file1", src, 2)
			require.NoError(t, err)
			assert.Equal(t, src.Size(), dst.Size())
			assert.Equal(t, "file1", dst.Remote())

			fstest.CheckListingWithPrecision(t, r.Fremote, []fstest.Item{file1}, nil, fs.ModTimeNotSupported)
			require.NoError(t, dst.Remove())
		})
	}

}
