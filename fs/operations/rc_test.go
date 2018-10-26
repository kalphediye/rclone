package operations_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ncw/rclone/fs"
	"github.com/ncw/rclone/fs/operations"
	"github.com/ncw/rclone/fs/rc"
	"github.com/ncw/rclone/fstest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rcNewRun(t *testing.T, method string) (*fstest.Run, *rc.Call) {
	if *fstest.RemoteName != "" {
		t.Skip("Skipping test on non local remote")
	}
	r := fstest.NewRun(t)
	call := rc.Calls.Get(method)
	assert.NotNil(t, call)
	rc.PutCachedFs(r.LocalName, r.Flocal)
	rc.PutCachedFs(r.FremoteName, r.Fremote)
	return r, call
}

// operations/about: Return the space used on the remote
func TestRcAbout(t *testing.T) {
	r, call := rcNewRun(t, "operations/about")
	defer r.Finalise()
	r.Mkdir(r.Fremote)

	// Will get an error if remote doesn't support About
	expectedErr := r.Fremote.Features().About == nil

	in := rc.Params{
		"fs": r.FremoteName,
	}
	out, err := call.Fn(in)
	if expectedErr {
		assert.Error(t, err)
		return
	}
	require.NoError(t, err)

	// Can't really check the output much!
	assert.NotEqual(t, int64(0), out["Total"])
}

// operations/cleanup: Remove trashed files in the remote or path
func TestRcCleanup(t *testing.T) {
	r, call := rcNewRun(t, "operations/cleanup")
	defer r.Finalise()

	in := rc.Params{
		"fs": r.LocalName,
	}
	out, err := call.Fn(in)
	require.Error(t, err)
	assert.Equal(t, rc.Params(nil), out)
	assert.Contains(t, err.Error(), "doesn't support cleanup")
}

// operations/copyfile: Copy a file from source remote to destination remote
func TestRcCopyfile(t *testing.T) {
	r, call := rcNewRun(t, "operations/copyfile")
	defer r.Finalise()
	file1 := r.WriteFile("file1", "file1 contents", t1)
	r.Mkdir(r.Fremote)
	fstest.CheckItems(t, r.Flocal, file1)
	fstest.CheckItems(t, r.Fremote)

	in := rc.Params{
		"srcFs":     r.LocalName,
		"srcRemote": "file1",
		"dstFs":     r.FremoteName,
		"dstRemote": "file1-renamed",
	}
	out, err := call.Fn(in)
	require.NoError(t, err)
	assert.Equal(t, rc.Params(nil), out)

	fstest.CheckItems(t, r.Flocal, file1)
	file1.Path = "file1-renamed"
	fstest.CheckItems(t, r.Fremote, file1)
}

// operations/copyurl: Copy the URL to the object
func TestRcCopyurl(t *testing.T) {
	r, call := rcNewRun(t, "operations/copyurl")
	defer r.Finalise()
	contents := "file1 contents\n"
	file1 := r.WriteFile("file1", contents, t1)
	r.Mkdir(r.Fremote)
	fstest.CheckItems(t, r.Fremote)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(contents))
		assert.NoError(t, err)
	}))
	defer ts.Close()

	in := rc.Params{
		"fs":     r.FremoteName,
		"remote": "file1",
		"url":    ts.URL,
	}
	out, err := call.Fn(in)
	require.NoError(t, err)
	assert.Equal(t, rc.Params(nil), out)

	fstest.CheckListingWithPrecision(t, r.Fremote, []fstest.Item{file1}, nil, fs.ModTimeNotSupported)
}

// operations/delete: Remove files in the path
func TestRcDelete(t *testing.T) {
	r, call := rcNewRun(t, "operations/delete")
	defer r.Finalise()

	file1 := r.WriteObject("small", "1234567890", t2)                                                                                           // 10 bytes
	file2 := r.WriteObject("medium", "------------------------------------------------------------", t1)                                        // 60 bytes
	file3 := r.WriteObject("large", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", t1) // 100 bytes
	fstest.CheckItems(t, r.Fremote, file1, file2, file3)

	in := rc.Params{
		"fs": r.FremoteName,
	}
	out, err := call.Fn(in)
	require.NoError(t, err)
	assert.Equal(t, rc.Params(nil), out)

	fstest.CheckItems(t, r.Fremote)
}

// operations/deletefile: Remove the single file pointed to
func TestRcDeletefile(t *testing.T) {
	r, call := rcNewRun(t, "operations/deletefile")
	defer r.Finalise()

	file1 := r.WriteObject("small", "1234567890", t2)                                                    // 10 bytes
	file2 := r.WriteObject("medium", "------------------------------------------------------------", t1) // 60 bytes
	fstest.CheckItems(t, r.Fremote, file1, file2)

	in := rc.Params{
		"fs":     r.FremoteName,
		"remote": "small",
	}
	out, err := call.Fn(in)
	require.NoError(t, err)
	assert.Equal(t, rc.Params(nil), out)

	fstest.CheckItems(t, r.Fremote, file2)
}

// operations/list: List the given remote and path in JSON format
func TestRcList(t *testing.T) {
	r, call := rcNewRun(t, "operations/list")
	defer r.Finalise()

	file1 := r.WriteObject("a", "a", t1)
	file2 := r.WriteObject("subdir/b", "bb", t2)

	fstest.CheckItems(t, r.Fremote, file1, file2)

	in := rc.Params{
		"fs":     r.FremoteName,
		"remote": "",
	}
	out, err := call.Fn(in)
	require.NoError(t, err)

	list := out["list"].([]*operations.ListJSONItem)
	assert.Equal(t, 2, len(list))

	checkFile1 := func(got *operations.ListJSONItem) {
		assert.WithinDuration(t, t1, time.Time(got.ModTime), time.Second)
		assert.Equal(t, "a", got.Path)
		assert.Equal(t, "a", got.Name)
		assert.Equal(t, int64(1), got.Size)
		assert.Equal(t, "application/octet-stream", got.MimeType)
		assert.Equal(t, false, got.IsDir)
	}
	checkFile1(list[0])

	checkSubdir := func(got *operations.ListJSONItem) {
		assert.Equal(t, "subdir", got.Path)
		assert.Equal(t, "subdir", got.Name)
		assert.Equal(t, int64(-1), got.Size)
		assert.Equal(t, "inode/directory", got.MimeType)
		assert.Equal(t, true, got.IsDir)
	}
	checkSubdir(list[1])

	in = rc.Params{
		"fs":     r.FremoteName,
		"remote": "",
		"opt": rc.Params{
			"recurse": true,
		},
	}
	out, err = call.Fn(in)
	require.NoError(t, err)

	list = out["list"].([]*operations.ListJSONItem)
	assert.Equal(t, 3, len(list))
	checkFile1(list[0])
	checkSubdir(list[1])

	checkFile2 := func(got *operations.ListJSONItem) {
		assert.WithinDuration(t, t2, time.Time(got.ModTime), time.Second)
		assert.Equal(t, "subdir/b", got.Path)
		assert.Equal(t, "b", got.Name)
		assert.Equal(t, int64(2), got.Size)
		assert.Equal(t, "application/octet-stream", got.MimeType)
		assert.Equal(t, false, got.IsDir)
	}
	checkFile2(list[2])
}

// operations/mkdir: Make a destination directory or container
func TestRcMkdir(t *testing.T) {
	r, call := rcNewRun(t, "operations/mkdir")
	defer r.Finalise()
	r.Mkdir(r.Fremote)

	fstest.CheckListingWithPrecision(t, r.Fremote, []fstest.Item{}, []string{}, fs.GetModifyWindow(r.Fremote))

	in := rc.Params{
		"fs":     r.FremoteName,
		"remote": "subdir",
	}
	out, err := call.Fn(in)
	require.NoError(t, err)
	assert.Equal(t, rc.Params(nil), out)

	fstest.CheckListingWithPrecision(t, r.Fremote, []fstest.Item{}, []string{"subdir"}, fs.GetModifyWindow(r.Fremote))
}

// operations/movefile: Move a file from source remote to destination remote
func TestRcMovefile(t *testing.T) {
	r, call := rcNewRun(t, "operations/movefile")
	defer r.Finalise()
	file1 := r.WriteFile("file1", "file1 contents", t1)
	r.Mkdir(r.Fremote)
	fstest.CheckItems(t, r.Flocal, file1)
	fstest.CheckItems(t, r.Fremote)

	in := rc.Params{
		"srcFs":     r.LocalName,
		"srcRemote": "file1",
		"dstFs":     r.FremoteName,
		"dstRemote": "file1-renamed",
	}
	out, err := call.Fn(in)
	require.NoError(t, err)
	assert.Equal(t, rc.Params(nil), out)

	fstest.CheckItems(t, r.Flocal)
	file1.Path = "file1-renamed"
	fstest.CheckItems(t, r.Fremote, file1)
}

// operations/purge: Remove a directory or container and all of its contents
func TestRcPurge(t *testing.T) {
	r, call := rcNewRun(t, "operations/purge")
	defer r.Finalise()
	file1 := r.WriteObject("subdir/file1", "subdir/file1 contents", t1)

	fstest.CheckListingWithPrecision(t, r.Fremote, []fstest.Item{file1}, []string{"subdir"}, fs.GetModifyWindow(r.Fremote))

	in := rc.Params{
		"fs":     r.FremoteName,
		"remote": "subdir",
	}
	out, err := call.Fn(in)
	require.NoError(t, err)
	assert.Equal(t, rc.Params(nil), out)

	fstest.CheckListingWithPrecision(t, r.Fremote, []fstest.Item{}, []string{}, fs.GetModifyWindow(r.Fremote))
}

// operations/rmdir: Remove an empty directory or container
func TestRcRmdir(t *testing.T) {
	r, call := rcNewRun(t, "operations/rmdir")
	defer r.Finalise()
	r.Mkdir(r.Fremote)
	assert.NoError(t, r.Fremote.Mkdir("subdir"))

	fstest.CheckListingWithPrecision(t, r.Fremote, []fstest.Item{}, []string{"subdir"}, fs.GetModifyWindow(r.Fremote))

	in := rc.Params{
		"fs":     r.FremoteName,
		"remote": "subdir",
	}
	out, err := call.Fn(in)
	require.NoError(t, err)
	assert.Equal(t, rc.Params(nil), out)

	fstest.CheckListingWithPrecision(t, r.Fremote, []fstest.Item{}, []string{}, fs.GetModifyWindow(r.Fremote))
}

// operations/rmdirs: Remove all the empty directories in the path
func TestRcRmdirs(t *testing.T) {
	r, call := rcNewRun(t, "operations/rmdirs")
	defer r.Finalise()
	r.Mkdir(r.Fremote)
	assert.NoError(t, r.Fremote.Mkdir("subdir"))
	assert.NoError(t, r.Fremote.Mkdir("subdir/subsubdir"))

	fstest.CheckListingWithPrecision(t, r.Fremote, []fstest.Item{}, []string{"subdir", "subdir/subsubdir"}, fs.GetModifyWindow(r.Fremote))

	in := rc.Params{
		"fs":     r.FremoteName,
		"remote": "subdir",
	}
	out, err := call.Fn(in)
	require.NoError(t, err)
	assert.Equal(t, rc.Params(nil), out)

	fstest.CheckListingWithPrecision(t, r.Fremote, []fstest.Item{}, []string{}, fs.GetModifyWindow(r.Fremote))

	assert.NoError(t, r.Fremote.Mkdir("subdir"))
	assert.NoError(t, r.Fremote.Mkdir("subdir/subsubdir"))

	in = rc.Params{
		"fs":        r.FremoteName,
		"remote":    "subdir",
		"leaveRoot": true,
	}
	out, err = call.Fn(in)
	require.NoError(t, err)
	assert.Equal(t, rc.Params(nil), out)

	fstest.CheckListingWithPrecision(t, r.Fremote, []fstest.Item{}, []string{"subdir"}, fs.GetModifyWindow(r.Fremote))

}

// operations/size: Count the number of bytes and files in remote
func TestRcSize(t *testing.T) {
	r, call := rcNewRun(t, "operations/size")
	defer r.Finalise()
	file1 := r.WriteObject("small", "1234567890", t2)                                                           // 10 bytes
	file2 := r.WriteObject("subdir/medium", "------------------------------------------------------------", t1) // 60 bytes
	file3 := r.WriteObject("subdir/subsubdir/large", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", t1)  // 50 bytes
	fstest.CheckItems(t, r.Fremote, file1, file2, file3)

	in := rc.Params{
		"fs": r.FremoteName,
	}
	out, err := call.Fn(in)
	require.NoError(t, err)
	assert.Equal(t, rc.Params{
		"count": int64(3),
		"bytes": int64(120),
	}, out)
}
