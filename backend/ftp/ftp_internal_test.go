package ftp

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/object"
	"github.com/rclone/rclone/fstest"
	"github.com/rclone/rclone/fstest/fstests"
	"github.com/rclone/rclone/lib/readers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type settings map[string]interface{}

func deriveFs(ctx context.Context, t *testing.T, f fs.Fs, opts settings) fs.Fs {
	fsName := strings.Split(f.Name(), "{")[0] // strip off hash
	configMap := configmap.Simple{}
	for key, val := range opts {
		configMap[key] = fmt.Sprintf("%v", val)
	}
	remote := fmt.Sprintf("%s,%s:%s", fsName, configMap.String(), f.Root())
	fixFs, err := fs.NewFs(ctx, remote)
	require.NoError(t, err)
	return fixFs
}

// test that big file uploads do not cause network i/o timeout
func (f *Fs) testUploadTimeout(t *testing.T) {
	const (
		fileSize    = 100000000             // 100 MiB
		idleTimeout = 40 * time.Millisecond // small because test server is local
		maxTime     = 5 * time.Second       // prevent test hangup
	)

	if testing.Short() {
		t.Skip("not running with -short")
	}

	ctx := context.Background()
	ci := fs.GetConfig(ctx)
	saveLowLevelRetries := ci.LowLevelRetries
	saveTimeout := ci.Timeout
	defer func() {
		ci.LowLevelRetries = saveLowLevelRetries
		ci.Timeout = saveTimeout
	}()
	ci.LowLevelRetries = 1
	ci.Timeout = idleTimeout

	upload := func(concurrency int, shutTimeout time.Duration) (obj fs.Object, err error) {
		fixFs := deriveFs(ctx, t, f, settings{
			"concurrency":  concurrency,
			"shut_timeout": shutTimeout,
		})

		// Make test object
		fileTime := fstest.Time("2020-03-08T09:30:00.000000000Z")
		meta := object.NewStaticObjectInfo("upload-timeout.test", fileTime, int64(fileSize), true, nil, nil)
		data := readers.NewPatternReader(int64(fileSize))

		// Run upload and ensure maximum time
		done := make(chan bool)
		deadline := time.After(maxTime)
		go func() {
			obj, err = fixFs.Put(ctx, data, meta)
			done <- true
		}()
		select {
		case <-done:
		case <-deadline:
			t.Fatalf("Upload got stuck for %v !", maxTime)
		}

		return obj, err
	}

	// i/o errors caused by zero shut_timeout shouldn't make upload hang
	_, err := upload(1, 0)
	assert.Error(t, err)
	if err != nil {
		t.Logf("Got expected error %q", err)
	}

	// non-zero shut_timeout should fix i/o errors
	obj, err := upload(f.opt.Concurrency, time.Second)
	assert.NoError(t, err)
	assert.NotNil(t, obj)
	if obj != nil {
		_ = obj.Remove(ctx)
	}
}

// test the about command
func (f *Fs) testAboutCommand(t *testing.T) {
	ctx := context.Background()
	fnAbout := f.Features().About
	assert.Nil(t, fnAbout)

	deriveAboutFs := func(cmd string) fs.Fs {
		return deriveFs(ctx, t, f, settings{"about_command": cmd})
	}
	fsAbout := deriveAboutFs("")
	fnAbout = fsAbout.Features().About
	assert.Nil(t, fnAbout)

	fsAbout = deriveAboutFs(`invalid-command`)
	fnAbout = fsAbout.Features().About
	require.NotNil(t, fnAbout)
	usage, err := fnAbout(ctx)
	assert.Error(t, err)
	assert.Nil(t, usage)

	fsAbout = deriveAboutFs(`echo "invalid json"`)
	fnAbout = fsAbout.Features().About
	require.NotNil(t, fnAbout)
	usage, err = fnAbout(ctx)
	assert.Error(t, err)
	assert.Nil(t, usage)

	fsAbout = deriveAboutFs(`echo '{"total":300000,"used":200000,"free":100000}'`)
	fnAbout = fsAbout.Features().About
	require.NotNil(t, fnAbout)
	usage, err = fnAbout(ctx)
	assert.NoError(t, err)
	require.NotNil(t, usage)

	assertUsage := func(expected int64, actualPtr *int64) {
		require.NotNil(t, actualPtr)
		assert.Equal(t, expected, *actualPtr)
	}
	assertUsage(300000, usage.Total)
	assertUsage(200000, usage.Used)
	assertUsage(100000, usage.Free)
}

// InternalTest dispatches all internal tests
func (f *Fs) InternalTest(t *testing.T) {
	t.Run("UploadTimeout", f.testUploadTimeout)
	t.Run("AboutCommand", f.testAboutCommand)
}

var _ fstests.InternalTester = (*Fs)(nil)
