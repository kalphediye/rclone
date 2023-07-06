package seafile

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/object"
	"github.com/stretchr/testify/assert"
)

var (
	smallContent = []byte("01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

func getBasicHandler(t *testing.T, libraryID, libraryName string) *http.ServeMux {
	t.Helper()

	handler := http.NewServeMux()
	handler.HandleFunc("/api2/server-info/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"9.0.10"}`))
	})
	handler.HandleFunc("/api2/auth-token/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token":"test_token"}`))
	})
	handler.HandleFunc("/api2/repos/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`[{"encrypted":false,"id":"%s","size":10,"name":"%s"}]`, libraryID, libraryName)))
	})
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Logf("unhandled call to %q", r.URL.String())
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not found: " + r.URL.String()))
	})
	return handler
}

func TestNewFsWithMockServer(t *testing.T) {
	handler := getBasicHandler(t, "library_id", "My Library")
	server := httptest.NewServer(handler)
	defer server.Close()

	options := configmap.Simple{
		"url":     server.URL,
		"library": "My Library",
	}
	fs, err := NewFs(context.Background(), "TestSeafile", "", options)
	assert.NoError(t, err)
	assert.NotEmpty(t, fs)
}

func TestUploadWholeFileWithErrorNoRetry(t *testing.T) {
	handler := getBasicHandler(t, "library_id", "My Library")
	server := httptest.NewServer(handler)
	defer server.Close()

	// call to retrieve an upload slot
	handler.HandleFunc("/api2/repos/library_id/upload-link/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`"%s/upload-api/temp_upload"`, server.URL)))
	})
	// upload will fail
	handler.HandleFunc("/upload-api/temp_upload", func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		w.WriteHeader(http.StatusInternalServerError)
	})

	options := configmap.Simple{
		"url":           server.URL,
		"library":       "My Library",
		"upload_cutoff": defaultUploadCutoff.String(),
		"chunk_size":    defaultChunkSize.String(),
	}
	fs, err := NewFs(context.Background(), "TestSeafile", "", options)
	assert.NoError(t, err)
	assert.NotEmpty(t, fs)

	src := object.NewStaticObjectInfo("new file.txt", time.Now(), int64(len(smallContent)), true, nil, nil)
	// call should fail
	in := bytes.NewReader(smallContent)
	_, err = fs.Put(context.Background(), in, src)
	assert.Error(t, err)
}

func TestUploadWholeFile(t *testing.T) {
	handler := getBasicHandler(t, "library_id", "My Library")
	server := httptest.NewServer(handler)
	defer server.Close()

	// call to retrieve an upload slot
	handler.HandleFunc("/api2/repos/library_id/upload-link/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`"%s/upload-api/temp_upload"`, server.URL)))
	})
	handler.HandleFunc("/upload-api/temp_upload", func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()

		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		assert.NoError(t, err)
		assert.Equal(t, "multipart/form-data", mediaType)
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				return
			}
			assert.NoError(t, err)
			if p.FileName() == "new file.txt" {
				body, err := io.ReadAll(p)
				assert.NoError(t, err)
				assert.Equal(t, smallContent, body)

				// sends response now
				_, _ = w.Write([]byte(fmt.Sprintf(`[{"name":"new file.txt","size":%d}]`, len(body))))
			}
		}
	})

	options := configmap.Simple{
		"url":           server.URL,
		"library":       "My Library",
		"upload_cutoff": defaultUploadCutoff.String(),
		"chunk_size":    defaultChunkSize.String(),
	}
	fs, err := NewFs(context.Background(), "TestSeafile", "", options)
	assert.NoError(t, err)
	assert.NotEmpty(t, fs)

	src := object.NewStaticObjectInfo("new file.txt", time.Now(), int64(len(smallContent)), true, nil, nil)
	in := bytes.NewReader(smallContent)
	object, err := fs.Put(context.Background(), in, src)
	assert.NoError(t, err)
	assert.NotEmpty(t, object)
	assert.Equal(t, int64(len(smallContent)), object.Size())
}

func TestUploadFileByChunksWithRetryOnError(t *testing.T) {
	var chunkSize fs.SizeSuffix = 1048576
	chunkCount := 0
	read := 0
	handler := getBasicHandler(t, "library_id", "My Library")
	server := httptest.NewServer(handler)
	defer server.Close()

	// call to retrieve an upload slot
	handler.HandleFunc("/api2/repos/library_id/upload-link/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`"%s/upload-api/temp_upload"`, server.URL)))
	})

	// call to upload chunks
	handler.HandleFunc("/upload-api/temp_upload", func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()

		chunkCount++
		t.Logf("received chunk %d", chunkCount)
		if chunkCount == 2 {
			// simulate an error on the second chunk
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		partLen := 0
		// read all the data
		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		assert.NoError(t, err)
		assert.Equal(t, "multipart/form-data", mediaType)
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				return
			}
			assert.NoError(t, err)
			if p.FileName() == "new file.txt" {
				body, err := io.ReadAll(p)
				assert.NoError(t, err)
				partLen = len(body)
				read += partLen
				break
			}
		}

		// check the content-range header
		contentRange := r.Header.Get("Content-Range")
		t.Logf("uploaded %s", contentRange)
		pattern := regexp.MustCompile(`bytes (\d+)-(\d+)\/(\d+)`)
		match := pattern.FindStringSubmatch(contentRange)
		if len(match) == 4 {
			start, err := strconv.Atoi(match[1])
			assert.NoError(t, err)
			end, err := strconv.Atoi(match[2])
			assert.NoError(t, err)
			size, err := strconv.Atoi(match[3])
			assert.NoError(t, err)

			// make sure the chunk size is right
			assert.Equal(t, end-start+1, partLen)

			if end+1 == size {
				// this was the last chunk
				_, _ = w.Write([]byte(fmt.Sprintf(`[{"name":"new file.txt","id":"new_file_id","size":%d}]`, read)))
				return
			}
		}
		// keep going to the next chunk
		_, _ = w.Write([]byte(`{"success":true}`))
	})

	options := configmap.Simple{
		"url":           server.URL,
		"library":       "My Library",
		"upload_cutoff": chunkSize.String(),
		"chunk_size":    chunkSize.String(),
	}
	fs, err := NewFs(context.Background(), "TestSeafile", "", options)
	assert.NoError(t, err)
	assert.NotEmpty(t, fs)

	// should allow for at least 2 chunks
	buffer := &bytes.Buffer{}
	iterations := int(chunkSize) * 2 / len(smallContent)
	for i := 0; i <= iterations; i++ {
		buffer.Write(smallContent)
	}

	size := int64(buffer.Len())
	src := object.NewStaticObjectInfo("new file.txt", time.Now(), size, true, nil, nil)

	object, err := fs.Put(context.Background(), buffer, src)
	assert.NoError(t, err)
	assert.NotEmpty(t, object)
	assert.Equal(t, size, object.Size())
}
