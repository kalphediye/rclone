//go:build go1.20

package seafile

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/object"
	"github.com/stretchr/testify/assert"
)

func TestNewFsWithProxiedServer(t *testing.T) {
	// creates a reverse proxy to a local instance of seafile
	host := "localhost:8088"
	target, _ := url.Parse("http://" + host)
	handler := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = host
			t.Logf("calling %s on %s", pr.Out.Method, pr.Out.URL.String())
		},
		ModifyResponse: func(r *http.Response) error {
			t.Logf("%s response: %s", r.Request.URL.String(), r.Status)
			return nil
		},
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	options := configmap.Simple{
		"url":            server.URL,
		"library":        "My Library",
		"user":           "seafile@rclone.org",
		"pass":           "GYdWLJQb55COZYnO9Zl0GcKc_SYDr0EMVcl6rnZVFxV8zoLPBjJ7NQ",
		"create_library": "true",
	}
	fs, err := NewFs(context.Background(), "TestSeafile", "", options)
	if err != nil && strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Skip("cannot contact local seafile instance")
	}
	assert.NoError(t, err)
	assert.NotEmpty(t, fs)
}

// this test is using a reverse proxy to simulate one broken chunk during an upload
// a local instance of seafile needs to be started from the script "fstest/testserver/init.d/TestSeafile"
func TestFailedChunkUploadWithProxiedServer(t *testing.T) {
	var chunkSize fs.SizeSuffix = 1048576
	chunkCount := 0

	var proxyURL []byte

	// creates a reverse proxy to a local instance of seafile
	host := "127.0.0.1:8088"
	target, _ := url.Parse("http://" + host)
	handler := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = host
			pr.Out.Header.Del("Accept-Encoding") // we don't want to decompress and recompress the response
			if strings.Contains(pr.Out.URL.String(), "/upload-api/") {
				chunkCount++
				t.Logf("uploading chunk %s (%d)", pr.Out.Header.Get("Content-Range"), chunkCount)
				if chunkCount == 2 {
					t.Log("this chunk should fail")
					// the length of the data won't match with the Content-Length header
					pr.Out.Body = io.NopCloser(io.LimitReader(pr.In.Body, 1000))
				}
			}
		},
		ModifyResponse: func(r *http.Response) error {
			b, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()

			// replace the URLs with the reverse proxy
			b = bytes.ReplaceAll(b, []byte("http://"+host), proxyURL)
			buf := bytes.NewBuffer(b)
			r.Body = io.NopCloser(buf)
			r.Header.Set("Content-Length", strconv.Itoa(buf.Len()))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if strings.Contains(err.Error(), "transport connection broken") {
				// we need to send a 500 error like the seafile server would do in case of a transmission error
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			t.Log(err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	proxyURL = []byte(server.URL)

	options := configmap.Simple{
		"url":            server.URL,
		"library":        "My Library",
		"user":           "seafile@rclone.org",
		"pass":           "GYdWLJQb55COZYnO9Zl0GcKc_SYDr0EMVcl6rnZVFxV8zoLPBjJ7NQ",
		"create_library": "true",
		"upload_cutoff":  chunkSize.String(),
		"chunk_size":     chunkSize.String(),
	}
	fs, err := NewFs(context.Background(), "TestSeafile", "", options)
	if err != nil && strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Skip("cannot contact local seafile instance")
	}
	assert.NoError(t, err)
	assert.NotEmpty(t, fs)

	// should allow for at least 3 chunks
	buffer := &bytes.Buffer{}
	iterations := int(chunkSize) * 3 / len(smallContent)
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
