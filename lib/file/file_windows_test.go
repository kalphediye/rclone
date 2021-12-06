//go:build windows
// +build windows

package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileOpenMaxPathLength(t *testing.T) {
	path := `C:\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path\my\path`
	_, err := OpenFile(path, 0644, 0644)
	assert.Error(t, err, "mkdir: Max path length can't exceed 260")
}
