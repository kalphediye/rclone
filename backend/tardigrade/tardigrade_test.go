//go:build !plan9
// +build !plan9

// Test Tardigrade filesystem interface
package tardigrade_test

import (
	"github.com/rclone/rclone/backend/storj"
	"testing"

	"github.com/rclone/rclone/fstest/fstests"
)

// TestIntegration runs integration tests against the remote
func TestIntegration(t *testing.T) {
	fstests.Run(t, &fstests.Opt{
		RemoteName: "TestTardigrade:",
		NilObject:  (*storj.Object)(nil),
	})
}
