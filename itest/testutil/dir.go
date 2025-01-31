package testutil

import (
	"os"
	"testing"
)

// TempDir creates a tmp dir
func TempDir(t *testing.T) (string, error) {
	t.Helper()
	tempPath, err := os.MkdirTemp(os.TempDir(), "babylon-test-*")
	if err != nil {
		return "", err
	}

	if err = os.Chmod(tempPath, 0777); err != nil {
		return "", err
	}

	t.Cleanup(func() {
		_ = os.RemoveAll(tempPath)
	})

	return tempPath, err
}
