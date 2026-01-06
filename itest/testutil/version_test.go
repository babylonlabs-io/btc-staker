package testutil

import (
	"testing"
)

func TestExtractShortHash(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "pseudo-version with snapshot",
			version:  "v4.0.0-snapshot.250925.0.20251201140620-7989574892c2",
			expected: "7989574892c2",
		},
		{
			name:     "standard pseudo-version",
			version:  "v0.0.0-20231201120000-abcdef123456",
			expected: "abcdef123456",
		},
		{
			name:     "release version",
			version:  "v4.2.1",
			expected: "",
		},
		{
			name:     "release version with suffix",
			version:  "v4.2.1-testnet",
			expected: "",
		},
		{
			name:     "pre-release version",
			version:  "v4.0.0-rc1",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractShortHash(tt.version)
			if result != tt.expected {
				t.Errorf("extractShortHash(%q) = %q, want %q", tt.version, result, tt.expected)
			}
		})
	}
}

func TestExpandCommitHash(t *testing.T) {
	// This test requires network access to GitHub API
	// Skip in short mode
	if testing.Short() {
		t.Skip("skipping test that requires network access")
	}

	shortHash := "7989574892c2"
	expectedFull := "7989574892c28f334f54f27006557be0052ba907"

	fullHash, err := expandCommitHash(shortHash)
	if err != nil {
		t.Fatalf("expandCommitHash(%q) failed: %v", shortHash, err)
	}

	if fullHash != expectedFull {
		t.Errorf("expandCommitHash(%q) = %q, want %q", shortHash, fullHash, expectedFull)
	}
}

func TestGetBabylonVersion(t *testing.T) {
	// This test requires network access to GitHub API
	// Skip in short mode
	if testing.Short() {
		t.Skip("skipping test that requires network access")
	}

	version, err := GetBabylonVersion()
	if err != nil {
		t.Fatalf("GetBabylonVersion() failed: %v", err)
	}

	// Version should be a 40-character hex string (full commit hash)
	// or a valid semver tag
	if len(version) != 40 && version[0] != 'v' {
		t.Errorf("GetBabylonVersion() = %q, expected 40-char hash or version tag", version)
	}

	t.Logf("Babylon version: %s", version)
}
