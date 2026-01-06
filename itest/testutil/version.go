package testutil

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"golang.org/x/mod/modfile"
)

const (
	modName       = "github.com/babylonlabs-io/babylon/v4"
	githubAPIURL  = "https://api.github.com/repos/babylonlabs-io/babylon/commits/%s"
	requestTimout = 10 * time.Second
)

// pseudoVersionRegex matches Go pseudo-versions like:
// v4.0.0-snapshot.250925.0.20251201140620-7989574892c2
// The last 12 characters after the final dash are the abbreviated commit hash
var pseudoVersionRegex = regexp.MustCompile(`-([0-9a-f]{12})$`)

// githubCommitResponse represents the relevant fields from GitHub's commit API response
type githubCommitResponse struct {
	SHA string `json:"sha"`
}

// GetBabylonVersion returns babylond version from go.mod
// For pseudo-versions (snapshots), it extracts the commit hash and expands it
// to the full 40-character hash using GitHub API.
// For release versions (e.g., v4.2.1), it returns the version as-is.
func GetBabylonVersion() (string, error) {
	goModPath, err := findGoMod()
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(goModPath)
	if err != nil {
		return "", err
	}

	// Parse the go.mod file
	modFile, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return "", err
	}

	for _, require := range modFile.Require {
		if require.Mod.Path == modName {
			version := require.Mod.Version

			// Check if it's a pseudo-version (contains abbreviated commit hash)
			shortHash := extractShortHash(version)
			if shortHash == "" {
				// Not a pseudo-version, return as-is (e.g., v4.2.1)
				return version, nil
			}

			// Expand the short hash to full 40-character hash via GitHub API
			fullHash, err := expandCommitHash(shortHash)
			if err != nil {
				return "", fmt.Errorf("failed to expand commit hash %s: %w", shortHash, err)
			}

			return fullHash, nil
		}
	}

	return "", fmt.Errorf("module %s not found", modName)
}

// extractShortHash extracts the 12-character abbreviated commit hash from a pseudo-version.
// Returns empty string if the version is not a pseudo-version.
func extractShortHash(version string) string {
	matches := pseudoVersionRegex.FindStringSubmatch(version)
	if len(matches) != 2 {
		return ""
	}
	return matches[1]
}

// findGoMod searches for go.mod starting from the current directory
// and walking up the directory tree until it finds one.
func findGoMod() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return goModPath, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root without finding go.mod
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}

// expandCommitHash expands an abbreviated commit hash to the full 40-character hash
// using the GitHub API.
func expandCommitHash(shortHash string) (string, error) {
	url := fmt.Sprintf(githubAPIURL, shortHash)

	client := &http.Client{Timeout: requestTimout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	// Use GITHUB_TOKEN if available (provides higher rate limits in CI)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch commit info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var commitResp githubCommitResponse
	if err := json.NewDecoder(resp.Body).Decode(&commitResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if commitResp.SHA == "" {
		return "", fmt.Errorf("empty SHA in response")
	}

	return commitResp.SHA, nil
}
