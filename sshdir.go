package sshutil

import (
	"fmt"
	"os"
	"path"
)

func currentUserSSHDirectory() (string, error) {
	homeDirPath, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get current user's home directory - %w", err)
	}

	return path.Join(homeDirPath, ".ssh"), nil
}
