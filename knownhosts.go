package sshutil

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"runtime"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	DefaultKnownHostsFileMode = 0600
)

const (
	ErrorNoKnownHostsFilePresent = "the known hosts file does not exist"
	ErrorUnknownHostKey          = "the specified host is not present in the known hosts file"
)

type SSHHostKeyPromptInfo struct {
	UserFacingPrompt    string
	FoundKnownHostsFile bool
	RemoteHostname      string
	RemotePublicKey     ssh.PublicKey
}

// ImitateSSHClientHostKeyCallBack returns a ssh.HostKeyCallback that
// imitates the standard SSH command line client's behavior of prompting the
// user to verify an unknown public key, as well as rejecting mismatched public
// keys. This callback will call the provided promptFunc, which provides data
// about the host. The function should return 'true' if the user accepts the
// SSH host key. The function should return 'false' if the user does not
// accept the key.
func ImitateSSHClientHostKeyCallBack(promptFunc func(SSHHostKeyPromptInfo) bool) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, currentKey ssh.PublicKey) error {
		exists, knownHostsPath, err := GetKnownHostsFile()
		if err != nil {
			return err
		}

		if exists {
			raw, err := ioutil.ReadFile(knownHostsPath)
			if err != nil {
				return err
			}

			isKnown, err := IsSSHHostKnown(currentKey, hostname, raw)
			if err != nil {
				return err
			}

			if isKnown {
				return nil
			}
		}

		if !promptFunc(SSHHostKeyPromptInfo{
			UserFacingPrompt:    getSSHPublicKeyPrompt(exists, hostname, currentKey),
			FoundKnownHostsFile: exists,
			RemoteHostname:      hostname,
			RemotePublicKey:     currentKey,
		}) {
			return fmt.Errorf("host key was rejected by user for %s", hostname)
		}

		err = AddHostKeyToKnownHosts(knownHostsPath, hostname, currentKey)
		if err != nil {
			return err
		}

		return nil
	}
}

// OnlyKnownHostKeyCallBack only permits known hosts when connecting to a SSH
// server. ErrorUnknownHostKey is returned if the host key does not exist in
// the known hosts file.
func OnlyAllowKnownHostsKeyCallBack(hostname string, remote net.Addr, currentKey ssh.PublicKey) error {
	exists, knownHostsPath, err := GetKnownHostsFile()
	if err != nil {
		return err
	}

	if !exists {
		return errors.New(ErrorNoKnownHostsFilePresent)
	}

	raw, err := ioutil.ReadFile(knownHostsPath)
	if err != nil {
		return err
	}

	isKnown, err := IsSSHHostKnown(currentKey, hostname, raw)
	if err != nil {
		return err
	}

	if isKnown {
		return nil
	}

	return errors.New(ErrorUnknownHostKey)
}

// AllowAndAddHostKeyCallBack permits any host and adds its key to the known
// hosts file.
func AllowAndAddHostKeyCallBack(hostname string, remote net.Addr, currentKey ssh.PublicKey) error {
	exists, knownHostsPath, err := GetKnownHostsFile()
	if err != nil {
		return err
	}

	if !exists {
		return errors.New(ErrorNoKnownHostsFilePresent)
	}

	raw, err := ioutil.ReadFile(knownHostsPath)
	if err != nil {
		return err
	}

	isKnown, err := IsSSHHostKnown(currentKey, hostname, raw)
	if err != nil {
		return err
	}

	if isKnown {
		return nil
	}

	err = AddHostKeyToKnownHosts(knownHostsPath, hostname, currentKey)
	if err != nil {
		return nil
	}

	return nil
}

// GetKnownHostsFile gets the path to the SSH known hosts file. The file path
// is not returned if the path could not be constructed. An error is returned
// when the file's path cannot be determined or if the file's mask is not equal
// to DefaultKnownHostsFileMode.
func GetKnownHostsFile() (exists bool, filePath string, err error) {
	sshDirPath, err := currentUserSSHDirectory()
	if err != nil {
		return false, "", fmt.Errorf("failed to get user's ssh directory - %w", err)
	}

	filePath = path.Join(sshDirPath, "known_hosts")

	info, statErr := os.Stat(filePath)
	if statErr != nil {
		return  false, filePath, nil
	}

	if runtime.GOOS != "windows" {
		if info.Mode() > DefaultKnownHostsFileMode {
			return false, filePath,
				fmt.Errorf("ssh known hosts file at '%s' file mode must be %o - it is %o",
					filePath, DefaultKnownHostsFileMode, info.Mode())
		}
	}

	return true, filePath, nil
}

// IsSSHHostKnown determines if an SSH server is known by the client according to
// the known hosts file.
func IsSSHHostKnown(hostPublicKey ssh.PublicKey, hostname string, fileContents []byte) (bool, error) {
	if fileContents == nil || len(fileContents) == 0 {
		return false, nil
	}

	_, knownHostAddresses, knownHostKey, _, rest, err := ssh.ParseKnownHosts(fileContents)
	if err != nil {
		return false, err
	}

	for _, knownHostAddress := range knownHostAddresses {
		// Super hack because Go forces us to include the port with the
		// hostname. SSH does not treat <address> and <address>:22 as the
		// same...
		if strings.HasSuffix(hostname, ":22") {
			hostname = strings.TrimSuffix(hostname, ":22")
		}

		if knownHostAddress == hostname {
			if ssh.FingerprintSHA256(knownHostKey) == ssh.FingerprintSHA256(hostPublicKey) {
				return true, nil
			} else {
				return false, fmt.Errorf("[!!!WARNING!!!] public key for '%s' does not match existing entry in SSH known hosts file. Someone might be doing something evil",
					hostname)
			}
		}
	}

	return IsSSHHostKnown(hostPublicKey, hostname, rest)
}

// AddHostKeyToKnownHosts adds a host key to the known hosts file.
func AddHostKeyToKnownHosts(knownHostsFilePath string, hostname string, key ssh.PublicKey) error {
	knownHosts, err := os.OpenFile(knownHostsFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, DefaultKnownHostsFileMode)
	if err != nil {
		return err
	}
	defer knownHosts.Close()

	_, err = knownHosts.WriteString(knownhosts.Line([]string{hostname}, key) + "\n")
	if err != nil {
		return err
	}

	return nil
}

func getSSHPublicKeyPrompt(couldReadKnownHostsFile bool, hostname string, key ssh.PublicKey) string {
	message := ""

	if !couldReadKnownHostsFile {
		message = "[WARN] failed to read known hosts file - "
	}

	return fmt.Sprintf("%sthe authenticity of host '%s' can't be established.\n" +
		"SHA256 key fingerprint is %s.\nAre you sure you want to continue connecting?",
			message, hostname,  ssh.FingerprintSHA256(key))
}
