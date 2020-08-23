package sshutil

import (
	"bufio"
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"strings"
)

const (
	OpenSSHPrivateKeyPEMLabel = "OPENSSH PRIVATE KEY"
)

// CurrentUserUnencryptedOpenSSHPrivateKeys returns only the current user's
// unencrypted OpenSSH private keys. This function implements the input for the
// ssh.PublicKeysCallback wrapper function
//
// See CurrentUserOpenSSHPrivateKeys for more information.
func CurrentUserUnencryptedOpenSSHPrivateKeys() ([]ssh.Signer, error) {
	return FindSSHPrivateKeys(FindSSHPrivateKeysConfig{
		DirPathFn:    currentUserSSHDirectory,
		IgnoreKeyErr: func(err error) bool {
			if keyErr, ok := err.(*IsSSHPrivateKeyError); ok {
				return keyErr.RequiresPassphrase
			}
			return false
		},
	})
}

// CurrentUserOpenSSHPrivateKeys implements the input for the
// ssh.PublicKeysCallback wrapper function. The function itself
// wraps the FindSSHPrivateKeys function using the default
// configuration values.
//
// See FindSSHPrivateKeys for more information.
func CurrentUserOpenSSHPrivateKeys() ([]ssh.Signer, error) {
	return FindSSHPrivateKeys(FindSSHPrivateKeysConfig{
		DirPathFn: currentUserSSHDirectory,
	})
}

type FindSSHPrivateKeysConfig struct {
	DirPathFn    func() (string, error)
	IgnoreKeyErr func(error) bool
}

func (o FindSSHPrivateKeysConfig) Validate() error {
	if o.DirPathFn == nil {
		return fmt.Errorf("dir path function cannot be nil")
	}

	return nil
}

// FindSSHPrivateKeys searches for OpenSSH private keys, parses them, and returns
// the corresponding ssh.Signers representing them using the specified config.
// By default, if any of the keys cannot be properly parsed, the function
// returns a non-nil error and a zero slice of ssh.Signer.
func FindSSHPrivateKeys(config FindSSHPrivateKeysConfig) ([]ssh.Signer, error) {
	sshDirPath, err := config.DirPathFn()
	if err != nil {
		return nil, fmt.Errorf("failed to get ssh directory path - %w", err)
	}

	sshDirFileInfos, err := ioutil.ReadDir(sshDirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ssh directory at '%s' - %w",
			sshDirPath, err)
	}

	var privateKeys []ssh.Signer
	for _, info := range sshDirFileInfos {
		if info.IsDir() || !info.Mode().IsRegular() || strings.HasSuffix(info.Name(), ".pub"){
			continue
		}

		filePath := path.Join(sshDirPath, info.Name())
		privateKey, isPrivateKey, err := IsPathSSHPrivateKey(filePath, OpenSSHPrivateKeyPEMLabel)
		if err != nil {
			if config.IgnoreKeyErr != nil && config.IgnoreKeyErr(err) {
				continue
			}
			return nil, fmt.Errorf("failed to get private key from '%s' - %w", filePath, err)
		}

		if !isPrivateKey {
			continue
		}

		privateKeys = append(privateKeys, privateKey)
	}

	return privateKeys, nil
}

// IsPathSSHPrivateKey returns a non-nil ssh.Signer, true, and a nil error if
// the PEM file specified at pemFilePath is an SSH private key according to the
// specified PEM label.
//
// A PEM label is the portion of the PEM '----- BEGIN' header that contains the
// expected data type. For example, the PEM label of the following header would
// be 'OPENSSH PRIVATE KEY':
//	-----BEGIN OPENSSH PRIVATE KEY-----
//
// Refer to RFC 7468 for more information: https://tools.ietf.org/html/rfc7468
//
// If the file is not an SSH private key, nil ssh.Signer, false, and a nil
// error are returned. If the file is an SSH private key, but could not be
// parsed, then nil ssh.Signer, true, and a non-nil error of type
// *IsSSHPrivateKeyError is returned.
func IsPathSSHPrivateKey(pemFilePath string, label string) (ssh.Signer, bool, error) {
	f, err := os.Open(pemFilePath)
	if err != nil {
		return nil, false, &IsSSHPrivateKeyError{
			FilePath:              pemFilePath,
			UnableToOpen:          true,
			OptionalUnderlyingErr: err,
			Message:               fmt.Sprintf("failed to open file - %s", err),
		}
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, false, &IsSSHPrivateKeyError{
			FilePath:              f.Name(),
			StatFail:              true,
			OptionalUnderlyingErr: err,
			Message:               fmt.Sprintf("failed to stat file get its mode - %s", err),
		}
	}

	if runtime.GOOS != "windows" && info.Mode() != 0600 {
		return nil, false, &IsSSHPrivateKeyError{
			FilePath:        f.Name(),
			CurrentFileMode: info.Mode(),
			BadFileMode:     true,
			Message:         fmt.Sprintf("the private key mode must be 0600 - it is %o",
				info.Mode()),
		}
	}

	s := bufio.NewScanner(f)
	s.Scan()
	if s.Text() != fmt.Sprintf("-----BEGIN %s-----", label) {
		return nil, false, nil
	}
	buff := bytes.NewBuffer(nil)
	buff.Write(s.Bytes())
	buff.WriteByte('\n')
	for s.Scan() {
		buff.Write(s.Bytes())
		buff.WriteByte('\n')
	}
	if err := s.Err(); err != nil {
		return nil, false, &IsSSHPrivateKeyError{
			FilePath:         f.Name(),
			CurrentFileMode:  info.Mode(),
			CopyContentsFail: true,
			Message:          fmt.Sprintf("failed to read file contents - %s", err),
		}
	}

	signer, err := ssh.ParsePrivateKey(buff.Bytes())
	switch err.(type) {
	case *ssh.PassphraseMissingError:
		return nil, false, &IsSSHPrivateKeyError{
			FilePath:              f.Name(),
			CurrentFileMode:       info.Mode(),
			RequiresPassphrase:    true,
			OptionalUnderlyingErr: err,
			Message:               err.Error(),
		}
	case nil:
		return signer, true, nil
	default:
		return nil, false, &IsSSHPrivateKeyError{
			FilePath:              f.Name(),
			CurrentFileMode:       info.Mode(),
			ParseFail:             true,
			OptionalUnderlyingErr: err,
			Message:               fmt.Sprintf("failed to parse file contents as a private key - %s",
				err),
		}
	}
}
