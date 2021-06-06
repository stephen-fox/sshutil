package sshutil

import (
	"bufio"
	"bytes"
	"errors"
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
// ssh.PublicKeysCallback wrapper function.
//
// Refer to FindSSHPrivateKeys for more information.
func CurrentUserUnencryptedOpenSSHPrivateKeys() ([]ssh.Signer, error) {
	return FindSSHPrivateKeys(FindSSHPrivateKeysConfig{
		DirPathFn:      currentUserSSHDirectory,
		IgnoreKeyErrFn: func(err error) bool {
			var isKeyErr *IsSSHPrivateKeyError
			if errors.As(err, &isKeyErr) {
				return isKeyErr.RequiresPassphrase
			}
			return false
		},
	})
}

// CurrentUserOpenSSHPrivateKeys returns the current user's OpenSSH private
// keys. This function implements the input for the ssh.PublicKeysCallback
// wrapper function. The function itself wraps the FindSSHPrivateKeys function
// using the default configuration values.
//
// Refer to FindSSHPrivateKeys for more information.
func CurrentUserOpenSSHPrivateKeys() ([]ssh.Signer, error) {
	return FindSSHPrivateKeys(FindSSHPrivateKeysConfig{
		DirPathFn: currentUserSSHDirectory,
	})
}

// FindSSHPrivateKeysConfig configures the FindSSHPrivateKeys function.
type FindSSHPrivateKeysConfig struct {
	// DirPathFn must be non-nil, and must return the path of
	// the directory to search. If an error is returned,
	// FindSSHPrivateKeys will stop, and return the error.
	DirPathFn func() (string, error)

	// IgnoreKeyErrFn, if specified, will be called if an error
	// occurs when parsing an SSH private key (the error being passed
	// to the function). If the function returns true, the error will
	// be ignored and FindSSHPrivateKeys will continue to the next
	// private key. If it returns false, FindSSHPrivateKeys will
	// stop parsing keys and return the error.
	IgnoreKeyErrFn func(error) bool

	// KeysToPassFn is a map of private key file names
	// (not absolute paths - only the file's name) to corresponding
	// GetPrivateKeyPasswordFunc. It is referenced when an SSH private
	// key could not be parsed due to a ssh.PassphraseMissingError error.
	// The map can be left uninitialized (nil) if desired.
	KeysToPassFn map[string]GetPrivateKeyPasswordFunc
}

func (o FindSSHPrivateKeysConfig) Validate() error {
	if o.DirPathFn == nil {
		return fmt.Errorf("dir path function is nil")
	}

	return nil
}

// FindSSHPrivateKeys searches for SSH private keys, parses them, and
// returns the corresponding []ssh.Signer using the specified config.
//
// By default the function returns a non-nil error and a zero slice of
// ssh.Signer if any of the keys cannot be parsed.
func FindSSHPrivateKeys(config FindSSHPrivateKeysConfig) ([]ssh.Signer, error) {
	err := config.Validate()
	if err != nil {
		return nil, err
	}

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
		privateKey, isPrivateKey, err := IsPathSSHPrivateKey(SSHPrivateKeyConfig{
			FilePath: filePath,
			PEMLabel: OpenSSHPrivateKeyPEMLabel,
			PassFn:   config.KeysToPassFn[info.Name()],
		})
		if err != nil {
			if config.IgnoreKeyErrFn != nil && config.IgnoreKeyErrFn(err) {
				continue
			}

			return nil, fmt.Errorf("failed to parse private key file '%s' - %w", filePath, err)
		}

		if !isPrivateKey {
			continue
		}

		privateKeys = append(privateKeys, privateKey)
	}

	return privateKeys, nil
}

// SSHPrivateKeyConfig configures an SSH private key parsing function.
type SSHPrivateKeyConfig struct {
	// FilePath is the file to attempt to parse. The usage of this field
	// may vary from function to function. Refer to the calling function's
	// documentation for details..
	FilePath string

	// PEMLabel, if specified, is the PEM label to search for.
	//
	// The purpose of this field is to identify if the current file
	// is a PEM-encoded private key without parsing the entire file.
	// If the first line of the file is not equal to the specified label,
	// then the function will return false and a nil error.
	//
	// A PEM label is the portion of the PEM header that contains the
	// expected data type. For example, the PEM label of the header:
	//	-----BEGIN OPENSSH PRIVATE KEY-----
	//
	// ... would be:
	//	OPENSSH PRIVATE KEY
	//
	// Refer to RFC 7468 for more information:
	// https://tools.ietf.org/html/rfc7468
	PEMLabel string

	// PassFn is an optional GetPrivateKeyPasswordFunc. This function
	// is invoked only if it is non-nil and the current file is an SSH
	// private key that requires a passphrase.
	PassFn GetPrivateKeyPasswordFunc
}

// ParseSSHPrivateKeyFromConfigDirSlice looks up the current user's SSH
// directory and prepends it to the specified file path. In effect, it
// searches the current user's SSH directory for a private key with the
// specified file name. It returns a slice of ssh.Signer containing only
// one key. This is meant to make usage with ssh.PublicKeysCallback
// more straightforward.
func ParseSSHPrivateKeyFromConfigDirSlice(config SSHPrivateKeyConfig) ([]ssh.Signer, error) {
	sshDirPath, err := currentUserSSHDirectory()
	if err != nil {
		return nil, err
	}

	config.FilePath = path.Join(sshDirPath, config.FilePath)

	return ParseSSHPrivateKeyIntoSlice(config)
}

// ParseSSHPrivateKeyIntoSlice wraps ParseSSHPrivateKey, returning a slice of
// ssh.Signer containing only one key. This is meant to make usage with
// ssh.PublicKeysCallback more straightforward.
func ParseSSHPrivateKeyIntoSlice(config SSHPrivateKeyConfig) ([]ssh.Signer, error) {
	signer, err := ParseSSHPrivateKey(config)
	if err != nil {
		return nil, err
	}

	return []ssh.Signer{signer}, nil
}

// ParseSSHPrivateKey wraps IsPathSSHPrivateKey. It requires that the specified
// file be a SSH private key.
func ParseSSHPrivateKey(config SSHPrivateKeyConfig) (ssh.Signer, error) {
	signer, isKey, err := IsPathSSHPrivateKey(config)
	if err != nil {
		return nil, err
	}

	if !isKey {
		return nil, fmt.Errorf("the specified file is not an ssh private key")
	}

	return signer, nil
}

// GetPrivateKeyPasswordFunc returns a password for the current private key.
// An error can also be returned if the password could not be retrieved.
// In such cases, the calling function will honor the failure and return.
type GetPrivateKeyPasswordFunc func() (password string, err error)

// IsPathSSHPrivateKey returns a non-nil ssh.Signer, true, and a nil error if
// the specified file is an SSH private key.
//
// If the file is not an SSH private key, nil ssh.Signer, false, and a nil
// error are returned. If the file is an SSH private key, but could not be
// parsed, then nil ssh.Signer, false, and a non-nil error of type
// *IsSSHPrivateKeyError is returned.
func IsPathSSHPrivateKey(config SSHPrivateKeyConfig) (ssh.Signer, bool, error) {
	f, err := os.Open(config.FilePath)
	if err != nil {
		return nil, false, &IsSSHPrivateKeyError{
			FilePath:              config.FilePath,
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
			Message:         fmt.Sprintf("the file mode must be 0600 - it is %o",
				info.Mode()),
		}
	}

	s := bufio.NewScanner(f)
	s.Scan()
	if len(config.PEMLabel) > 0 && s.Text() != fmt.Sprintf("-----BEGIN %s-----", config.PEMLabel) {
		return nil, false, nil
	}

	buf := bytes.NewBuffer(nil)
	buf.Write(s.Bytes())
	buf.WriteByte('\n')
	for s.Scan() {
		buf.Write(s.Bytes())
		buf.WriteByte('\n')
	}
	if err := s.Err(); err != nil {
		return nil, false, &IsSSHPrivateKeyError{
			FilePath:         f.Name(),
			CurrentFileMode:  info.Mode(),
			CopyContentsFail: true,
			Message:          fmt.Sprintf("failed to read file contents - %s", err),
		}
	}

	signer, err := ssh.ParsePrivateKey(buf.Bytes())
	switch err.(type) {
	case *ssh.PassphraseMissingError:
		if config.PassFn == nil {
			return nil, false, &IsSSHPrivateKeyError{
				FilePath:              f.Name(),
				CurrentFileMode:       info.Mode(),
				RequiresPassphrase:    true,
				OptionalUnderlyingErr: err,
				Message:               err.Error(),
			}
		}

		password, err := config.PassFn()
		if err != nil {
			return nil, false, &IsSSHPrivateKeyError{
				FilePath:              f.Name(),
				CurrentFileMode:       info.Mode(),
				RequiresPassphrase:    true,
				OptionalUnderlyingErr: err,
				Message:               err.Error(),
			}
		}

		signer, err = ssh.ParsePrivateKeyWithPassphrase(buf.Bytes(), []byte(password))
		if err != nil {
			return nil, false, &IsSSHPrivateKeyError{
				FilePath:              f.Name(),
				CurrentFileMode:       info.Mode(),
				RequiresPassphrase:    true,
				OptionalUnderlyingErr: err,
				Message:               err.Error(),
			}
		}

		return signer, true, nil
	case nil:
		return signer, true, nil
	default:
		return nil, false, &IsSSHPrivateKeyError{
			FilePath:              f.Name(),
			CurrentFileMode:       info.Mode(),
			ParseFail:             true,
			OptionalUnderlyingErr: err,
			Message:               fmt.Sprintf("failed to parse file contents as a private key - %s", err),
		}
	}
}
