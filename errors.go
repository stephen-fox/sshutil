package sshutil

import "os"

const (
	ErrorCommandDidNotProduceOutput = "the executed command did not produce any output"
	ErrorNoKnownHostsFilePresent    = "the known hosts file does not exist"
	ErrorUnknownHostKey             = "the specified host is not present in the known hosts file"
	ErrorUploadTimeoutReached       = "upload timeout was exceeded"
	ErrorUploadCanceled             = "the upload was canceled"
)

type IsSSHPrivateKeyError struct {
	FilePath              string
	UnableToOpen          bool
	StatFail              bool
	CurrentFileMode       os.FileMode
	BadFileMode           bool
	CopyContentsFail      bool
	ParseFail             bool
	RequiresPassphrase    bool
	OptionalUnderlyingErr error
	Message               string
}

func (o IsSSHPrivateKeyError) Error() string {
	return o.Message
}
