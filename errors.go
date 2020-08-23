package sshutil

import "os"

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
