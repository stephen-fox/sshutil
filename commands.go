package sshutil

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

type CommandOptions struct {
	RequireOutput bool
	StripNewLine  bool
}

type CommandResult struct {
	Output string
	Error  string
}

func (o CommandResult) IsError() bool {
	return len(strings.TrimSpace(o.Error)) > 0
}

func (o CommandResult) IsOutputEmpty() bool {
	return len(strings.TrimSpace(o.Output)) == 0
}

func (o CommandResult) LastString(delimiter string) string {
	if o.IsOutputEmpty() {
		return ""
	}

	parts := strings.Split(o.Output, delimiter)

	return parts[len(parts)-1]
}

func (o CommandResult) FirstString(delimiter string) string {
	if o.IsOutputEmpty() {
		return ""
	}

	parts := strings.Split(o.Output, delimiter)

	return parts[0]
}

// ExecuteCommand executes a command on a remote machine using SSH.
func ExecuteCommand(command string, sshClient *ssh.Client, options CommandOptions) CommandResult {
	s, err := sshClient.NewSession()
	if err != nil {
		return CommandResult{
			Error: err.Error(),
		}
	}
	defer s.Close()

	raw, err := s.CombinedOutput(command)
	out := string(raw)
	if err != nil {
		return CommandResult{
			Error:  err.Error(),
			Output: out,
		}
	}

	if options.RequireOutput && len(strings.TrimSpace(out)) == 0 {
		return CommandResult{
			Error: ErrorCommandDidNotProduceOutput,
		}
	}

	if options.StripNewLine {
		out = strings.TrimSuffix(out, "\n")
	}

	return CommandResult{
		Output: out,
	}
}
