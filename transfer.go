package sshutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type TransferProgress struct {
	LocalFileSize  int64
	RemoteFileSize int64
	Percent        int
}

type writerWrapper struct {
	progress   chan TransferProgress
	ioWriter   io.Writer
	written    int64
	sourceSize int64
	isToRemote bool
}

func (o *writerWrapper) Write(p []byte) (n int, err error) {
	n, err = o.ioWriter.Write(p)

	if o.progress != nil && o.sourceSize != 0 && n != 0 {
		o.written = o.written + int64(n)

		tp := TransferProgress{
			LocalFileSize:  o.written,
			RemoteFileSize: o.sourceSize,
			Percent:        int((float64(o.written) / float64(o.sourceSize)) * 100),
		}

		if o.isToRemote {
			tp.LocalFileSize = o.sourceSize
			tp.RemoteFileSize = o.written
		}

		o.progress <- tp
	}

	return n, err
}

type UploadOptions struct {
	Cancel   chan  bool
	Progress chan  TransferProgress
	Timeout  time.Duration
}

type uploadChannels struct {
	Result chan error
	Stop   chan struct{}
}

func (o uploadChannels) waitForCancel(onCancel chan bool) {
	select {
	case cancel := <-onCancel:
		if cancel {
			o.Result <- errors.New(ErrorUploadCanceled)
		}
	case <-o.Stop:
	}
}

func (o uploadChannels) waitForTimeout(timeout time.Duration) {
	ticker := time.NewTicker(timeout)

	select {
	case <-ticker.C:
		o.Result <- errors.New(ErrorUploadTimeoutReached)
	case <-o.Stop:
	}
}

func remoteWriter(ioWriter io.Writer, progress chan TransferProgress, sourceSize int64) io.Writer {
	return &writerWrapper{
		progress:   progress,
		ioWriter:   ioWriter,
		sourceSize: sourceSize,
		isToRemote: true,
	}
}

// UploadFileUsingSftp uploads a file using SFTP (SSH File Transfer Protocol).
// The resulting file name is determined by the value of the destination file
// path. I.e., specifying a destination of '/root/my-cool-file.txt' results in
// the file being named 'my-cool-file.txt' located in '/root'. Be aware that
// the '~' character is not supported. If a timeout occurs, then
// ErrorUploadTimeoutReached is returned.
func UploadFileUsingSftp(localFilePath string, destinationFilePath string, sshClient *ssh.Client, options UploadOptions) error {
	local, err := os.Open(localFilePath)
	if err != nil {
		return err
	}

	info, err := local.Stat()
	if err != nil {
		return err
	}

	localSize := info.Size()

	uc := uploadChannels{
		Stop:   make(chan struct{}),
		Result: make(chan error),
	}
	defer close(uc.Stop)

	if options.Cancel != nil {
		go uc.waitForCancel(options.Cancel)
	}

	if options.Timeout > 0 {
		go uc.waitForTimeout(options.Timeout)
	}

	go func() {
		sftpClient, err := sftp.NewClient(sshClient)
		if err != nil {
			uc.Result <- err
			return
		}

		go func() {
			select {
			case <-uc.Stop:
				sftpClient.Close()
			}
		}()

		remote, err := sftpClient.Create(destinationFilePath)
		if err != nil {
			uc.Result <- err
			return
		}

		err = remote.Chmod(info.Mode())
		if err != nil {
			uc.Result <- err
			return
		}

		_, err = io.Copy(remoteWriter(remote, options.Progress, localSize), local)
		uc.Result <- err
	}()

	return <- uc.Result
}

// UploadFileUsingScp uploads a file using SCP (Secure Copy Protocol). The
// resulting file name is determined by the value of the destination file path.
// I.e., specifying a destination of '/root/my-cool-file.txt' results in the
// file being named 'my-cool-file.txt' located in '/root'. Be aware that the
// '~' character is not supported. If a timeout occurs, then
// ErrorUploadTimeoutReached is returned.
func UploadFileUsingScp(localFilePath string, destinationFilePath string, sshClient *ssh.Client, options UploadOptions) error {
	local, err := os.Open(localFilePath)
	if err != nil {
		return err
	}

	info, err := local.Stat()
	if err != nil {
		return err
	}

	localSize := info.Size()

	uc := uploadChannels{
		Stop:   make(chan struct{}),
		Result: make(chan error),
	}
	defer close(uc.Stop)

	if options.Cancel != nil {
		go uc.waitForCancel(options.Cancel)
	}

	if options.Timeout > 0 {
		go uc.waitForTimeout(options.Timeout)
	}

	go func() {
		session, err := sshClient.NewSession()
		if err != nil {
			uc.Result <- err
			return
		}

		go func() {
			select {
			case <-uc.Stop:
				session.Close()
			}
		}()

		stdin, err := session.StdinPipe()
		if err != nil {
			uc.Result <- err
			return
		}

		go func() {
			select {
			case <-uc.Stop:
				stdin.Close()
			}
		}()

		err = session.Start("scp -t '" + destinationFilePath + "'")
		if err != nil {
			uc.Result <- err
			return
		}

		go func() {
			uc.Result <- session.Wait()
		}()

		_, err = fmt.Fprintf(stdin, "C%#o %d %s\n", info.Mode(), localSize, path.Base(destinationFilePath))
		if err != nil {
			uc.Result <- err
			return
		}

		_, err = io.Copy(remoteWriter(stdin, options.Progress, localSize), local)
		if err != nil {
			err = fmt.Errorf("failed to write to remote file - %s", err.Error())
		}

		uc.Result <- err
	}()

	return <- uc.Result
}
