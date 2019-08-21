package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/stephen-fox/sshutil"
	"github.com/stephen-fox/userutil"
	"golang.org/x/crypto/ssh"
)

var (
	address      = flag.String("a", "", "The address to connect to")
	port         = flag.Int("i", 22, "The SSH server's port")
	uploadSftp   = flag.String("sftp", "", "Upload a file using SFTP")
	uploadScp    = flag.String("scp", "", "Upload a file using SCP")
	fileDestPath = flag.String("r", "", "Tha path to save the file")
)

func main() {
	flag.Parse()

	if len(os.Args) <= 1 {
		flag.PrintDefaults()
		os.Exit(0)
	}

	username, err := userutil.GetUserInput("Username", userutil.PromptOptions{
		ShouldHideInput: true,
	})

	password, err := userutil.GetUserInput("Password", userutil.PromptOptions{
		ShouldHideInput: true,
	})
	if err != nil {
		log.Fatal(err.Error())
	}

	clientConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: sshutil.ImitateSSHClientHostKeyCallBack(func(info sshutil.SSHHostKeyPromptInfo) bool {
			b, _ := userutil.GetYesOrNoUserInput(info.UserFacingPrompt, userutil.PromptOptions{})
			return b
		}),
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", *address, *port), clientConfig)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer client.Close()

	fmt.Println(string(client.ServerVersion()))

	if len(strings.TrimSpace(*uploadSftp)) > 0 || len(strings.TrimSpace(*uploadScp)) > 0 {
		if len(strings.TrimSpace(*fileDestPath)) == 0 {
			log.Fatal("Please specify a file destination path")
		}

		uo := sshutil.UploadOptions{
			Progress: make(chan sshutil.TransferProgress),
			Timeout:  1 * time.Minute,
		}

		go func() {
			for p := range uo.Progress {
				fmt.Print("\r" + strconv.FormatInt(p.RemoteFileSize, 10) + "/" +
					strconv.FormatInt(p.LocalFileSize, 10) +
						" bytes - " + strconv.Itoa(p.Percent) + "%")
			}
		}()

		var localFilePath string
		var uploadFunc func(string, string, *ssh.Client, sshutil.UploadOptions) error

		if len(strings.TrimSpace(*uploadSftp)) > 0 {
			localFilePath = *uploadSftp
			uploadFunc = sshutil.UploadFileUsingSftp
		} else {
			localFilePath = *uploadScp
			uploadFunc = sshutil.UploadFileUsingScp
		}

		err = uploadFunc(localFilePath, *fileDestPath, client, uo)
		if err != nil {
			fmt.Println()
			log.Fatal(err.Error())
		}
	}
}