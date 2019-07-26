package main

import (
	"io"
	"log"
	"os"
	"os/exec"
)

func execute(command string, arg ...string) error {
	cmd := exec.Command(command, arg...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	io.Copy(os.Stderr, stderr)
	io.Copy(os.Stdout, stdout)

	if err := cmd.Wait(); err != nil {
		return err
	}
	return nil
}

func prepare() error {
	err := execute("docker-compose", "build")
	if err != nil {
		return err
	}

	err = execute("docker-compose", "pull")
	if err != nil {
		return err
	}

	err = execute("docker-compose", "up", "-d")
	if err != nil {
		return err
	}
	return nil
}

func main() {
	err := prepare()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
