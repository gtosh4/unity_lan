package openurl

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sync"
)

var (
	isWSL      bool
	isWSLOnce  sync.Once
	msKernelRE = regexp.MustCompile(`microsoft-standard-WSL2`)
)

func Open(ctx context.Context, url string) error {
	isWSLOnce.Do(setIsWSL)

	if !isWSL {
		return exec.Command("xdg-open", url).Start()
	} else {
		return exec.Command("wslview", url).Start()
	}
}

func setIsWSL() {
	cmd := exec.Command("uname", "-a")
	buf := new(bytes.Buffer)
	cmd.Stdout = buf

	err := cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not determine kernel version: %v\n", err)
		return
	}

	if msKernelRE.Match(buf.Bytes()) {
		isWSL = true
	}
}
