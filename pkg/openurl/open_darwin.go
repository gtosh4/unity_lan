package openurl

import (
	"context"
	"os/exec"
)

func Open(ctx context.Context, url string) error {
	return exec.Command("open", url).Start()
}
