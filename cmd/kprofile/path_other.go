//go:build !windows && !js && !plan9

package main

import (
	"errors"
	"os"
)

func localPathRoot(path string) (string, error) {
	if path == "" || path[0] != os.PathSeparator {
		return "", errors.New("absolute path required")
	}
	return string(os.PathSeparator), nil
}
