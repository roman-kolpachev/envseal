//go:build windows

package fileutil

import "errors"

// mkfifo is unsupported on Windows; FIFOs are a Unix concept.
func mkfifo(path string) error {
	return errors.New("mkfifo is not supported on windows")
}
