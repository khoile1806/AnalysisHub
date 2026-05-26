//go:build !windows

package executor

import "syscall"

func getSysProcAttr() *syscall.SysProcAttr {
	return nil
}
