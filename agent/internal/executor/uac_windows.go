package executor

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modshell32         = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteEx = modshell32.NewProc("ShellExecuteExW")
)

const SEE_MASK_NOCLOSEPROCESS = 0x00000040

type SHELLEXECUTEINFO struct {
	CbSize       uint32
	FMask        uint32
	Hwnd         windows.Handle
	LpVerb       *uint16
	LpFile       *uint16
	LpParameters *uint16
	LpDirectory  *uint16
	NShow        int32
	HInstApp     windows.Handle
	LpIDList     uintptr
	LpClass      *uint16
	HkeyClass    windows.Handle
	DwHotKey     uint32
	HIcon        windows.Handle
	HProcess     windows.Handle
}

// IsElevated reports whether the current agent process is already running with
// an elevated (high-integrity) token. When true, admin-requiring scans can run
// in-process directly — no ShellExecuteEx "runas", so no UAC prompt and no
// child process (Windows only shows UAC on a medium→high elevation transition;
// an already-elevated parent spawns elevated children silently anyway).
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// KillProcess terminates the process with the given PID. Requires the agent to
// have rights over the target (admin for other users' / elevated processes).
func KillProcess(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid")
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("terminate process %d: %w", pid, err)
	}
	return nil
}

// RunElevatedAndWait requests UAC elevation for the given executable.
// It waits for the process to complete.
func RunElevatedAndWait(exe string, args string) error {
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	exe16, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	args16, err := windows.UTF16PtrFromString(args)
	if err != nil {
		return err
	}

	var sei SHELLEXECUTEINFO
	sei.CbSize = uint32(unsafe.Sizeof(sei))
	sei.FMask = SEE_MASK_NOCLOSEPROCESS
	sei.Hwnd = 0
	sei.LpVerb = verb
	sei.LpFile = exe16
	sei.LpParameters = args16
	sei.NShow = windows.SW_NORMAL

	ret, _, err := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&sei)))
	if ret == 0 {
		return fmt.Errorf("UAC prompt failed or denied: %v", err)
	}

	if sei.HProcess != 0 {
		defer windows.CloseHandle(sei.HProcess)
		windows.WaitForSingleObject(sei.HProcess, windows.INFINITE)
	}
	return nil
}
