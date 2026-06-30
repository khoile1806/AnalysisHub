//go:build windows

package executor

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type jobobjectCpuRateControlInformation struct {
	ControlFlags uint32
	CpuRate      uint32
}

const (
	jobObjectCpuRateControlInformation = 15
	jobObjectCpuRateControlEnable      = 0x1
	jobObjectCpuRateControlHardCap     = 0x4
)

// createLimitedJob creates a Windows job object used to (a) optionally hard-cap
// CPU% and RAM (MB) for every process placed in it and (b) tie the lifetime of
// the whole process tree to the returned handle (KILL_ON_JOB_CLOSE). Limits and
// tree membership are inherited by every child a member process spawns, so a job
// assigned to the launcher transparently covers powershell and the real tool.
//
// The caller OWNS the returned handle and must keep it open for the tool's
// lifetime, then CloseHandle it. Because of KILL_ON_JOB_CLOSE, closing the last
// handle while the tool is still running terminates the entire tree — that is
// exactly how the agent implements "stop" and guarantees no orphaned children if
// the agent itself dies. A job is created even when no limits are requested, so
// the agent can always terminate the tree atomically.
//
// Note: a process elevated through UAC (Start-Process -Verb RunAs) is created by
// the AppInfo service, not as a child of the launcher, so it BREAKS OUT of this
// job. Resource caps therefore do not apply to tools that self-elevate; this is
// an inherent Windows limitation, not a bug here.
func createLimitedJob(cpuLimitPercent, ramLimitMB int) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}

	var extInfo windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	extInfo.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if ramLimitMB > 0 {
		extInfo.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_MEMORY
		extInfo.JobMemoryLimit = uintptr(ramLimitMB) * 1024 * 1024
	}
	if _, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&extInfo)),
		uint32(unsafe.Sizeof(extInfo)),
	); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject (Extended): %w", err)
	}

	if cpuLimitPercent > 0 {
		// CpuRate is a hard cap expressed in 1/100 of a percent of TOTAL system
		// capacity across all logical processors (50% -> 5000, 100% -> 10000).
		rate := uint32(cpuLimitPercent * 100)
		if rate > 10000 {
			rate = 10000
		}
		cpuInfo := jobobjectCpuRateControlInformation{
			ControlFlags: jobObjectCpuRateControlEnable | jobObjectCpuRateControlHardCap,
			CpuRate:      rate,
		}
		if _, err = windows.SetInformationJobObject(
			job,
			jobObjectCpuRateControlInformation,
			uintptr(unsafe.Pointer(&cpuInfo)),
			uint32(unsafe.Sizeof(cpuInfo)),
		); err != nil {
			windows.CloseHandle(job)
			return 0, fmt.Errorf("SetInformationJobObject (CPU): %w", err)
		}
	}

	return job, nil
}

// assignProcessToJob places an already-created process (ideally still suspended,
// so it has not yet spawned children) into the job. Every process the member
// later creates inherits the job, so the caps and tree-kill cover the whole tree.
func assignProcessToJob(job windows.Handle, pid int) error {
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(ph)
	if err := windows.AssignProcessToJobObject(job, ph); err != nil {
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return nil
}

// resumeProcess resumes every thread of a process created with CREATE_SUSPENDED.
// A freshly created suspended process has exactly one thread; the snapshot walk
// is defensive in case the runtime injected additional threads.
func resumeProcess(pid int) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	resumed := 0
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != uint32(pid) {
			continue
		}
		th, oerr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if oerr != nil {
			continue
		}
		windows.ResumeThread(th)
		windows.CloseHandle(th)
		resumed++
	}
	if resumed == 0 {
		return fmt.Errorf("no threads resumed for pid %d", pid)
	}
	return nil
}
