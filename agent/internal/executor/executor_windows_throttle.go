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

func applyHardLimitsWindows(pid int, cpuLimitPercent int, ramLimitMB int) error {
	if cpuLimitPercent <= 0 && ramLimitMB <= 0 {
		return nil
	}

	jobHandle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("CreateJobObject: %w", err)
	}

	if ramLimitMB > 0 {
		var extInfo windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		extInfo.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_JOB_MEMORY
		extInfo.JobMemoryLimit = uintptr(ramLimitMB) * 1024 * 1024

		_, err = windows.SetInformationJobObject(
			jobHandle,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&extInfo)),
			uint32(unsafe.Sizeof(extInfo)),
		)
		if err != nil {
			windows.CloseHandle(jobHandle)
			return fmt.Errorf("SetInformationJobObject (Memory): %w", err)
		}
	}

	if cpuLimitPercent > 0 {
		var cpuInfo jobobjectCpuRateControlInformation
		cpuInfo.ControlFlags = jobObjectCpuRateControlEnable | jobObjectCpuRateControlHardCap
		cpuInfo.CpuRate = uint32(cpuLimitPercent * 100)

		_, err = windows.SetInformationJobObject(
			jobHandle,
			jobObjectCpuRateControlInformation,
			uintptr(unsafe.Pointer(&cpuInfo)),
			uint32(unsafe.Sizeof(cpuInfo)),
		)
		if err != nil {
			windows.CloseHandle(jobHandle)
			return fmt.Errorf("SetInformationJobObject (CPU): %w", err)
		}
	}

	procHandle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		windows.CloseHandle(jobHandle)
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(procHandle)

	err = windows.AssignProcessToJobObject(jobHandle, procHandle)
	if err != nil {
		windows.CloseHandle(jobHandle)
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}

	// Do NOT CloseHandle(jobHandle) here or the job object is destroyed
	// We want the job object to persist as long as the processes inside it are alive.
	// Wait, if we close the handle, does the Job Object get destroyed if processes are inside it?
	// Actually, a job object is destroyed when its last handle is closed AND all associated processes have exited.
	// Wait, if we close the handle, the job continues to affect the processes that are already assigned to it.
	// So it IS safe to close the handle after assigning the process!
	windows.CloseHandle(jobHandle)

	return nil
}
