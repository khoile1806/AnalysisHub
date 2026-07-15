//go:build windows

package monitor

import (
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemory   = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetDiskFreeEx  = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetSystemTimes = kernel32.NewProc("GetSystemTimes")
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX structure.
type memoryStatusEx struct {
	cbSize                  uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

func sampleResource() Resource {
	var r Resource

	// Physical memory.
	var ms memoryStatusEx
	ms.cbSize = uint32(unsafe.Sizeof(ms))
	if ret, _, _ := procGlobalMemory.Call(uintptr(unsafe.Pointer(&ms))); ret != 0 {
		r.MemTotalMB = int64(ms.ullTotalPhys / (1024 * 1024))
		r.MemUsedMB = int64((ms.ullTotalPhys - ms.ullAvailPhys) / (1024 * 1024))
	}

	// System drive usage.
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	if ptr, err := windows.UTF16PtrFromString(drive + `\`); err == nil {
		var freeToCaller, totalBytes, totalFree uint64
		if ret, _, _ := procGetDiskFreeEx.Call(
			uintptr(unsafe.Pointer(ptr)),
			uintptr(unsafe.Pointer(&freeToCaller)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFree)),
		); ret != 0 && totalBytes > 0 {
			const gb = 1024 * 1024 * 1024
			r.DiskTotalGB = float64(totalBytes) / gb
			r.DiskUsedGB = float64(totalBytes-totalFree) / gb
		}
	}

	r.CPUPercent = cpuPercentWindows()
	return r
}

// cpuPercentWindows samples system CPU times twice over a short window and
// returns the busy percentage. GetSystemTimes' kernel figure INCLUDES idle, so
// total = kernel + user and busy = total - idle.
func cpuPercentWindows() float64 {
	idle0, kernel0, user0, ok := systemTimes()
	if !ok {
		return 0
	}
	time.Sleep(250 * time.Millisecond)
	idle1, kernel1, user1, ok := systemTimes()
	if !ok {
		return 0
	}
	total := (kernel1 + user1) - (kernel0 + user0)
	idle := idle1 - idle0
	if total == 0 || idle > total {
		return 0
	}
	return float64(total-idle) / float64(total) * 100
}

func systemTimes() (idle, kernel, user uint64, ok bool) {
	var idleFT, kernelFT, userFT windows.Filetime
	ret, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleFT)),
		uintptr(unsafe.Pointer(&kernelFT)),
		uintptr(unsafe.Pointer(&userFT)),
	)
	if ret == 0 {
		return 0, 0, 0, false
	}
	return ftToUint64(idleFT), ftToUint64(kernelFT), ftToUint64(userFT), true
}

func ftToUint64(ft windows.Filetime) uint64 {
	return uint64(uint32(ft.HighDateTime))<<32 | uint64(ft.LowDateTime)
}
