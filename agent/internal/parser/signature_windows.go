//go:build windows

package parser

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Authenticode signature verification — the native equivalent of Sysinternals
// Sigcheck. Checks BOTH the embedded signature (WinVerifyTrust) and security
// catalogs (CryptCATAdmin*), since most Windows system binaries are catalog-
// signed rather than carrying an embedded signature. Reused by Autoruns /
// Process / File forensics to flag unsigned or untrusted binaries.

var (
	wintrustDLL = syscall.NewLazyDLL("wintrust.dll")

	procWinVerifyTrust                      = wintrustDLL.NewProc("WinVerifyTrust")
	procCryptCATAdminAcquireContext         = wintrustDLL.NewProc("CryptCATAdminAcquireContext")
	procCryptCATAdminReleaseContext         = wintrustDLL.NewProc("CryptCATAdminReleaseContext")
	procCryptCATAdminCalcHashFromFileHandle = wintrustDLL.NewProc("CryptCATAdminCalcHashFromFileHandle")
	procCryptCATAdminEnumCatalogFromHash    = wintrustDLL.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATAdminReleaseCatalogContext  = wintrustDLL.NewProc("CryptCATAdminReleaseCatalogContext")
)

// WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11D0-8CC2-00C04FC295EE}
var wintrustActionVerifyV2 = windows.GUID{
	Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  uintptr
	hFile          uintptr
	pgKnownSubject uintptr
}

type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	fileInfo            uintptr
	dwStateAction       uint32
	hWVTStateData       uintptr
	pwszURLReference    uintptr
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

const (
	wtdUINone            = 2
	wtdRevokeNone        = 0
	wtdChoiceFile        = 1
	wtdStateActionIgnore = 0
	wtdSaferFlag         = 0x100

	trustENoSignature = 0x800B0100
)

// fileSignatureStatus returns "Signed", "Unsigned", "Untrusted" or "" (path
// missing). Revocation checks are disabled so it stays fast and offline.
func fileSignatureStatus(path string) string {
	if path == "" {
		return ""
	}
	switch embeddedSignatureStatus(path) {
	case "Signed":
		return "Signed"
	case "Untrusted":
		return "Untrusted"
	}
	// No (valid) embedded signature — most OS binaries are catalog-signed.
	if catalogSigned(path) {
		return "Signed"
	}
	return "Unsigned"
}

// embeddedSignatureStatus verifies an embedded Authenticode signature.
func embeddedSignatureStatus(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	fi := wintrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(wintrustFileInfo{})),
		pcwszFilePath: uintptr(unsafe.Pointer(p)),
	}
	wd := wintrustData{
		cbStruct:            uint32(unsafe.Sizeof(wintrustData{})),
		dwUIChoice:          wtdUINone,
		fdwRevocationChecks: wtdRevokeNone,
		dwUnionChoice:       wtdChoiceFile,
		fileInfo:            uintptr(unsafe.Pointer(&fi)),
		dwStateAction:       wtdStateActionIgnore,
		dwProvFlags:         wtdSaferFlag,
	}
	ret, _, _ := procWinVerifyTrust.Call(0,
		uintptr(unsafe.Pointer(&wintrustActionVerifyV2)),
		uintptr(unsafe.Pointer(&wd)))
	switch uint32(ret) {
	case 0:
		return "Signed"
	case trustENoSignature:
		return "Unsigned"
	default:
		return "Untrusted"
	}
}

// catalogSigned reports whether the file's hash is present in a trusted Windows
// security catalog (how Microsoft signs most OS binaries).
func catalogSigned(path string) bool {
	var hCatAdmin uintptr
	r, _, _ := procCryptCATAdminAcquireContext.Call(uintptr(unsafe.Pointer(&hCatAdmin)), 0, 0)
	if r == 0 || hCatAdmin == 0 {
		return false
	}
	defer procCryptCATAdminReleaseContext.Call(hCatAdmin, 0)

	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)

	var cb uint32
	procCryptCATAdminCalcHashFromFileHandle.Call(uintptr(h), uintptr(unsafe.Pointer(&cb)), 0, 0)
	if cb == 0 {
		return false
	}
	hash := make([]byte, cb)
	r, _, _ = procCryptCATAdminCalcHashFromFileHandle.Call(uintptr(h),
		uintptr(unsafe.Pointer(&cb)), uintptr(unsafe.Pointer(&hash[0])), 0)
	if r == 0 {
		return false
	}
	hCatInfo, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(hCatAdmin,
		uintptr(unsafe.Pointer(&hash[0])), uintptr(cb), 0, 0)
	if hCatInfo != 0 {
		procCryptCATAdminReleaseCatalogContext.Call(hCatAdmin, hCatInfo, 0)
		return true
	}
	return false
}
