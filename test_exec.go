
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

func main() {
	ps1 := "# ForensicHub\r\n& 'notepad.exe' | Out-String -Stream\r\n"
	os.WriteFile("test.ps1", []byte(ps1), 0600)
	
	bat := "@echo off\r\nstart \"Test\" /wait powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"test.ps1\"\r\n"
	os.WriteFile("test.bat", []byte(bat), 0600)
	
	cmd := exec.CommandContext(context.Background(), "cmd.exe", "/c", "test.bat")
	cmd.Run()
	fmt.Println("Done")
}

