package main

import (
	"fmt"
	"os/exec"
)

func main() {
	cmd := exec.Command("cmd.exe", "/c", "start", "/wait", "MyTitle", "cmd.exe", "/c", "echo Hello World && timeout 3")
	// No CreationFlags, no Stdout!
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Done")
}
