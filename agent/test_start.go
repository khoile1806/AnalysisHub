package main

import (
	"fmt"
	"os/exec"
)

func main() {
	// Let's test start /wait
	cmd := exec.Command("cmd.exe", "/c", "start", "/wait", "Test Window", "ping.exe", "8.8.8.8", "-n", "3")
	
	fmt.Println("Starting...")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Done")
}
