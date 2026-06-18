package main

import (
	"fmt"
	"os"
)

func main() {
	searchPaths := []string{
		"docs/playbooks",
		"../docs/playbooks",
		"../../docs/playbooks",
	}

	for _, p := range searchPaths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			fmt.Println("Found playbooks at:", p)
			return
		}
	}
	fmt.Println("Playbooks directory not found")
}
