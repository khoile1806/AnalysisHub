package main
import (
	"fmt"
	"golang.org/x/sys/windows"
)
func main() {
	fmt.Println(windows.JOB_OBJECT_LIMIT_JOB_MEMORY)
}
