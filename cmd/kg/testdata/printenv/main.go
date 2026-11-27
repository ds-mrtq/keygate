// Helper child for CLI tests: prints an env var or the test file it names.
package main

import (
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--read-file" {
		b, err := os.ReadFile(os.Getenv(os.Args[2]))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Print(string(b))
		return
	}
	v := os.Getenv(os.Args[1])
	fmt.Println("plain=" + v)
	fmt.Println("b64=" + base64.StdEncoding.EncodeToString([]byte(v)))
	fmt.Fprintln(os.Stderr, "err="+v)
}
