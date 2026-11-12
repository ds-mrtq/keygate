// Helper child for the e2e test: prints the named env var and its base64 form.
package main

import (
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	v := os.Getenv(os.Args[1])
	fmt.Println("plain=" + v)
	fmt.Println("b64=" + base64.StdEncoding.EncodeToString([]byte(v)))
	fmt.Fprintln(os.Stderr, "err="+v)
}
