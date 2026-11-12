package importer

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDotenvAnomaliesCRLFBlank(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(p, []byte("A=1\r\n\r\n  \t\r\n# c\r\nbad line\r\nB=2\r\nC: x\r\n"), 0o600)
	got, err := DotenvAnomalies(p)
	if err != nil || !reflect.DeepEqual(got, []int{5, 7}) {
		t.Fatalf("%v %v", got, err)
	}
}
