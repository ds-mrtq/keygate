package fsx

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// ErrLocked is returned when another live process holds the lock.
var ErrLocked = errors.New("keygate: KG_HOME is locked by another process")

var (
	lockMu    sync.Mutex
	lockCount = map[string]int{} // re-entrancy inside one process
)

// Lock takes a cross-process lock by exclusively creating path containing our pid.
// A lock file whose pid is no longer alive is stale and is taken over. Locking the same path
// again inside this process is allowed (reference counted). Call the returned func to release.
func Lock(path string) (func(), error) {
	lockMu.Lock()
	defer lockMu.Unlock()
	if lockCount[path] > 0 {
		lockCount[path]++
		return release(path), nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			lockCount[path] = 1
			return release(path), nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		b, rerr := os.ReadFile(path)
		pid, perr := strconv.Atoi(strings.TrimSpace(string(b)))
		if rerr == nil && perr == nil && pid != os.Getpid() && processAlive(pid) {
			return nil, fmt.Errorf("%w (pid %d)", ErrLocked, pid)
		}
		if rerr == nil && perr != nil && attempt == 0 {
			continue // possibly being written right now; retry once before treating as stale
		}
		os.Remove(path) // stale
	}
	return nil, ErrLocked
}

func release(path string) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			lockMu.Lock()
			defer lockMu.Unlock()
			if lockCount[path]--; lockCount[path] <= 0 {
				delete(lockCount, path)
				os.Remove(path)
			}
		})
	}
}
