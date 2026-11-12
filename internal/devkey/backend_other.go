//go:build !windows && !darwin

package devkey

func openNative(home string, opt Options) (Store, error) { return NewFile(home, opt), nil }
