package envname

import "testing"

// Each name makes a common loader, runtime or shell load or run code chosen by
// whoever sets it, so a caller could run its own code inside an allowed program.
func TestCheckBlocksCodeLoadingVariables(t *testing.T) {
	for _, name := range []string{
		// glibc
		"GCONV_PATH", "GLIBC_TUNABLES",
		// interpreters
		"PERLLIB", "LUA_INIT", "LUA_INIT_5_4", "LUA_PATH", "LUA_CPATH", "TCLLIBPATH",
		"PHPRC", "PHP_INI_SCAN_DIR", "R_PROFILE", "R_PROFILE_USER",
		// .NET runtime
		"DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS",
		"COR_ENABLE_PROFILING", "COR_PROFILER", "COR_PROFILER_PATH",
		"CORECLR_ENABLE_PROFILING", "CORECLR_PROFILER", "CORECLR_PROFILER_PATH",
		// shells
		"SHELLOPTS", "BASHOPTS", "PS4", "ZDOTDIR",
		// shared-object plugin paths
		"OPENSSL_CONF", "OPENSSL_ENGINES", "GTK_MODULES", "GTK_PATH", "QT_PLUGIN_PATH", "GIO_MODULE_DIR",
	} {
		t.Run(name, func(t *testing.T) {
			if err := Check(name); err == nil {
				t.Errorf("Check(%q) = nil; want blocked", name)
			}
		})
	}
}
