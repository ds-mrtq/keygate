package envname

import "testing"

func TestCheckBlocklist(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "LD_PRELOAD", wantErr: true},
		{name: "LD_LIBRARY_PATH", wantErr: true},
		{name: "LD_AUDIT", wantErr: true},
		{name: "LD_DEBUG", wantErr: true},
		{name: "LD_DEBUG_OUTPUT", wantErr: true},
		{name: "LD_PROFILE", wantErr: true},
		{name: "LD_ORIGIN_PATH", wantErr: true},
		{name: "LD_", wantErr: true},
		{name: "LD_FUTURE_OPTION", wantErr: true},
		{name: "DYLD_INSERT_LIBRARIES", wantErr: true},
		{name: "DYLD_LIBRARY_PATH", wantErr: true},
		{name: "DYLD_FRAMEWORK_PATH", wantErr: true},
		{name: "DYLD_FALLBACK_LIBRARY_PATH", wantErr: true},
		{name: "DYLD_FALLBACK_FRAMEWORK_PATH", wantErr: true},
		{name: "DYLD_ROOT_PATH", wantErr: true},
		{name: "DYLD_IMAGE_SUFFIX", wantErr: true},
		{name: "DYLD_", wantErr: true},
		{name: "DYLD_FUTURE_OPTION", wantErr: true},
		{name: "ld_preload", wantErr: true},
		{name: "Ld_Preload", wantErr: true},
		{name: "ld_library_path", wantErr: true},
		{name: "dyld_insert_libraries", wantErr: true},
		{name: "DyLd_Library_Path", wantErr: true},
		{name: "PATH", wantErr: true},
		{name: "HOME", wantErr: true},
		{name: "path", wantErr: true},
		{name: "Home", wantErr: true},
		{name: "API_TOKEN"},
		{name: "api_token"},
		{name: "_TOKEN2"},
		{name: "KG_LD_PRELOAD"},
		{name: "MY_LD_LIBRARY_PATH"},
		{name: "BUILD_TOKEN"},
		{name: "KG_DYLD_INSERT_LIBRARIES"},
		{name: "LD"},
		{name: "DYLD"},
		{name: "LDLIBRARY_PATH"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Check(tt.name); (err != nil) != tt.wantErr {
				t.Errorf("Check(%q) = %v; want error: %t", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestCheckInvalidNames(t *testing.T) {
	for _, name := range []string{
		"", "1TOKEN",
		" LD_PRELOAD", "LD_PRELOAD ", "\tLD_PRELOAD", "LD_PRELOAD\t",
		"LD_ PRELOAD", "LD_\tPRELOAD",
		" DYLD_INSERT_LIBRARIES", "DYLD_INSERT_LIBRARIES ",
		"\tDYLD_INSERT_LIBRARIES", "DYLD_INSERT_LIBRARIES\t",
		"DYLD_INSERT LIBRARIES", "DYLD_INSERT\tLIBRARIES",
		" API_TOKEN", "API_TOKEN ", "\tAPI_TOKEN", "API_TOKEN\t",
		"API TOKEN", "API\tTOKEN", "API_TOKEN\n", "API_TOKEN\r",
		"LD_PRELOAD=fake", "DYLD_INSERT_LIBRARIES=fake", "API_TOKEN=fake", "=LD_PRELOAD",
		"LD_PRELOAD\x00", "DYLD_INSERT_LIBRARIES\x00", "API\x00TOKEN", "\x00API_TOKEN",
	} {
		t.Run(name, func(t *testing.T) {
			if err := Check(name); err == nil {
				t.Errorf("Check(%q) = nil; want invalid-name error", name)
			}
		})
	}
}
