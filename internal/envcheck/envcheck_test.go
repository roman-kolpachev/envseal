package envcheck

import "testing"

func TestIsDangerous(t *testing.T) {
	for _, name := range DangerousVarNames() {
		if !IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = false, want true", name)
		}
	}
}

func TestIsDangerous_CaseInsensitive(t *testing.T) {
	cases := []string{"path", "Path", "ld_preload", "Ld_Preload", "node_options"}
	for _, name := range cases {
		if !IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = false, want true (case-insensitive)", name)
		}
	}
}

func TestIsDangerous_Safe(t *testing.T) {
	safe := []string{
		"DATABASE_URL", "API_KEY", "SECRET_TOKEN", "MY_VAR",
		"APP_PORT", "LOG_LEVEL", "",
	}
	for _, name := range safe {
		if IsDangerous(name) {
			t.Errorf("IsDangerous(%q) = true, want false", name)
		}
	}
}
