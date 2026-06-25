package discovery

import (
	"os"
	"sort"
	"strings"
)

// .lock excludes .envseal.lock (cmd/init.go's own cross-process init lock,
// created at the project root — a sibling of real .env* files — by every
// `envseal init`): without this, it matches the ".env" prefix below and
// shows up as a bogus, confusing candidate in `import`'s interactive file
// picker for every already-initialized project.
var excludedSuffixes = []string{".vault", ".example", ".sample", ".template", ".keys", ".lock"}

func FindEnvFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, ".env") {
			continue
		}
		if isExcluded(name) {
			continue
		}
		files = append(files, name)
	}

	sort.Strings(files)
	return files, nil
}

func isExcluded(name string) bool {
	for _, suffix := range excludedSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
