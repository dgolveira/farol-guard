package keys

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoPredictableRandomness(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".cache" || d.Name() == ".git" || d.Name() == "dist") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if p := strings.Trim(imp.Path.Value, `"`); p == "math/rand" || p == "math/rand/v2" {
				t.Errorf("%s imports %s: key material and secrets must only use crypto/rand", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedKeysAreUnique(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		k, err := Generate("k"+string(rune('a'+i)), "test", nil)
		if err != nil {
			t.Fatal(err)
		}
		if seen[k.Fingerprint] {
			t.Fatalf("duplicate key generated: %s", k.Fingerprint)
		}
		seen[k.Fingerprint] = true
	}
}

func TestAppKeyLineIsRestricted(t *testing.T) {
	app := &Key{Name: AppKeyName, PublicLine: "ssh-ed25519 AAAA test"}
	if got := AuthorizedLine(app, []string{"203.0.113.7"}); got != `restrict,from="203.0.113.7" ssh-ed25519 AAAA test` {
		t.Fatalf("unexpected app key line: %s", got)
	}
	user := &Key{Name: "team-ops", PublicLine: "ssh-ed25519 AAAA test"}
	if got := AuthorizedLine(user, nil); got != "ssh-ed25519 AAAA test" {
		t.Fatalf("personal keys must not be restricted: %s", got)
	}
}
