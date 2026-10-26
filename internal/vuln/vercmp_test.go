package vuln

import "testing"

func TestVercmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0-1", "1.0-1", 0},
		{"1.0-1", "1.0-2", -1},
		{"1.0.1-1", "1.0-1", 1},
		{"1:1.0-1", "2.0-1", 1},
		{"9.0.1224-1", "9.0.1225-1", -1},
		{"1.0a-1", "1.0-1", -1},
		{"1.0-1", "1.0", 0},
		{"3.0.13-1", "3.0.2-1", 1},
		{"2.40-2", "2.40.1-1", -1},
	}
	for _, c := range cases {
		if got := Vercmp(c.a, c.b); got != c.want {
			t.Errorf("Vercmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
