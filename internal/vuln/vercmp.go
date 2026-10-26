package vuln

import "strings"

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		si, sj := i, j
		for i < len(a) && !isAlnum(a[i]) {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) {
			j++
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		if i-si != j-sj {
			if i-si < j-sj {
				return -1
			}
			return 1
		}
		s1, s2 := i, j
		numeric := isDigit(a[i])
		if numeric {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlnum(a[i]) && !isDigit(a[i]) {
				i++
			}
			for j < len(b) && isAlnum(b[j]) && !isDigit(b[j]) {
				j++
			}
		}
		x, y := a[s1:i], b[s2:j]
		if y == "" {
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				if len(x) < len(y) {
					return -1
				}
				return 1
			}
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	oneEmpty, twoEmpty := i >= len(a), j >= len(b)
	if oneEmpty && twoEmpty {
		return 0
	}
	if (oneEmpty && !isAlpha(b[j])) || (!oneEmpty && isAlpha(a[i])) {
		return -1
	}
	return 1
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func splitEVR(v string) (epoch, version, release string) {
	epoch = "0"
	if e, rest, ok := strings.Cut(v, ":"); ok && e != "" && strings.Trim(e, "0123456789") == "" {
		epoch, v = e, rest
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func Vercmp(a, b string) int {
	if a == b {
		return 0
	}
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if c := rpmvercmp(ea, eb); c != 0 {
		return c
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	if ra != "" && rb != "" {
		return rpmvercmp(ra, rb)
	}
	return 0
}
