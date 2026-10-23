package vuln

import "testing"

func TestCVSS3Score(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L": 5.3,
		"CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L": 4.1,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for vec, want := range cases {
		if got := cvss3Score(vec); got != want {
			t.Errorf("%s: got %.1f want %.1f", vec, got, want)
		}
	}
}
