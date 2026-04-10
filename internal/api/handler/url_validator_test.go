package handler

import "testing"

func TestValidateScanURL(t *testing.T) {
	cases := []struct{
		url     string
		wantErr bool
		desc    string
	}{
		{"https://target.example.com", false, "valid external https"},
		{"http://target.example.com", false, "valid external http"},
		{"https://127.0.0.1/scan", true, "localhost blocked"},
		{"https://localhost/scan", true, "localhost name blocked"},
		{"https://10.0.0.1/scan", true, "RFC1918 10.x blocked"},
		{"https://192.168.1.1/scan", true, "RFC1918 192.168.x blocked"},
		{"https://172.16.0.1/scan", true, "RFC1918 172.16.x blocked"},
		{"https://169.254.169.254/latest/meta-data", true, "AWS metadata blocked"},
		{"https://metadata.google.internal", true, "GCP metadata blocked"},
		{"ftp://target.example.com", true, "non-http scheme blocked"},
		{"", false, "empty URL allowed (optional field)"},
		{"not-a-url", true, "invalid URL blocked"},
	}
	for _, c := range cases {
		err := validateScanURL(c.url)
		gotErr := err != nil
		if gotErr != c.wantErr {
			t.Errorf("%s: url=%q wantErr=%v gotErr=%v err=%v",
				c.desc, c.url, c.wantErr, gotErr, err)
		} else {
			t.Logf("✓ %s", c.desc)
		}
	}
}
