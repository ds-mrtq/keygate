package relay

import (
	"strings"
	"testing"
)

func TestDeviceFallbacksAndBrowserPrecedence(t *testing.T) {
	for _, tc := range []struct{ ua, want string }{
		{"", ""},
		{"iPad Safari/604.1", "iPad · Safari"},
		{"Android Chrome/140 Safari/537", "Android · Chrome"},
		{"iPhone CriOS/140 Safari/604", "iPhone · Chrome"},
		{"iPhone FxiOS/140 Safari/604", "iPhone · Firefox"},
		{"Linux Firefox/140", "Linux · Firefox"},
		{"Macintosh", "Mac"},
		{"Safari/604", "Safari"},
		{"custom agent", "custom agent"},
		{strings.Repeat("x", 40), strings.Repeat("x", 40)},
		{strings.Repeat("x", 41), strings.Repeat("x", 40) + "…"},
	} {
		t.Run(tc.ua, func(t *testing.T) {
			if got := Device(tc.ua); got != tc.want {
				t.Fatalf("Device(%q)=%q, want %q", tc.ua, got, tc.want)
			}
		})
	}
}

func TestOriginSummary(t *testing.T) {
	for _, tc := range []struct {
		origin Origin
		want   string
	}{
		{Origin{}, ""},
		{Origin{IP: "192.0.2.1"}, "192.0.2.1"},
		{Origin{City: "Test"}, "Test"},
		{Origin{Country: "US"}, "US"},
		{Origin{Org: "Test network"}, "Test network"},
		{Origin{UA: "Go-http-client/1.1"}, "kg"},
		{Origin{City: "Test", Country: "US"}, "Test, US"},
		{Origin{IP: "192.0.2.1", City: "Test", Country: "US", Org: "Test network", UA: "Windows Chrome/140"}, "192.0.2.1 · Test, US · Test network · Windows · Chrome"},
	} {
		if got := tc.origin.Summary(); got != tc.want {
			t.Errorf("%+v.Summary()=%q, want %q", tc.origin, got, tc.want)
		}
	}
}
