package relay

import "strings"

// Device names a User-Agent coarsely ("iPhone · Safari", "Windows · Chrome", "kg").
func Device(ua string) string {
	if ua == "" {
		return ""
	}
	if strings.HasPrefix(ua, "Go-http-client") {
		return "kg"
	}
	os := ""
	for _, p := range [][2]string{{"iPhone", "iPhone"}, {"iPad", "iPad"}, {"Android", "Android"}, {"Windows", "Windows"}, {"Macintosh", "Mac"}, {"Linux", "Linux"}} {
		if strings.Contains(ua, p[0]) {
			os = p[1]
			break
		}
	}
	br := ""
	for _, p := range [][2]string{{"Edg", "Edge"}, {"CriOS", "Chrome"}, {"FxiOS", "Firefox"}, {"Firefox/", "Firefox"}, {"Chrome/", "Chrome"}, {"Safari/", "Safari"}} {
		if strings.Contains(ua, p[0]) {
			br = p[1]
			break
		}
	}
	switch {
	case os != "" && br != "":
		return os + " · " + br
	case os != "":
		return os
	case br != "":
		return br
	}
	if len(ua) > 40 {
		ua = ua[:40] + "…"
	}
	return ua
}

// Summary is the one-line display text: "IP · city, CC · network · device" ("" when empty).
func (o Origin) Summary() string {
	place := o.City
	if o.Country != "" {
		if place != "" {
			place += ", "
		}
		place += o.Country
	}
	var parts []string
	for _, p := range []string{o.IP, place, o.Org, Device(o.UA)} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, " · ")
}
