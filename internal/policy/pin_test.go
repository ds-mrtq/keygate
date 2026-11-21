package policy

import "testing"

func TestReplaceScalarPreservesBoundaries(t *testing.T) {
	const raw = "python path:/scripts/job.py"
	const pinned = "python path:/scripts/job.py sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	for _, tc := range []struct {
		name, input, want string
		count             int
	}{
		{"quoted flow items", `["` + raw + `", '` + raw + `']`, `["` + pinned + `", '` + pinned + `']`, 2},
		{"bare flow items", "[" + raw + "," + raw + "]", "[" + pinned + "," + pinned + "]", 2},
		{"flow whitespace", "[ " + raw + " ,\t" + raw + " ]", "[ " + pinned + " ,\t" + pinned + " ]", 2},
		{"block line endings", "  - " + raw + "\r\n  - " + raw + " \t\n  - " + raw, "  - " + pinned + "\r\n  - " + pinned + " \t\n  - " + pinned, 3},
		{"trailing comment", "  - " + raw + " \t# keep this comment", "  - " + pinned + " \t# keep this comment", 1},
		{"longer path", "[" + raw + "w]", "[" + raw + "w]", 0},
		{"longer command", "[" + raw + " --flag, " + raw + "]", "[" + raw + " --flag, " + pinned + "]", 1},
		{"suffix of another item", "[wrapper " + raw + ", " + raw + "]", "[wrapper " + raw + ", " + pinned + "]", 1},
		{"not a list item", raw + "\n", raw + "\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, n := replaceScalar([]byte(tc.input), raw, pinned)
			if string(got) != tc.want || n != tc.count {
				t.Fatalf("replaceScalar = %q (%d replacements), want %q (%d)", got, n, tc.want, tc.count)
			}
		})
	}
}
