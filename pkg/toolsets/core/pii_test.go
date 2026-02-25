package core_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/containers/kubernetes-mcp-server/pkg/toolsets/core"
)

// rep returns '*' repeated to match the rune length of s, mirroring MaskPII's behaviour.
func rep(s string) string {
	return strings.Repeat("*", utf8.RuneCountInString(s))
}

func TestMaskPII(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// ── Taiwan National ID ───────────────────────────────────────
		{
			name:  "Taiwan ID masked",
			input: "ID: A123456789",
			want:  "ID: " + rep("A123456789"), // 10 → **********
		},
		{
			name:  "Taiwan ID female masked",
			input: "身份證: K299887766",
			want:  "身份證: " + rep("K299887766"), // 10 → **********
		},

		// ── Email ────────────────────────────────────────────────────
		{
			name:  "email masked",
			input: "Email: user@example.com",
			want:  "Email: " + rep("user@example.com"), // 16 → ****************
		},
		{
			name:  "email with subdomain masked",
			input: "Addr: john.doe+tag@mail.company.org",
			want:  "Addr: " + rep("john.doe+tag@mail.company.org"), // 29 → *****************************
		},

		// ── Mobile phone ─────────────────────────────────────────────
		{
			name:  "mobile phone without separator masked",
			input: "Phone: 0912345678",
			want:  "Phone: " + rep("0912345678"), // 10 → **********
		},
		{
			name:  "mobile phone with dashes masked",
			input: "Phone: 0912-345-678",
			want:  "Phone: " + rep("0912-345-678"), // 12 → ************
		},

		// ── Landline ─────────────────────────────────────────────────
		{
			name:  "landline with parens masked",
			input: "Tel: (02)1234-5678",
			want:  "Tel: " + rep("(02)1234-5678"), // 13 → *************
		},
		{
			name:  "landline with dashes masked",
			input: "Tel: 04-7654321",
			want:  "Tel: " + rep("04-7654321"), // 10 → **********
		},

		// ── Chinese Names (keyword-anchored) ─────────────────────────
		{
			name:  "two-char name after 姓名 keyword",
			input: "姓名：歐美",
			want:  "姓名：" + rep("歐美"), // keyword preserved, name 2 → **
		},
		{
			name:  "three-char name after 申請人 keyword",
			input: "申請人：歐美麗",
			want:  "申請人：" + rep("歐美麗"), // keyword preserved, name 3 → ***
		},
		{
			name:  "non-keyword CJK text NOT masked",
			input: "台北市中正區忠孝東路",
			want:  "台北市中正區忠孝東路",
		},

		// ── Address numbers ──────────────────────────────────────────
		{
			name:  "address 號 and 樓 masked, street name preserved",
			input: "地址：忠孝東路3號5樓",
			want:  "地址：忠孝東路" + rep("3號") + rep("5樓"), // 2+2=4 → ****
		},

		// ── JWT token ────────────────────────────────────────────────
		{
			name: "JWT token masked",
			input: "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123",
			want:  "token=" + rep("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123"),
		},
		{
			name:  "Bearer token masks whole phrase",
			input: "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.signature",
			want:  "Authorization: " + rep("Bearer eyJhbGciOiJSUzI1NiJ9.payload.signature"),
		},

		// ── No PII ───────────────────────────────────────────────────
		{
			name:  "no PII passes through unchanged",
			input: "Pod started successfully on node worker-1",
			want:  "Pod started successfully on node worker-1",
		},
		{
			name:  "empty string passes through",
			input: "",
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := core.MaskPII(tc.input)
			if got != tc.want {
				t.Errorf("MaskPII(%q)\n  got:  %q\n  want: %q", tc.input, got, tc.want)
			}
		})
	}
}
