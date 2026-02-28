package executor

import (
	"encoding/json"
	"testing"
)

func TestComputeBillingVersionSuffix(t *testing.T) {
	tests := []struct {
		name        string
		userMessage string
		version     string
	}{
		{
			name:        "empty message",
			userMessage: "",
			version:     "2.1.63",
		},
		{
			name:        "short message",
			userMessage: "Hi",
			version:     "2.1.63",
		},
		{
			name:        "normal message",
			userMessage: "Hello, can you help me with my code?",
			version:     "2.1.63",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := buildPayloadWithUserMessage(tt.userMessage)
			suffix := computeBillingVersionSuffix(payload, tt.version)

			if len(suffix) != 3 {
				t.Errorf("expected 3-char hex suffix, got %q (len=%d)", suffix, len(suffix))
			}

			// Verify determinism: same input = same output
			suffix2 := computeBillingVersionSuffix(payload, tt.version)
			if suffix != suffix2 {
				t.Errorf("not deterministic: got %q then %q", suffix, suffix2)
			}
		})
	}
}

func TestComputeBillingVersionSuffix_Determinism(t *testing.T) {
	// Same user message should always produce the same suffix
	payload := buildPayloadWithUserMessage("Please review my pull request")
	version := "2.1.63"

	expected := computeBillingVersionSuffix(payload, version)
	for i := 0; i < 100; i++ {
		got := computeBillingVersionSuffix(payload, version)
		if got != expected {
			t.Fatalf("iteration %d: expected %q, got %q", i, expected, got)
		}
	}
}

func TestComputeBillingVersionSuffix_DifferentInputs(t *testing.T) {
	version := "2.1.63"
	msg1 := buildPayloadWithUserMessage("Hello world, how are you doing today?")
	msg2 := buildPayloadWithUserMessage("Goodbye world, see you later friend!")

	suffix1 := computeBillingVersionSuffix(msg1, version)
	suffix2 := computeBillingVersionSuffix(msg2, version)

	// Different messages should (very likely) produce different suffixes
	// This is probabilistic but with 3 different char positions, collision is unlikely
	if suffix1 == suffix2 {
		t.Logf("warning: different messages produced same suffix %q (possible but unlikely)", suffix1)
	}
}

func TestExtractFirstUserMessageText(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected string
	}{
		{
			name:     "string content",
			payload:  `{"messages":[{"role":"user","content":"hello world"}]}`,
			expected: "hello world",
		},
		{
			name:     "array content with text block",
			payload:  `{"messages":[{"role":"user","content":[{"type":"text","text":"hello from array"}]}]}`,
			expected: "hello from array",
		},
		{
			name:     "skips assistant messages",
			payload:  `{"messages":[{"role":"assistant","content":"I am assistant"},{"role":"user","content":"user message"}]}`,
			expected: "user message",
		},
		{
			name:     "empty messages",
			payload:  `{"messages":[]}`,
			expected: "",
		},
		{
			name:     "no messages field",
			payload:  `{}`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFirstUserMessageText([]byte(tt.payload))
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestInjectBillingHeaderBlock_DynamicSuffix(t *testing.T) {
	// Build a payload with system array and user message
	payload := []byte(`{
		"system": [{"type":"text","text":"You are Claude Code."}],
		"messages": [{"role":"user","content":"Hello, help me with code please!"}]
	}`)

	billingHeader := "x-anthropic-billing-header: cc_version=2.1.63.000; cc_entrypoint=cli; cch=00000;"

	result := injectBillingHeaderBlock(payload, billingHeader)

	// The suffix should be replaced with the computed value, not "000"
	type systemBlock struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type body struct {
		System []systemBlock `json:"system"`
	}
	var b body
	if err := json.Unmarshal(result, &b); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if len(b.System) < 2 {
		t.Fatalf("expected at least 2 system blocks, got %d", len(b.System))
	}

	injected := b.System[0].Text
	if injected == billingHeader {
		t.Error("billing header suffix was not dynamically replaced")
	}

	// Verify the suffix was actually computed (3 hex chars)
	if !ccVersionSuffixPattern.MatchString(injected) {
		t.Errorf("injected header doesn't match expected pattern: %s", injected)
	}

	// Verify it still contains the base parts
	if !contains(injected, "cc_version=2.1.63.") {
		t.Errorf("missing cc_version base in: %s", injected)
	}
	if !contains(injected, "cch=00000") {
		t.Errorf("missing cch=00000 in: %s", injected)
	}
}

func TestInjectBillingHeaderBlock_NoDuplicateInjection(t *testing.T) {
	payload := []byte(`{
		"system": [{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.63.68f; cc_entrypoint=cli; cch=00000;"},{"type":"text","text":"You are Claude."}],
		"messages": [{"role":"user","content":"hi"}]
	}`)

	billingHeader := "x-anthropic-billing-header: cc_version=2.1.63.000; cc_entrypoint=cli; cch=00000;"
	result := injectBillingHeaderBlock(payload, billingHeader)

	// Should not inject again since billing header already exists
	type systemBlock struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type body struct {
		System []systemBlock `json:"system"`
	}
	var b body
	if err := json.Unmarshal(result, &b); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if len(b.System) != 2 {
		t.Errorf("expected 2 system blocks (no duplicate), got %d", len(b.System))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestComputeBillingVersionSuffix_MatchesClaudeCodeJS(t *testing.T) {
	// Expected values computed by running the original Claude Code JS algorithm:
	//   crypto.createHash('sha256').update("59cf53e54c78" + chars + "2.1.63").digest('hex').slice(0,3)
	tests := []struct {
		userMessage    string
		expectedSuffix string
	}{
		{"", "257"},
		{"Hi", "257"},
		{"Hello, can you help me with my code?", "17a"},
		{"Please review my pull request", "4cf"},
		{"Hello world, how are you doing today?", "fda"},
		{"Hello, help me with code please!", "ddd"},
	}

	for _, tt := range tests {
		t.Run(tt.userMessage, func(t *testing.T) {
			payload := buildPayloadWithUserMessage(tt.userMessage)
			got := computeBillingVersionSuffix(payload, "2.1.63")
			if got != tt.expectedSuffix {
				t.Errorf("message %q: expected suffix %q, got %q", tt.userMessage, tt.expectedSuffix, got)
			}
		})
	}
}

func buildPayloadWithUserMessage(msg string) []byte {
	payload := map[string]interface{}{
		"messages": []map[string]interface{}{
			{
				"role":    "user",
				"content": msg,
			},
		},
	}
	data, _ := json.Marshal(payload)
	return data
}
