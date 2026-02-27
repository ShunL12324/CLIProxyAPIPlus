package executor

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// userIDPattern matches Claude Code format: user_[64-hex]_account_[uuid]_session_[uuid]
var userIDPattern = regexp.MustCompile(`^user_[a-fA-F0-9]{64}_account_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_session_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// userIDBasePattern matches the fixed part: user_[64-hex]_account_[uuid]
// Used to extract the base from fixed-user-id config and append a fresh session UUID.
var userIDBasePattern = regexp.MustCompile(`^(user_[a-fA-F0-9]{64}_account_[0-9a-f-]+)_session_`)

// fixedSessionUUID caches the session UUID for the lifetime of the process,
// mimicking real Claude Code which generates one session UUID per CLI invocation.
var (
	fixedSessionUUID     string
	fixedSessionUUIDOnce sync.Once
)

func getFixedSessionUUID() string {
	fixedSessionUUIDOnce.Do(func() {
		fixedSessionUUID = uuid.New().String()
	})
	return fixedSessionUUID
}

// generateFakeUserID generates a fake user ID in Claude Code format.
// Format: user_[64-hex-chars]_account_[UUID-v4]_session_[UUID-v4]
func generateFakeUserID() string {
	hexBytes := make([]byte, 32)
	_, _ = rand.Read(hexBytes)
	hexPart := hex.EncodeToString(hexBytes)
	accountUUID := uuid.New().String()
	sessionUUID := uuid.New().String()
	return "user_" + hexPart + "_account_" + accountUUID + "_session_" + sessionUUID
}

// isValidUserID checks if a user ID matches Claude Code format.
func isValidUserID(userID string) bool {
	return userIDPattern.MatchString(userID)
}

// injectFixedUserID injects a fixed user ID from config into the payload.
// The session UUID is generated once per process lifetime, mimicking real Claude Code
// which generates one session UUID per CLI invocation.
func injectFixedUserID(payload []byte, fixedUserID string) []byte {
	finalID := fixedUserID
	if matches := userIDBasePattern.FindStringSubmatch(fixedUserID); len(matches) > 1 {
		finalID = matches[1] + "_session_" + getFixedSessionUUID()
	}
	payload, _ = sjson.SetBytes(payload, "metadata.user_id", finalID)
	return payload
}

// injectBillingHeaderBlock injects the x-anthropic-billing-header as system prompt block 0.
// Real Claude Code sends this as the first system block with no cache_control.
func injectBillingHeaderBlock(payload []byte, billingHeader string) []byte {
	system := gjson.GetBytes(payload, "system")
	if !system.Exists() || !system.IsArray() {
		return payload
	}

	// Check if billing header block already exists
	first := gjson.GetBytes(payload, "system.0.text")
	if first.Exists() && strings.HasPrefix(first.String(), "x-anthropic-billing-header:") {
		return payload
	}

	// Build new block and prepend to system array
	billingBlock := map[string]string{
		"type": "text",
		"text": billingHeader,
	}

	// Get existing blocks
	var blocks []interface{}
	blocks = append(blocks, billingBlock)
	system.ForEach(func(_, value gjson.Result) bool {
		var block map[string]interface{}
		if err := json.Unmarshal([]byte(value.Raw), &block); err == nil {
			blocks = append(blocks, block)
		}
		return true
	})

	payload, _ = sjson.SetBytes(payload, "system", blocks)
	return payload
}

// shouldCloak determines if request should be cloaked based on config and client User-Agent.
// Returns true if cloaking should be applied.
func shouldCloak(cloakMode string, userAgent string) bool {
	switch strings.ToLower(cloakMode) {
	case "always":
		return true
	case "never":
		return false
	default: // "auto" or empty
		// If client is Claude Code, don't cloak
		return !strings.HasPrefix(userAgent, "claude-cli")
	}
}

// isClaudeCodeClient checks if the User-Agent indicates a Claude Code client.
func isClaudeCodeClient(userAgent string) bool {
	return strings.HasPrefix(userAgent, "claude-cli")
}
