package executor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// billingHashSalt is the constant salt used by Claude Code to compute
// the cc_version suffix hash.
const billingHashSalt = "59cf53e54c78"

// userIDPattern matches Claude Code format: user_[64-hex]_account_[uuid]_session_[uuid]
var userIDPattern = regexp.MustCompile(`^user_[a-fA-F0-9]{64}_account_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_session_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// userIDBasePattern matches the fixed part: user_[64-hex]_account_[uuid]
// Used to extract the base from fixed-user-id config and append a fresh session UUID.
var userIDBasePattern = regexp.MustCompile(`^(user_[a-fA-F0-9]{64}_account_[0-9a-f-]+)_session_`)

// userIDAccountPattern matches Claude Code format with account UUID:
// user_[64-hex]_account_[uuid]_session_[uuid-v4]
var userIDAccountPattern = regexp.MustCompile(`^user_[a-fA-F0-9]{64}_account_[0-9a-f-]+_session_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

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
	return userIDPattern.MatchString(userID) || userIDAccountPattern.MatchString(userID)
}

// userIDSessionPattern extracts the session UUID from a user_id string.
var userIDSessionPattern = regexp.MustCompile(`_session_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

// injectFixedUserID injects a fixed user ID from config into the payload.
// The user hash and account UUID come from config; the session UUID is
// passthrough from the client when available, falling back to a process-level
// fixed UUID otherwise.
func injectFixedUserID(payload []byte, fixedUserID string) []byte {
	baseMatch := userIDBasePattern.FindStringSubmatch(fixedUserID)
	if len(baseMatch) <= 1 {
		payload, _ = sjson.SetBytes(payload, "metadata.user_id", fixedUserID)
		return payload
	}
	base := baseMatch[1] // user_{hash}_account_{uuid}

	// Try to passthrough the client's session UUID.
	session := ""
	if current := gjson.GetBytes(payload, "metadata.user_id").String(); current != "" {
		if m := userIDSessionPattern.FindStringSubmatch(current); len(m) > 1 {
			session = m[1]
		}
	}
	if session == "" {
		session = getFixedSessionUUID()
	}

	payload, _ = sjson.SetBytes(payload, "metadata.user_id", base+"_session_"+session)
	return payload
}

func authAccountUUID(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		for _, key := range []string{"account_uuid", "account-uuid", "accountUUID", "organization_uuid", "org_uuid"} {
			if v, ok := auth.Metadata[key].(string); ok {
				u := strings.TrimSpace(v)
				if u != "" {
					return u
				}
			}
		}
	}
	if auth.Attributes != nil {
		for _, key := range []string{"account_uuid", "account-uuid", "accountUUID", "organization_uuid", "org_uuid"} {
			u := strings.TrimSpace(auth.Attributes[key])
			if u != "" {
				return u
			}
		}
	}
	return ""
}

func stableSessionUUIDFromSeed(seed string) string {
	if strings.TrimSpace(seed) == "" {
		return uuid.New().String()
	}
	sum := sha256.Sum256([]byte(seed))
	b := make([]byte, 16)
	copy(b, sum[:16])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return uuid.UUID(b).String()
}

func generateOAuthUserID(apiKey string, accountUUID string) string {
	if accountUUID == "" {
		return generateFakeUserID()
	}
	hashInput := apiKey + "|" + accountUUID
	if strings.TrimSpace(apiKey) == "" {
		hashInput = accountUUID
	}
	sum := sha256.Sum256([]byte(hashInput))
	hexPart := hex.EncodeToString(sum[:])
	session := uuid.New().String()
	return "user_" + hexPart + "_account_" + accountUUID + "_session_" + session
}

func injectOAuthUserID(payload []byte, auth *cliproxyauth.Auth, apiKey string, cacheUserID bool) []byte {
	metadata := gjson.GetBytes(payload, "metadata")
	current := gjson.GetBytes(payload, "metadata.user_id").String()
	if current != "" && isValidUserID(current) {
		return payload
	}

	accountUUID := authAccountUUID(auth)
	if accountUUID == "" {
		return injectFakeUserID(payload, apiKey, cacheUserID)
	}

	baseUserID := generateOAuthUserID(apiKey, accountUUID)
	if cacheUserID {
		keySeed := strings.TrimSpace(apiKey)
		if keySeed == "" && auth != nil {
			keySeed = strings.TrimSpace(auth.ID)
		}
		if keySeed == "" {
			keySeed = accountUUID
		}
		ttlBucket := strconv.FormatInt(time.Now().Unix()/(15*60), 10)
		session := stableSessionUUIDFromSeed(keySeed + "|" + accountUUID + "|" + ttlBucket)
		if matches := userIDBasePattern.FindStringSubmatch(baseUserID); len(matches) > 1 {
			baseUserID = matches[1] + "_session_" + session
		}
	}

	if !metadata.Exists() {
		payload, _ = sjson.SetBytes(payload, "metadata.user_id", baseUserID)
		return payload
	}
	payload, _ = sjson.SetBytes(payload, "metadata.user_id", baseUserID)
	return payload
}

// computeBillingVersionSuffix computes the 3-char hex suffix for cc_version
// using the same algorithm as real Claude Code:
//  1. Extract the first user message text from the conversation
//  2. Take characters at positions 4, 7, 20 (0-indexed), defaulting to "0"
//  3. Compute SHA-256 of: salt + chars + version
//  4. Return first 3 hex characters of the hash
func computeBillingVersionSuffix(payload []byte, version string) string {
	// Extract first user message text from messages array
	firstUserText := extractFirstUserMessageText(payload)

	// Take characters at positions 4, 7, 20
	charAtPos := func(s string, pos int) string {
		if pos < len(s) {
			return string(s[pos])
		}
		return "0"
	}
	chars := charAtPos(firstUserText, 4) + charAtPos(firstUserText, 7) + charAtPos(firstUserText, 20)

	// SHA-256 hash of: salt + chars + version
	input := billingHashSalt + chars + version
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash[:])[:3]
}

// extractFirstUserMessageText extracts the text content from the first user
// message in the messages array, matching Claude Code's behavior.
func extractFirstUserMessageText(payload []byte) string {
	messages := gjson.GetBytes(payload, "messages")
	if !messages.Exists() || !messages.IsArray() {
		return ""
	}

	var firstUserText string
	messages.ForEach(func(_, msg gjson.Result) bool {
		if msg.Get("role").String() != "user" {
			return true // continue
		}
		content := msg.Get("content")
		if content.Type == gjson.String {
			firstUserText = content.String()
			return false // break
		}
		if content.IsArray() {
			content.ForEach(func(_, block gjson.Result) bool {
				if block.Get("type").String() == "text" {
					firstUserText = block.Get("text").String()
					return false // break
				}
				return true
			})
			return false // break
		}
		return true
	})
	return firstUserText
}

// ccVersionSuffixPattern matches the version suffix in billing headers, e.g. "2.1.63.68f"
var ccVersionSuffixPattern = regexp.MustCompile(`(cc_version=\d+\.\d+\.\d+)\.([0-9a-f]{3})`)

// injectBillingHeaderBlock injects the x-anthropic-billing-header as system prompt block 0.
// Real Claude Code sends this as the first system block with no cache_control.
// The cc_version suffix is dynamically computed per-request to match Claude Code behavior.
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

	// Dynamically compute the cc_version suffix if the billing header contains
	// a version pattern like "cc_version=2.1.63.xxx"
	finalHeader := billingHeader
	if matches := ccVersionSuffixPattern.FindStringSubmatch(billingHeader); len(matches) == 3 {
		// Extract the base version (e.g. "2.1.63") from the full match
		baseVersionPrefix := matches[1] // "cc_version=2.1.63"
		baseVersion := strings.TrimPrefix(baseVersionPrefix, "cc_version=")
		suffix := computeBillingVersionSuffix(payload, baseVersion)
		finalHeader = ccVersionSuffixPattern.ReplaceAllString(billingHeader, "${1}."+suffix)
	}

	// Build new block and prepend to system array
	billingBlock := map[string]string{
		"type": "text",
		"text": finalHeader,
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
