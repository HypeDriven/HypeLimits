#include "token_sync.hpp"

#include "provider_parsing.hpp"

#include <chrono>
#include <cctype>
#include <format>
#include <string>
#include <utility>

namespace hypelimits {
namespace {

std::string escapeJson(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const unsigned char ch : value) {
        if (ch == '"' || ch == '\\') {
            out.push_back('\\');
            out.push_back(static_cast<char>(ch));
        } else if (ch == '\n') {
            out += "\\n";
        } else {
            out.push_back(static_cast<char>(ch));
        }
    }
    return out;
}

std::size_t skipJsonString(std::string_view json, std::size_t quote) {
    std::size_t i = quote + 1;
    while (i < json.size()) {
        if (json[i] == '\\') {
            i += 2;
            continue;
        }
        if (json[i] == '"') return i + 1;
        ++i;
    }
    return json.size();
}

std::optional<std::size_t> matchingBrace(std::string_view json, std::size_t open) {
    int depth = 0;
    for (std::size_t i = open; i < json.size();) {
        if (json[i] == '"') {
            i = skipJsonString(json, i);
            continue;
        }
        if (json[i] == '{') ++depth;
        else if (json[i] == '}') {
            --depth;
            if (depth == 0) return i;
        }
        ++i;
    }
    return std::nullopt;
}

std::size_t skipWs(std::string_view json, std::size_t i) {
    while (i < json.size() && (json[i] == ' ' || json[i] == '\t' || json[i] == '\r' || json[i] == '\n')) ++i;
    return i;
}

bool looksLikeObject(std::string_view json) {
    const auto i = skipWs(json, 0);
    return i < json.size() && json[i] == '{';
}

std::optional<std::size_t> findDepth1Key(std::string_view json, std::size_t open, std::size_t close, std::string_view key) {
    const std::string needle = "\"" + std::string(key) + "\"";
    int depth = 0;
    for (std::size_t i = open + 1; i < close;) {
        if (json[i] == '"') {
            if (depth == 0 && json.substr(i, needle.size()) == needle) return i;
            i = skipJsonString(json, i);
            continue;
        }
        if (json[i] == '{' || json[i] == '[') ++depth;
        else if (json[i] == '}' || json[i] == ']') --depth;
        ++i;
    }
    return std::nullopt;
}

std::size_t valueEnd(std::string_view json, std::size_t valueStart, std::size_t close) {
    std::size_t i = skipWs(json, valueStart);
    if (i >= close) return close;
    if (json[i] == '"') return skipJsonString(json, i);
    if (json[i] == '{') return matchingBrace(json, i).value_or(close) + 1;
    if (json[i] == '[') {
        int depth = 0;
        for (; i < close; ++i) {
            if (json[i] == '"') {
                i = skipJsonString(json, i) - 1;
                continue;
            }
            if (json[i] == '[') ++depth;
            else if (json[i] == ']') {
                --depth;
                if (depth == 0) return i + 1;
            }
        }
        return close;
    }
    while (i < close && json[i] != ',' && json[i] != '}' && json[i] != ']') ++i;
    return i;
}

std::string setObjectField(std::string json, std::size_t open, std::string_view key, std::string_view renderedValue) {
    const auto close = matchingBrace(json, open);
    if (!close) return json;
    if (const auto keyAt = findDepth1Key(json, open, *close, key)) {
        const auto colon = json.find(':', *keyAt + key.size() + 2);
        if (colon == std::string::npos || colon > *close) return json;
        const auto start = skipWs(json, colon + 1);
        const auto end = valueEnd(json, start, *close);
        json.replace(start, end - start, renderedValue);
        return json;
    }
    std::size_t insertAt = *close;
    bool empty = true;
    for (std::size_t i = open + 1; i < *close; ++i) {
        if (!std::isspace(static_cast<unsigned char>(json[i]))) {
            empty = false;
            break;
        }
    }
    const std::string insertion = std::string(empty ? "" : ",") + "\"" + std::string(key) + "\":" + std::string(renderedValue);
    json.insert(insertAt, insertion);
    return json;
}

std::string setStringField(std::string json, std::size_t open, std::string_view key, std::string_view value) {
    return setObjectField(std::move(json), open, key, "\"" + escapeJson(value) + "\"");
}

std::string setNumberField(std::string json, std::size_t open, std::string_view key, std::int64_t value) {
    return setObjectField(std::move(json), open, key, std::to_string(value));
}

std::optional<std::pair<std::size_t, std::size_t>> nestedObject(std::string_view json, std::size_t parentOpen, std::string_view key) {
    const auto parentClose = matchingBrace(json, parentOpen);
    if (!parentClose) return std::nullopt;
    const auto keyAt = findDepth1Key(json, parentOpen, *parentClose, key);
    if (!keyAt) return std::nullopt;
    const auto colon = json.find(':', *keyAt + key.size() + 2);
    if (colon == std::string::npos) return std::nullopt;
    const auto open = skipWs(json, colon + 1);
    if (open >= json.size() || json[open] != '{') return std::nullopt;
    const auto close = matchingBrace(json, open);
    if (!close) return std::nullopt;
    return std::pair{open, *close};
}

std::string ensureNestedObject(std::string json, std::size_t parentOpen, std::string_view key) {
    if (nestedObject(json, parentOpen, key)) return json;
    return setObjectField(std::move(json), parentOpen, key, "{}");
}

std::optional<std::int64_t> parseExpiryMs(std::string_view json, std::size_t start) {
    for (const char* key : {"expiresAt", "expires_at", "expiry_date", "expires"}) {
        if (const auto value = jsonNumber(json, key, start)) {
            const auto n = static_cast<std::int64_t>(*value);
            if (n > 10'000'000'000LL) return n;
            if (n > 1'000'000'000LL) return n * 1000;
            return n;
        }
    }
    return std::nullopt;
}

TokenRecord parseFromObject(std::string_view json, std::size_t start) {
    TokenRecord record;
    record.accessToken = jsonString(json, "accessToken", start).value_or(jsonString(json, "access_token", start).value_or(jsonString(json, "token", start).value_or(jsonString(json, "api_key", start).value_or(std::string{}))));
    record.refreshToken = jsonString(json, "refreshToken", start).value_or(jsonString(json, "refresh_token", start).value_or(std::string{}));
    record.accountId = jsonString(json, "account_id", start).value_or(jsonString(json, "chatgpt_account_id", start).value_or(std::string{}));
    record.teamId = jsonString(json, "team_id", start).value_or(jsonString(json, "teamId", start).value_or(std::string{}));
    record.expiresAtMs = parseExpiryMs(json, start);
    if (const auto last = jsonString(json, "last_refresh", start)) {
        if (const auto at = parseTimestamp(*last)) {
            record.observedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(at->time_since_epoch()).count();
        }
    } else if (const auto n = jsonNumber(json, "last_refresh", start)) {
        auto ms = static_cast<std::int64_t>(*n);
        if (ms > 0 && ms < 10'000'000'000LL) ms *= 1000;
        if (ms > 0) record.observedAtMs = ms;
    }
    return record;
}

std::string emptySkeleton(CliCredentialFormat format) {
    switch (format) {
    case CliCredentialFormat::ClaudeOauth: return "{\"claudeAiOauth\":{}}";
    case CliCredentialFormat::CodexTokens: return "{\"tokens\":{}}";
    case CliCredentialFormat::GrokAuth:
    case CliCredentialFormat::GeminiOauth:
    case CliCredentialFormat::KimiCredentials: return "{}";
    }
    return "{}";
}

} // namespace

bool tokenRecordUsable(const TokenRecord& record, std::int64_t nowMs) {
    if (record.accessToken.empty() && record.refreshToken.empty()) return false;
    if (record.expiresAtMs && *record.expiresAtMs <= nowMs && record.refreshToken.empty()) return false;
    return true;
}

TokenPick pickLatestValidToken(const TokenRecord& left, const TokenRecord& right, std::int64_t nowMs) {
    const bool leftOk = tokenRecordUsable(left, nowMs);
    const bool rightOk = tokenRecordUsable(right, nowMs);
    if (!leftOk && !rightOk) return TokenPick::Tie;
    if (leftOk && !rightOk) return TokenPick::Left;
    if (!leftOk && rightOk) return TokenPick::Right;
    if (left.accessToken == right.accessToken && left.refreshToken == right.refreshToken) return TokenPick::Tie;
    if (left.observedAtMs && right.observedAtMs && *left.observedAtMs != *right.observedAtMs) {
        return *left.observedAtMs > *right.observedAtMs ? TokenPick::Left : TokenPick::Right;
    }
    if (left.expiresAtMs && right.expiresAtMs && *left.expiresAtMs != *right.expiresAtMs) {
        return *left.expiresAtMs > *right.expiresAtMs ? TokenPick::Left : TokenPick::Right;
    }
    if (left.observedAtMs && !right.observedAtMs) return TokenPick::Left;
    if (!left.observedAtMs && right.observedAtMs) return TokenPick::Right;
    if (!left.refreshToken.empty() && right.refreshToken.empty()) return TokenPick::Left;
    if (left.refreshToken.empty() && !right.refreshToken.empty()) return TokenPick::Right;
    return TokenPick::Tie;
}

std::size_t pickLatestValidTokenIndex(std::span<const TokenRecord> records, std::int64_t nowMs) {
    if (records.empty()) return 0;
    std::size_t best = 0;
    for (std::size_t i = 1; i < records.size(); ++i) {
        if (pickLatestValidToken(records[best], records[i], nowMs) == TokenPick::Right) best = i;
    }
    return best;
}

std::vector<std::string> cliHomeRelativePaths(std::string_view providerId) {
    if (providerId == "anthropic") return {".claude/.credentials.json"};
    if (providerId == "openai") return {".codex/auth.json"};
    if (providerId == "xai") return {".grok/auth.json"};
    if (providerId == "antigravity") {
        return {".gemini/oauth_creds.json", ".antigravity/oauth.json", ".antigravity/oauth_creds.json"};
    }
    if (providerId == "moonshot") {
        return {".kimi-code/credentials/kimi-code.json", ".kimi/credentials/kimi-code.json", ".kimi/credentials.json"};
    }
    return {};
}

std::string wslUserSettingKey(std::string_view distro, std::string_view user) {
    return std::format("WslUser.{}/{}", distro, user);
}

std::optional<CliCredentialFormat> cliFormatForProvider(std::string_view providerId) {
    if (providerId == "anthropic") return CliCredentialFormat::ClaudeOauth;
    if (providerId == "openai") return CliCredentialFormat::CodexTokens;
    if (providerId == "xai") return CliCredentialFormat::GrokAuth;
    if (providerId == "antigravity") return CliCredentialFormat::GeminiOauth;
    if (providerId == "moonshot") return CliCredentialFormat::KimiCredentials;
    return std::nullopt;
}

TokenRecord parseCliTokenRecord(CliCredentialFormat format, std::string_view json) {
    if (!looksLikeObject(json)) return {};
    const auto root = skipWs(json, 0);
    if (format == CliCredentialFormat::ClaudeOauth) {
        if (const auto nested = nestedObject(json, root, "claudeAiOauth")) {
            return parseFromObject(json, nested->first);
        }
    }
    if (format == CliCredentialFormat::CodexTokens) {
        TokenRecord record;
        if (const auto nested = nestedObject(json, root, "tokens")) {
            record = parseFromObject(json, nested->first);
        } else {
            record = parseFromObject(json, root);
        }
        if (auto account = jsonString(json, "account_id", root)) record.accountId = *account;
        if (const auto last = jsonString(json, "last_refresh", root)) {
            if (const auto at = parseTimestamp(*last)) {
                record.observedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(at->time_since_epoch()).count();
            }
        }
        return record;
    }
    return parseFromObject(json, root);
}

std::string mergeCliCredentialJson(CliCredentialFormat format, std::string_view existingJson, const TokenRecord& winner) {
    std::string json = looksLikeObject(existingJson) ? std::string(existingJson) : emptySkeleton(format);
    auto root = skipWs(json, 0);
    if (root >= json.size() || json[root] != '{' || !matchingBrace(json, root)) {
        json = emptySkeleton(format);
        root = 0;
    }

    if (format == CliCredentialFormat::ClaudeOauth) {
        json = ensureNestedObject(std::move(json), root, "claudeAiOauth");
        root = skipWs(json, 0);
        const auto nested = nestedObject(json, root, "claudeAiOauth");
        if (!nested) return json;
        json = setStringField(std::move(json), nested->first, "accessToken", winner.accessToken);
        json = setStringField(std::move(json), nested->first, "refreshToken", winner.refreshToken);
        if (winner.expiresAtMs) json = setNumberField(std::move(json), nested->first, "expiresAt", *winner.expiresAtMs);
        return json;
    }

    if (format == CliCredentialFormat::CodexTokens) {
        json = ensureNestedObject(std::move(json), root, "tokens");
        root = skipWs(json, 0);
        const auto nested = nestedObject(json, root, "tokens");
        if (!nested) return json;
        json = setStringField(std::move(json), nested->first, "access_token", winner.accessToken);
        json = setStringField(std::move(json), nested->first, "refresh_token", winner.refreshToken);
        if (!winner.accountId.empty()) json = setStringField(std::move(json), root, "account_id", winner.accountId);
        return json;
    }

    json = setStringField(std::move(json), root, "access_token", winner.accessToken);
    json = setStringField(std::move(json), root, "refresh_token", winner.refreshToken);
    if (format == CliCredentialFormat::GeminiOauth && winner.expiresAtMs) {
        json = setNumberField(std::move(json), root, "expiry_date", *winner.expiresAtMs);
    }
    if ((format == CliCredentialFormat::GrokAuth || format == CliCredentialFormat::KimiCredentials) && winner.expiresAtMs) {
        json = setNumberField(std::move(json), root, "expires_at", *winner.expiresAtMs);
    }
    if (!winner.accountId.empty()) json = setStringField(std::move(json), root, "account_id", winner.accountId);
    if (!winner.teamId.empty()) json = setStringField(std::move(json), root, "team_id", winner.teamId);
    return json;
}

} // namespace hypelimits
