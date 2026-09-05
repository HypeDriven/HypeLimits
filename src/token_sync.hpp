#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace hypelimits {

enum class CliCredentialFormat {
    ClaudeOauth,
    CodexTokens,
    GrokAuth,
    GeminiOauth,
    KimiCredentials
};

struct TokenRecord {
    std::string accessToken;
    std::string refreshToken;
    std::string accountId;
    std::string teamId;
    std::optional<std::int64_t> expiresAtMs;
    std::optional<std::int64_t> observedAtMs;
};

enum class TokenPick { Left, Right, Tie };

[[nodiscard]] bool tokenRecordUsable(const TokenRecord& record, std::int64_t nowMs);
[[nodiscard]] TokenPick pickLatestValidToken(const TokenRecord& left, const TokenRecord& right, std::int64_t nowMs);
[[nodiscard]] std::size_t pickLatestValidTokenIndex(std::span<const TokenRecord> records, std::int64_t nowMs);
[[nodiscard]] std::optional<CliCredentialFormat> cliFormatForProvider(std::string_view providerId);
[[nodiscard]] std::vector<std::string> cliHomeRelativePaths(std::string_view providerId);
[[nodiscard]] std::string wslUserSettingKey(std::string_view distro, std::string_view user);
[[nodiscard]] TokenRecord parseCliTokenRecord(CliCredentialFormat format, std::string_view json);
[[nodiscard]] std::string mergeCliCredentialJson(CliCredentialFormat format, std::string_view existingJson, const TokenRecord& winner);

} // namespace hypelimits
