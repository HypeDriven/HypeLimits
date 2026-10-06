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
    std::string idToken;
};

enum class TokenPick { Left, Right, Tie };

// Background CLI import/write-back runs only while the provider is enabled
// and the user has not disconnected it from Options.
[[nodiscard]] bool shouldBackgroundSyncProvider(bool enabled, bool allowOfficialCliImport);
[[nodiscard]] bool sameCredentialAccount(const TokenRecord& left, const TokenRecord& right);
// Whether a live CLI login may replace a slot's rejected credential. A known slot identity must match the
// login's identity. Without one, only a single-account provider or the selected managed slot may adopt it,
// and never a login another slot is known to own.
[[nodiscard]] bool cliLoginMayRecoverSlot(std::string_view slotIdentity, std::string_view loginIdentity, bool managed,
                                          bool selectedSlot, bool ownedByOtherSlot);
[[nodiscard]] bool tokenRecordUsable(const TokenRecord& record, std::int64_t nowMs);
[[nodiscard]] TokenPick pickLatestValidToken(const TokenRecord& left, const TokenRecord& right, std::int64_t nowMs);
[[nodiscard]] std::size_t pickLatestValidTokenIndex(std::span<const TokenRecord> records, std::int64_t nowMs);
[[nodiscard]] std::optional<CliCredentialFormat> cliFormatForProvider(std::string_view providerId);
[[nodiscard]] std::vector<std::string> cliHomeRelativePaths(std::string_view providerId);
[[nodiscard]] std::string wslUserSettingKey(std::string_view distro, std::string_view user);
[[nodiscard]] TokenRecord parseCliTokenRecord(CliCredentialFormat format, std::string_view json);
[[nodiscard]] std::string mergeCliCredentialJson(CliCredentialFormat format, std::string_view existingJson, const TokenRecord& winner);

} // namespace hypelimits
