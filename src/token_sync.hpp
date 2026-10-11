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
// A selected account's credential is shared by every CLI home, so whichever holder refreshes first strands the
// others on a consumed refresh token. A slot therefore remembers fingerprints of the refresh tokens it held before.
[[nodiscard]] std::string appendTokenFingerprint(std::string_view chain, std::string_view fingerprint, std::size_t limit = 32);
[[nodiscard]] bool tokenChainContains(std::string_view chain, std::string_view fingerprint);

enum class CliTargetAction { Keep, Write, AdoptIfSameAccount };

// What background sync does with one CLI file while an account is selected. Write replaces a stale copy of the
// selected account's own token. AdoptIfSameAccount is a newer login the CLI made itself: the caller adopts it only
// after proving it belongs to the selected account. Any other login is the CLI's own and is kept.
[[nodiscard]] CliTargetAction selectedCliTargetAction(const TokenRecord& file, const TokenRecord& selected,
                                                      bool fileHoldsEarlierToken, std::int64_t nowMs);
[[nodiscard]] bool tokenRecordUsable(const TokenRecord& record, std::int64_t nowMs);
[[nodiscard]] TokenPick pickLatestValidToken(const TokenRecord& left, const TokenRecord& right, std::int64_t nowMs);
[[nodiscard]] std::size_t pickLatestValidTokenIndex(std::span<const TokenRecord> records, std::int64_t nowMs);
[[nodiscard]] std::optional<CliCredentialFormat> cliFormatForProvider(std::string_view providerId);
[[nodiscard]] std::vector<std::string> cliHomeRelativePaths(std::string_view providerId);
[[nodiscard]] std::string wslUserSettingKey(std::string_view distro, std::string_view user);
[[nodiscard]] TokenRecord parseCliTokenRecord(CliCredentialFormat format, std::string_view json);
// ChatGPT account id carried in an OpenAI access or id token's JWT payload; empty when absent.
[[nodiscard]] std::string chatgptAccountIdFromJwt(std::string_view token);
[[nodiscard]] std::string mergeCliCredentialJson(CliCredentialFormat format, std::string_view existingJson, const TokenRecord& winner);

} // namespace hypelimits
