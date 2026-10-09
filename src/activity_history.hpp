#pragma once

#include "model.hpp"

#include <array>
#include <chrono>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace hypelimits {

// A local calendar day. Token totals use the machine's local calendar, not UTC.
struct CivilDay {
    int year{1970};
    unsigned month{1};
    unsigned day{1};

    friend bool operator==(const CivilDay&, const CivilDay&) = default;
    friend auto operator<=>(const CivilDay&, const CivilDay&) = default;
};

enum class AllowanceWindow { Session, Weekly };
enum class CounterUnit { Tokens, Percent, Requests, Credits, Currency };

// One allowance reading. Account id is a slot label, never a credential.
struct TokenObservation {
    std::string providerId;
    std::string accountId;
    AllowanceWindow window{AllowanceWindow::Session};
    CounterUnit unit{CounterUnit::Tokens};
    double used{0};
    MetricState state{MetricState::Current};
    TimePoint observedAt{};
};

struct TokenDelta {
    TimePoint at{};
    double tokens{0};
    // Empty for an increase saved before the provider was recorded with it.
    std::string providerId;
    // Empty when the increase was saved for the provider but not for one account.
    std::string accountId;
};

struct DailyTokens {
    CivilDay day{};
    double tokens{0};
    // Empty for a total saved before the provider was recorded with it.
    std::string providerId;
    // Empty when the total was saved for the provider but not for one account.
    std::string accountId;
};

// Last absolute token counter for one provider account and allowance window.
struct TokenBaseline {
    std::string providerId;
    std::string accountId;
    AllowanceWindow window{AllowanceWindow::Session};
    double used{0};
    TimePoint observedAt{};
};

// Absolute tokens a provider reported for one account on one day.
// This is a daily total, not an allowance-window counter.
struct ImportedDailyTokens {
    std::string providerId;
    std::string accountId;
    CivilDay day{};
    double tokens{0};
};

struct TokenHistory {
    std::vector<DailyTokens> days;
    std::vector<TokenDelta> deltas;
    std::vector<TokenBaseline> baselines;
    std::vector<ImportedDailyTokens> imported;
};

struct ActivityStats {
    double lifetimeTokens{0};
    double peakTokensPerDay{0};
    int longestStreakDays{0};
    int currentStreakDays{0};
};

struct CalendarCell {
    CivilDay day{};
    double tokens{0};
    int level{0};
};

struct CalendarWeek {
    std::string monthLabel;
    std::array<std::optional<CalendarCell>, 7> days{};
};

struct ActivityCalendar {
    std::vector<CalendarWeek> weeks;
    double yearTokens{0};
};

[[nodiscard]] CivilDay localCivilDay(TimePoint time);
[[nodiscard]] CivilDay shiftCivilDay(CivilDay day, int deltaDays);
[[nodiscard]] int sundayIndex(CivilDay day);
[[nodiscard]] TimePoint timePointOnLocalDay(CivilDay day, int hour, int minute);

// Positive token increases only. The first current token sample is a baseline.
// Session is ignored when that account also reports weekly absolute tokens.
// Returns true when daily totals, deltas, or baselines change.
bool recordTokenObservations(TokenHistory& history, std::span<const TokenObservation> observations);

// Codex daily analytics. nullopt when the body has no data array, so a failed
// response cannot wipe a saved import. An empty array is a real empty report.
[[nodiscard]] std::optional<std::vector<DailyTokens>> parseCodexDailyTokens(std::string_view json);

// Local CLI session logs for providers that do not report absolute daily tokens.
// Codex is intentionally absent: its daily endpoint already supplies those totals.
inline constexpr std::string_view kLocalSessionAccount{"local"};

enum class SessionLogScan { Unavailable, Unchanged, Updated };

// One already-parsed log. Path is a filesystem path, never log text or a credential.
// accountId is empty until a Claude file is scanned for its organization. After that
// scan it is the organization id, "local" when the file names none, or "mixed" when
// it names more than one. Grok and Kimi files use "local".
struct SessionLogCacheEntry {
    std::string providerId;
    std::string path;
    std::int64_t modified{0};
    std::uint64_t size{0};
    std::string accountId;
    std::vector<DailyTokens> days;
};

struct SessionLogCache {
    std::vector<SessionLogCacheEntry> entries;
};

struct LocalSessionImport {
    std::string providerId;
    // Organization id, a saved slot label, or "local" for totals that belong to no one login.
    std::string accountId;
    std::vector<DailyTokens> days;
};

// A Claude login's account id paired with the organization id stored beside it.
// Neither value is a credential.
struct OrganizationAccountLink {
    std::string accountUuid;
    std::string organizationUuid;
};

// One saved HypeLimits slot. slotId is the slot label ("0", "1"). accountUuid may be empty.
struct SavedAccountSlot {
    std::string slotId;
    std::string accountUuid;
};

struct OrganizationSlotMatch {
    std::string organizationId;
    std::string slotId;
};

// Absolute tokens in one JSONL log. Repeated Claude requests and repeated Grok
// turns count once. Lines without a recognized token record add nothing.
[[nodiscard]] std::vector<DailyTokens> parseSessionLogTokens(std::string_view jsonl);

// Rereads changed logs under a home directory. A missing or unreadable home
// leaves the cache alone. A home that exists drops logs that are no longer there.
SessionLogScan refreshSessionLogCache(SessionLogCache& cache, const std::filesystem::path& home);

// Claude, Grok, and Kimi totals from the cache. A provider with no logs is an empty list.
// Claude rows are split by organization. A file that names no organization inherits its
// session's organization when that session names exactly one; otherwise it stays "local".
[[nodiscard]] std::vector<LocalSessionImport> sessionLogImports(const SessionLogCache& cache);

// Account and organization ids named by ~/.claude.json and its backups. Other files are ignored.
[[nodiscard]] std::vector<OrganizationAccountLink> claudeOrganizationLinks(const std::filesystem::path& home);

// Pairs an organization with a saved slot when the slot's account id is already linked to
// that organization. When exactly one organization and one slot are still unpaired, they
// are paired. With no saved account ids, or with more than one of either left over, the
// remainder stays unpaired.
[[nodiscard]] std::vector<OrganizationSlotMatch> matchOrganizationsToSlots(
    std::span<const OrganizationAccountLink> links, std::span<const SavedAccountSlot> slots,
    std::span<const std::string> organizationIds);

// Moves Claude imports onto the matched slot labels. Every saved slot is present, with an
// empty day list when it has no logs. Unmatched organizations and "local" rows are summed
// onto account "local". Other providers are ignored.
[[nodiscard]] std::vector<LocalSessionImport> assignClaudeSessionImports(
    std::span<const LocalSessionImport> imports, std::span<const OrganizationAccountLink> links,
    std::span<const SavedAccountSlot> slots);

[[nodiscard]] std::string serializeSessionLogCache(const SessionLogCache& cache);
[[nodiscard]] SessionLogCache parseSessionLogCache(std::string_view text);
bool storeSessionLogCache(const SessionLogCache& cache, const std::filesystem::path& path);
[[nodiscard]] SessionLogCache loadSessionLogCache(const std::filesystem::path& path);

// Replaces one account's imported days. Other accounts and recorded deltas stay.
// Returns true when that account's imported days change.
bool replaceImportedDailyTokens(TokenHistory& history, std::string_view providerId, std::string_view accountId,
                                std::span<const DailyTokens> days);

// An empty provider id is every provider. A provider id with an empty account id is
// every account of that provider, including totals that name no account. Both ids
// keep one account. Older totals with no provider stay in the all-providers view only.
[[nodiscard]] ActivityStats activityStats(const TokenHistory& history, TimePoint now, std::string_view providerId = {},
                                          std::string_view accountId = {});
[[nodiscard]] ActivityCalendar activityCalendar(const TokenHistory& history, TimePoint now, std::string_view providerId = {},
                                                std::string_view accountId = {});

// Non-secret text. Malformed input returns an empty history.
[[nodiscard]] std::string serializeTokenHistory(const TokenHistory& history);
[[nodiscard]] TokenHistory parseTokenHistory(std::string_view text);

} // namespace hypelimits
