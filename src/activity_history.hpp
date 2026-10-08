#pragma once

#include "model.hpp"

#include <array>
#include <chrono>
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
};

struct DailyTokens {
    CivilDay day{};
    double tokens{0};
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
    std::chrono::seconds longestTask{0};
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

// Replaces one account's imported days. Other accounts and recorded deltas stay.
// Returns true when that account's imported days change.
bool replaceImportedDailyTokens(TokenHistory& history, std::string_view providerId, std::string_view accountId,
                                std::span<const DailyTokens> days);

[[nodiscard]] ActivityStats activityStats(const TokenHistory& history, TimePoint now, std::chrono::seconds refreshInterval);
[[nodiscard]] ActivityCalendar activityCalendar(const TokenHistory& history, TimePoint now);
[[nodiscard]] std::string formatTaskDuration(std::chrono::seconds duration);

// Non-secret text. Malformed input returns an empty history.
[[nodiscard]] std::string serializeTokenHistory(const TokenHistory& history);
[[nodiscard]] TokenHistory parseTokenHistory(std::string_view text);

} // namespace hypelimits
