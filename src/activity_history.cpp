#include "activity_history.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <set>
#include <utility>

namespace hypelimits {
namespace {

constexpr const char* kMonthNames[] = {
    "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

std::chrono::sys_days toSysDays(CivilDay day) {
    return std::chrono::sys_days{
        std::chrono::year{day.year} / std::chrono::month{day.month} / std::chrono::day{day.day}};
}

CivilDay fromYearMonthDay(std::chrono::year_month_day ymd) {
    return CivilDay{static_cast<int>(ymd.year()), static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day())};
}

bool finiteNonNegative(double value) {
    return std::isfinite(value) && value >= 0.0;
}

bool countsAsTokens(const TokenObservation& observation) {
    return observation.state == MetricState::Current && observation.unit == CounterUnit::Tokens
        && finiteNonNegative(observation.used);
}

double tokensOn(const TokenHistory& history, CivilDay day) {
    const auto found = std::ranges::lower_bound(history.days, day, {}, &DailyTokens::day);
    if (found != history.days.end() && found->day == day) return found->tokens;
    return 0.0;
}

double percentile(const std::vector<double>& sorted, double position) {
    if (sorted.empty()) return 0.0;
    if (sorted.size() == 1) return sorted.front();
    const double index = position * static_cast<double>(sorted.size() - 1);
    const auto lower = static_cast<std::size_t>(std::floor(index));
    const auto upper = static_cast<std::size_t>(std::ceil(index));
    const double fraction = index - static_cast<double>(lower);
    return sorted[lower] * (1.0 - fraction) + sorted[upper] * fraction;
}

int levelFor(double tokens, const std::vector<double>& positiveSorted) {
    if (!(tokens > 0.0) || positiveSorted.empty()) return 0;
    const double first = percentile(positiveSorted, 0.25);
    const double second = percentile(positiveSorted, 0.50);
    const double third = percentile(positiveSorted, 0.75);
    if (tokens <= first) return 1;
    if (tokens <= second) return 2;
    if (tokens <= third) return 3;
    return 4;
}

void assignMonthLabels(ActivityCalendar& calendar) {
    int lastLabeled = -10;
    for (std::size_t weekIndex = 0; weekIndex < calendar.weeks.size(); ++weekIndex) {
        auto& week = calendar.weeks[weekIndex];
        unsigned month = 0;
        bool monthStarts = false;
        for (const auto& cell : week.days) {
            if (!cell) continue;
            if (month == 0) month = cell->day.month;
            if (cell->day.day == 1 && cell->day.month >= 1 && cell->day.month <= 12) {
                month = cell->day.month;
                monthStarts = true;
            }
        }
        const bool wantLabel = weekIndex == 0 || monthStarts;
        if (!wantLabel || month < 1 || month > 12) continue;
        const int index = static_cast<int>(weekIndex);
        if (lastLabeled >= 0 && index - lastLabeled < 2) {
            if (!monthStarts) continue;
            calendar.weeks[static_cast<std::size_t>(lastLabeled)].monthLabel.clear();
        }
        week.monthLabel = kMonthNames[month];
        lastLabeled = index;
    }
}

std::string formatDouble(double value) {
    char buffer[128];
    const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value, std::chars_format::general);
    if (result.ec != std::errc{}) return "0";
    return std::string(buffer, result.ptr);
}

std::string formatDate(CivilDay day) {
    return std::format("{:04}-{:02}-{:02}", day.year, day.month, day.day);
}

bool parseInt(std::string_view text, long long& value) {
    if (text.empty()) return false;
    const char* begin = text.data();
    const char* end = begin + text.size();
    const auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end;
}

bool parseDouble(std::string_view text, double& value) {
    if (text.empty()) return false;
    const char* begin = text.data();
    const char* end = begin + text.size();
    const auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end && std::isfinite(value);
}

bool parseDate(std::string_view text, CivilDay& day) {
    if (text.size() != 10 || text[4] != '-' || text[7] != '-') return false;
    long long year = 0;
    long long month = 0;
    long long date = 0;
    if (!parseInt(text.substr(0, 4), year) || !parseInt(text.substr(5, 2), month) || !parseInt(text.substr(8, 2), date)) {
        return false;
    }
    if (year < 1970 || year > 9999 || month < 1 || month > 12 || date < 1 || date > 31) return false;
    const std::chrono::year_month_day ymd{std::chrono::year{static_cast<int>(year)}
        / std::chrono::month{static_cast<unsigned>(month)} / std::chrono::day{static_cast<unsigned>(date)}};
    if (!ymd.ok()) return false;
    day = CivilDay{static_cast<int>(year), static_cast<unsigned>(month), static_cast<unsigned>(date)};
    return true;
}

bool parseId(std::string_view text) {
    if (text.empty() || text.size() > 64) return false;
    for (const unsigned char character : text) {
        const bool ok = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' || character == ':';
        if (!ok) return false;
    }
    return true;
}

std::optional<std::string_view> takeField(std::string_view& rest) {
    if (rest.empty()) return std::nullopt;
    const auto space = rest.find(' ');
    const auto field = space == std::string_view::npos ? rest : rest.substr(0, space);
    if (field.empty()) return std::nullopt;
    rest.remove_prefix(space == std::string_view::npos ? rest.size() : space + 1);
    return field;
}

std::int64_t toUnixMilliseconds(TimePoint time) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count();
}

TimePoint fromUnixMilliseconds(std::int64_t milliseconds) {
    return TimePoint{std::chrono::milliseconds{milliseconds}};
}

} // namespace

CivilDay localCivilDay(TimePoint time) {
    try {
        const auto zoned = std::chrono::zoned_time{std::chrono::current_zone(), time};
        const auto localDays = std::chrono::floor<std::chrono::days>(zoned.get_local_time());
        const std::chrono::year_month_day ymd{localDays};
        if (ymd.ok()) return fromYearMonthDay(ymd);
    } catch (const std::exception&) {
    }
    return fromYearMonthDay(std::chrono::year_month_day{std::chrono::floor<std::chrono::days>(time)});
}

CivilDay shiftCivilDay(CivilDay day, int deltaDays) {
    return fromYearMonthDay(std::chrono::year_month_day{toSysDays(day) + std::chrono::days{deltaDays}});
}

int sundayIndex(CivilDay day) {
    return static_cast<int>(std::chrono::weekday{toSysDays(day)}.c_encoding());
}

TimePoint timePointOnLocalDay(CivilDay day, int hour, int minute) {
    const std::chrono::local_days localDay{
        std::chrono::year{day.year} / std::chrono::month{day.month} / std::chrono::day{day.day}};
    const auto local = localDay + std::chrono::hours{hour} + std::chrono::minutes{minute};
    try {
        const std::chrono::zoned_time zoned{std::chrono::current_zone(), local};
        return std::chrono::clock_cast<std::chrono::system_clock>(zoned.get_sys_time());
    } catch (const std::exception&) {
        return TimePoint{toSysDays(day)} + std::chrono::hours{hour} + std::chrono::minutes{minute};
    }
}

bool recordTokenObservations(TokenHistory& history, std::span<const TokenObservation> observations) {
    std::set<std::pair<std::string, std::string>> weeklyTokens;
    for (const auto& baseline : history.baselines) {
        if (baseline.window == AllowanceWindow::Weekly) weeklyTokens.emplace(baseline.providerId, baseline.accountId);
    }
    for (const auto& observation : observations) {
        if (countsAsTokens(observation) && observation.window == AllowanceWindow::Weekly) {
            weeklyTokens.emplace(observation.providerId, observation.accountId);
        }
    }

    std::vector<std::size_t> order(observations.size());
    for (std::size_t index = 0; index < order.size(); ++index) order[index] = index;
    std::ranges::stable_sort(order, [&](std::size_t left, std::size_t right) {
        return observations[left].observedAt < observations[right].observedAt;
    });

    bool changed = false;
    for (const std::size_t index : order) {
        const auto& observation = observations[index];
        if (!countsAsTokens(observation)) continue;
        // Weekly is the longer allowance window. Counting session as well would double the same tokens.
        const bool suppressSession = observation.window == AllowanceWindow::Session
            && weeklyTokens.contains(std::pair<std::string, std::string>{observation.providerId, observation.accountId});
        const auto found = std::ranges::find_if(history.baselines, [&](const TokenBaseline& baseline) {
            return baseline.providerId == observation.providerId && baseline.accountId == observation.accountId
                && baseline.window == observation.window;
        });
        if (found == history.baselines.end()) {
            history.baselines.push_back(TokenBaseline{
                observation.providerId, observation.accountId, observation.window, observation.used, observation.observedAt});
            changed = true;
            continue;
        }
        const double delta = observation.used - found->used;
        const bool usedChanged = observation.used != found->used;
        found->used = observation.used;
        found->observedAt = observation.observedAt;
        if (usedChanged) changed = true;
        if (suppressSession || !(delta > 0.0)) continue;

        const CivilDay day = localCivilDay(observation.observedAt);
        const auto dayIt = std::ranges::lower_bound(history.days, day, {}, &DailyTokens::day);
        if (dayIt != history.days.end() && dayIt->day == day) dayIt->tokens += delta;
        else history.days.insert(dayIt, DailyTokens{day, delta});
        const auto deltaIt = std::ranges::upper_bound(history.deltas, observation.observedAt, {}, &TokenDelta::at);
        history.deltas.insert(deltaIt, TokenDelta{observation.observedAt, delta});
        changed = true;
    }
    return changed;
}

ActivityStats activityStats(const TokenHistory& history, TimePoint now, std::chrono::seconds refreshInterval) {
    ActivityStats stats;
    int run = 0;
    bool inRun = false;
    CivilDay previous{};
    for (const auto& day : history.days) {
        stats.lifetimeTokens += day.tokens;
        stats.peakTokensPerDay = std::max(stats.peakTokensPerDay, day.tokens);
        if (!(day.tokens > 0.0)) {
            run = 0;
            inRun = false;
            continue;
        }
        if (inRun && day.day == shiftCivilDay(previous, 1)) ++run;
        else run = 1;
        previous = day.day;
        inRun = true;
        stats.longestStreakDays = std::max(stats.longestStreakDays, run);
    }

    const CivilDay today = localCivilDay(now);
    // Today still at zero does not erase a streak that was alive yesterday.
    CivilDay cursor = tokensOn(history, today) > 0.0 ? today : shiftCivilDay(today, -1);
    while (tokensOn(history, cursor) > 0.0 && stats.currentStreakDays < 100000) {
        ++stats.currentStreakDays;
        cursor = shiftCivilDay(cursor, -1);
    }

    if (history.deltas.empty()) return stats;
    std::vector<TimePoint> times;
    times.reserve(history.deltas.size());
    for (const auto& delta : history.deltas) times.push_back(delta.at);
    std::ranges::sort(times);
    const auto limit = refreshInterval < std::chrono::seconds::zero() ? std::chrono::seconds::zero() : refreshInterval * 2;
    auto start = times.front();
    auto previousTime = start;
    for (std::size_t index = 1; index < times.size(); ++index) {
        if (times[index] - previousTime <= limit) {
            previousTime = times[index];
            continue;
        }
        stats.longestTask = std::max(stats.longestTask, std::chrono::duration_cast<std::chrono::seconds>(previousTime - start));
        start = previousTime = times[index];
    }
    stats.longestTask = std::max(stats.longestTask, std::chrono::duration_cast<std::chrono::seconds>(previousTime - start));
    return stats;
}

ActivityCalendar activityCalendar(const TokenHistory& history, TimePoint now) {
    const CivilDay today = localCivilDay(now);
    const CivilDay earliest = shiftCivilDay(today, -364);
    const CivilDay start = shiftCivilDay(earliest, -sundayIndex(earliest));

    ActivityCalendar calendar;
    std::vector<double> positive;
    CivilDay cursor = start;
    for (int week = 0; week < 54 && cursor <= today; ++week) {
        CalendarWeek column;
        for (int row = 0; row < 7 && cursor <= today; ++row) {
            CalendarCell cell;
            cell.day = cursor;
            cell.tokens = tokensOn(history, cursor);
            if (cell.tokens > 0.0) positive.push_back(cell.tokens);
            column.days[static_cast<std::size_t>(row)] = cell;
            cursor = shiftCivilDay(cursor, 1);
        }
        calendar.weeks.push_back(std::move(column));
    }

    std::ranges::sort(positive);
    for (auto& week : calendar.weeks) {
        for (auto& cell : week.days) {
            if (!cell) continue;
            cell->level = levelFor(cell->tokens, positive);
            calendar.yearTokens += cell->tokens;
        }
    }
    assignMonthLabels(calendar);
    return calendar;
}

std::string formatTaskDuration(std::chrono::seconds duration) {
    if (duration < std::chrono::seconds::zero()) duration = std::chrono::seconds::zero();
    const auto total = duration.count();
    const auto days = total / 86400;
    const auto hours = (total % 86400) / 3600;
    const auto minutes = (total % 3600) / 60;
    const auto seconds = total % 60;
    if (days > 0) {
        if (hours > 0 && minutes > 0) return std::format("{}d {}h {}m", days, hours, minutes);
        if (hours > 0) return std::format("{}d {}h", days, hours);
        if (minutes > 0) return std::format("{}d {}m", days, minutes);
        return std::format("{}d", days);
    }
    if (hours > 0) {
        if (minutes > 0) return std::format("{}h {}m", hours, minutes);
        return std::format("{}h", hours);
    }
    if (minutes > 0) {
        if (seconds > 0) return std::format("{}m {}s", minutes, seconds);
        return std::format("{}m", minutes);
    }
    return std::format("{}s", seconds);
}

std::string serializeTokenHistory(const TokenHistory& history) {
    auto days = history.days;
    std::ranges::sort(days, {}, &DailyTokens::day);
    auto deltas = history.deltas;
    std::ranges::sort(deltas, {}, &TokenDelta::at);
    auto baselines = history.baselines;
    std::ranges::sort(baselines, [](const TokenBaseline& left, const TokenBaseline& right) {
        if (left.providerId != right.providerId) return left.providerId < right.providerId;
        if (left.accountId != right.accountId) return left.accountId < right.accountId;
        return static_cast<int>(left.window) < static_cast<int>(right.window);
    });

    std::string text = "HLHIST1\n";
    for (const auto& day : days) {
        if (!(day.tokens > 0.0) || !std::isfinite(day.tokens)) continue;
        text += "D ";
        text += formatDate(day.day);
        text += ' ';
        text += formatDouble(day.tokens);
        text += '\n';
    }
    for (const auto& delta : deltas) {
        if (!(delta.tokens > 0.0) || !std::isfinite(delta.tokens)) continue;
        text += "T ";
        text += std::to_string(toUnixMilliseconds(delta.at));
        text += ' ';
        text += formatDouble(delta.tokens);
        text += '\n';
    }
    for (const auto& baseline : baselines) {
        if (!parseId(baseline.providerId) || !parseId(baseline.accountId) || !finiteNonNegative(baseline.used)) continue;
        text += "B ";
        text += baseline.providerId;
        text += ' ';
        text += baseline.accountId;
        text += baseline.window == AllowanceWindow::Weekly ? " W " : " S ";
        text += formatDouble(baseline.used);
        text += ' ';
        text += std::to_string(toUnixMilliseconds(baseline.observedAt));
        text += '\n';
    }
    return text;
}

TokenHistory parseTokenHistory(std::string_view text) {
    if (text.empty()) return {};
    TokenHistory history;
    bool header = false;
    bool anyLine = false;
    std::size_t cursor = 0;
    while (cursor <= text.size()) {
        const auto end = text.find('\n', cursor);
        auto line = text.substr(cursor, (end == std::string_view::npos ? text.size() : end) - cursor);
        const bool last = end == std::string_view::npos;
        cursor = last ? text.size() + 1 : end + 1;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) {
            if (last) break;
            return {};
        }
        anyLine = true;
        if (!header) {
            if (line != "HLHIST1") return {};
            header = true;
            if (last) break;
            continue;
        }
        if (line.size() < 3 || line[1] != ' ') return {};
        auto rest = line.substr(2);
        const char kind = line[0];
        if (kind == 'D') {
            const auto date = takeField(rest);
            const auto amount = takeField(rest);
            if (!date || !amount || !rest.empty()) return {};
            DailyTokens day;
            if (!parseDate(*date, day.day) || !parseDouble(*amount, day.tokens) || !(day.tokens > 0.0)) return {};
            history.days.push_back(day);
        } else if (kind == 'T') {
            const auto stamp = takeField(rest);
            const auto amount = takeField(rest);
            if (!stamp || !amount || !rest.empty()) return {};
            long long milliseconds = 0;
            TokenDelta delta;
            if (!parseInt(*stamp, milliseconds) || !parseDouble(*amount, delta.tokens) || !(delta.tokens > 0.0)) return {};
            delta.at = fromUnixMilliseconds(milliseconds);
            history.deltas.push_back(delta);
        } else if (kind == 'B') {
            const auto provider = takeField(rest);
            const auto account = takeField(rest);
            const auto window = takeField(rest);
            const auto used = takeField(rest);
            const auto stamp = takeField(rest);
            if (!provider || !account || !window || !used || !stamp || !rest.empty()) return {};
            if (!parseId(*provider) || !parseId(*account) || (window != "S" && window != "W")) return {};
            TokenBaseline baseline;
            long long milliseconds = 0;
            if (!parseDouble(*used, baseline.used) || !finiteNonNegative(baseline.used) || !parseInt(*stamp, milliseconds)) return {};
            baseline.providerId = std::string{*provider};
            baseline.accountId = std::string{*account};
            baseline.window = *window == "W" ? AllowanceWindow::Weekly : AllowanceWindow::Session;
            baseline.observedAt = fromUnixMilliseconds(milliseconds);
            history.baselines.push_back(std::move(baseline));
        } else {
            return {};
        }
        if (last) break;
    }
    if (!anyLine || !header) return {};

    std::ranges::sort(history.days, {}, &DailyTokens::day);
    for (std::size_t index = 1; index < history.days.size(); ++index) {
        if (history.days[index].day == history.days[index - 1].day) return {};
    }
    std::ranges::sort(history.deltas, {}, &TokenDelta::at);
    std::ranges::sort(history.baselines, [](const TokenBaseline& left, const TokenBaseline& right) {
        if (left.providerId != right.providerId) return left.providerId < right.providerId;
        if (left.accountId != right.accountId) return left.accountId < right.accountId;
        return static_cast<int>(left.window) < static_cast<int>(right.window);
    });
    for (std::size_t index = 1; index < history.baselines.size(); ++index) {
        const auto& previous = history.baselines[index - 1];
        const auto& current = history.baselines[index];
        if (previous.providerId == current.providerId && previous.accountId == current.accountId
            && previous.window == current.window) {
            return {};
        }
    }
    return history;
}

} // namespace hypelimits
