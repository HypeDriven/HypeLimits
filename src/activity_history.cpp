#include "activity_history.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <unordered_map>
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

void addDaily(std::vector<DailyTokens>& days, CivilDay day, double tokens) {
    if (!(tokens > 0.0) || !std::isfinite(tokens)) return;
    const auto it = std::ranges::lower_bound(days, day, {}, &DailyTokens::day);
    if (it != days.end() && it->day == day) it->tokens += tokens;
    else days.insert(it, DailyTokens{day, tokens, {}});
}

bool matchesProvider(std::string_view filter, std::string_view providerId) {
    return filter.empty() || filter == providerId;
}

std::vector<DailyTokens> combinedDailyTotals(const TokenHistory& history, std::string_view providerId) {
    std::vector<DailyTokens> days;
    for (const auto& day : history.days) {
        if (!matchesProvider(providerId, day.providerId)) continue;
        addDaily(days, day.day, day.tokens);
    }
    for (const auto& imported : history.imported) {
        if (!matchesProvider(providerId, imported.providerId)) continue;
        addDaily(days, imported.day, imported.tokens);
    }
    return days;
}

double tokensOn(const TokenHistory& history, CivilDay day, std::string_view providerId) {
    double total = 0.0;
    const auto found = std::ranges::lower_bound(history.days, day, {}, &DailyTokens::day);
    for (auto it = found; it != history.days.end() && it->day == day; ++it) {
        if (!matchesProvider(providerId, it->providerId)) continue;
        total += it->tokens;
    }
    for (const auto& imported : history.imported) {
        if (imported.day != day || !matchesProvider(providerId, imported.providerId)) continue;
        total += imported.tokens;
    }
    return total;
}

void skipJsonString(std::string_view json, std::size_t& index) {
    if (index >= json.size() || json[index] != '"') return;
    ++index;
    while (index < json.size()) {
        if (json[index] == '\\') {
            index += 2;
            continue;
        }
        if (json[index] == '"') {
            ++index;
            return;
        }
        ++index;
    }
}

std::size_t matchingJsonBrace(std::string_view json, std::size_t open) {
    if (open >= json.size() || json[open] != '{') return open;
    int depth = 0;
    for (std::size_t index = open; index < json.size();) {
        const char character = json[index];
        if (character == '"') {
            skipJsonString(json, index);
            continue;
        }
        if (character == '{') ++depth;
        else if (character == '}') {
            --depth;
            if (depth == 0) return index + 1;
        }
        ++index;
    }
    return open;
}

std::optional<double> jsonNumberIn(std::string_view json, std::string_view key) {
    const std::string needle = "\"" + std::string(key) + "\"";
    const auto keyAt = json.find(needle);
    if (keyAt == std::string_view::npos) return std::nullopt;
    auto at = json.find(':', keyAt + needle.size());
    if (at == std::string_view::npos) return std::nullopt;
    ++at;
    while (at < json.size() && (json[at] == ' ' || json[at] == '\t' || json[at] == '\r' || json[at] == '\n')) ++at;
    if (at >= json.size()) return std::nullopt;
    std::string tail(json.substr(at, 64));
    char* end{};
    const double value = std::strtod(tail.c_str(), &end);
    if (end == tail.c_str() || !std::isfinite(value)) return std::nullopt;
    return value;
}

std::string jsonStringIn(std::string_view json, std::string_view key) {
    const std::string needle = "\"" + std::string(key) + "\"";
    const auto keyAt = json.find(needle);
    if (keyAt == std::string_view::npos) return {};
    const auto colon = json.find(':', keyAt + needle.size());
    if (colon == std::string_view::npos) return {};
    const auto first = json.find('"', colon + 1);
    if (first == std::string_view::npos) return {};
    std::size_t index = first;
    skipJsonString(json, index);
    if (index <= first + 1) return {};
    return std::string(json.substr(first + 1, index - first - 2));
}

bool jsonFieldEquals(std::string_view json, std::string_view key, std::string_view expected) {
    const std::string needle = "\"" + std::string(key) + "\"";
    std::size_t from = 0;
    while (from < json.size()) {
        const auto keyAt = json.find(needle, from);
        if (keyAt == std::string_view::npos) return false;
        const auto colon = json.find(':', keyAt + needle.size());
        if (colon == std::string_view::npos) return false;
        auto index = colon + 1;
        while (index < json.size() && std::isspace(static_cast<unsigned char>(json[index]))) ++index;
        if (index >= json.size() || json[index] != '"') {
            from = keyAt + needle.size();
            continue;
        }
        const auto start = index;
        skipJsonString(json, index);
        if (index > start + 1 && json.substr(start + 1, index - start - 2) == expected) return true;
        from = keyAt + needle.size();
    }
    return false;
}

std::optional<std::string_view> jsonObjectContaining(std::string_view json, std::string_view key, std::string_view needle) {
    const std::string quoted = "\"" + std::string(key) + "\"";
    std::size_t from = 0;
    while (from < json.size()) {
        const auto keyAt = json.find(quoted, from);
        if (keyAt == std::string_view::npos) return std::nullopt;
        const auto colon = json.find(':', keyAt + quoted.size());
        if (colon == std::string_view::npos) return std::nullopt;
        auto index = colon + 1;
        while (index < json.size() && std::isspace(static_cast<unsigned char>(json[index]))) ++index;
        if (index >= json.size() || json[index] != '{') {
            from = keyAt + quoted.size();
            continue;
        }
        const auto end = matchingJsonBrace(json, index);
        if (end <= index) return std::nullopt;
        const auto object = json.substr(index, end - index);
        if (object.find(needle) != std::string_view::npos) return object;
        from = end;
    }
    return std::nullopt;
}

std::optional<std::string_view> jsonObjectIn(std::string_view json, std::string_view key) {
    const std::string needle = "\"" + std::string(key) + "\"";
    const auto keyAt = json.find(needle);
    if (keyAt == std::string_view::npos) return std::nullopt;
    const auto colon = json.find(':', keyAt + needle.size());
    if (colon == std::string_view::npos) return std::nullopt;
    const auto open = json.find('{', colon + 1);
    if (open == std::string_view::npos) return std::nullopt;
    const auto end = matchingJsonBrace(json, open);
    if (end <= open) return std::nullopt;
    return json.substr(open, end - open);
}

double tokensInCodexTotals(std::string_view totals) {
    if (const auto reported = jsonNumberIn(totals, "text_total_tokens"); reported && *reported > 0.0) return *reported;
    double tokens = 0.0;
    bool any = false;
    for (const char* key : {"cached_text_input_tokens", "uncached_text_input_tokens", "text_output_tokens"}) {
        const auto value = jsonNumberIn(totals, key);
        if (!value || !std::isfinite(*value) || *value <= 0.0) continue;
        tokens += *value;
        any = true;
    }
    return any ? tokens : 0.0;
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

double positiveSum(std::string_view json, std::initializer_list<const char*> keys) {
    double total = 0.0;
    for (const char* key : keys) {
        const auto value = jsonNumberIn(json, key);
        if (!value || !std::isfinite(*value) || !(*value > 0.0)) continue;
        total += *value;
    }
    return total;
}

void removeDaily(std::vector<DailyTokens>& days, CivilDay day, double tokens) {
    if (!(tokens > 0.0) || !std::isfinite(tokens)) return;
    const auto it = std::ranges::lower_bound(days, day, {}, &DailyTokens::day);
    if (it == days.end() || it->day != day) return;
    it->tokens -= tokens;
    if (!(it->tokens > 0.000001)) days.erase(it);
}

std::optional<TimePoint> timeFromUnix(double value) {
    if (!std::isfinite(value) || value < 1000000000.0) return std::nullopt;
    if (value > 10000000000.0) value /= 1000.0;
    if (value > static_cast<double>(std::numeric_limits<std::int64_t>::max())) return std::nullopt;
    return TimePoint{std::chrono::seconds{static_cast<std::int64_t>(value)}};
}

std::optional<TimePoint> timeFromIso(std::string_view text) {
    if (text.size() < 19 || text[10] != 'T' || text[13] != ':' || text[16] != ':') return std::nullopt;
    CivilDay day;
    long long hour = 0;
    long long minute = 0;
    long long second = 0;
    if (!parseDate(text.substr(0, 10), day) || !parseInt(text.substr(11, 2), hour) || !parseInt(text.substr(14, 2), minute)
        || !parseInt(text.substr(17, 2), second)) {
        return std::nullopt;
    }
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) return std::nullopt;
    std::size_t index = 19;
    if (index < text.size() && text[index] == '.') {
        ++index;
        if (index >= text.size() || !std::isdigit(static_cast<unsigned char>(text[index]))) return std::nullopt;
        while (index < text.size() && std::isdigit(static_cast<unsigned char>(text[index]))) ++index;
    }
    int offsetMinutes = 0;
    if (index < text.size() && (text[index] == 'Z' || text[index] == 'z')) {
        ++index;
    } else if (index < text.size() && (text[index] == '+' || text[index] == '-')) {
        const int sign = text[index] == '-' ? -1 : 1;
        ++index;
        long long offsetHour = 0;
        long long offsetMinute = 0;
        if (index + 5 <= text.size() && text[index + 2] == ':') {
            if (!parseInt(text.substr(index, 2), offsetHour) || !parseInt(text.substr(index + 3, 2), offsetMinute)) return std::nullopt;
            index += 5;
        } else if (index + 4 <= text.size()) {
            if (!parseInt(text.substr(index, 2), offsetHour) || !parseInt(text.substr(index + 2, 2), offsetMinute)) return std::nullopt;
            index += 4;
        } else {
            return std::nullopt;
        }
        if (offsetHour > 23 || offsetMinute > 59) return std::nullopt;
        offsetMinutes = sign * static_cast<int>(offsetHour * 60 + offsetMinute);
    }
    if (index != text.size()) return std::nullopt;
    return TimePoint{toSysDays(day)} + std::chrono::hours{hour} + std::chrono::minutes{minute} + std::chrono::seconds{second}
        - std::chrono::minutes{offsetMinutes};
}

std::optional<TimePoint> timeFromTimestamp(std::string_view json) {
    const auto text = jsonStringIn(json, "timestamp");
    if (!text.empty()) {
        if (const auto parsed = timeFromIso(text)) return parsed;
    }
    if (const auto stamp = jsonNumberIn(json, "timestamp")) {
        if (const auto parsed = timeFromUnix(*stamp)) return parsed;
    }
    if (const auto stamp = jsonNumberIn(json, "time")) return timeFromUnix(*stamp);
    return std::nullopt;
}

struct SeenUse {
    double tokens{0};
    CivilDay day{};
};

void noteOnce(std::vector<DailyTokens>& days, std::unordered_map<std::string, SeenUse>& seen, const std::string& key,
              CivilDay day, double tokens) {
    if (!(tokens > 0.0) || !std::isfinite(tokens)) return;
    const auto [it, inserted] = seen.try_emplace(key, SeenUse{tokens, day});
    if (inserted) {
        addDaily(days, day, tokens);
        return;
    }
    if (tokens <= it->second.tokens) return;
    removeDaily(days, it->second.day, it->second.tokens);
    addDaily(days, day, tokens);
    it->second = SeenUse{tokens, day};
}

bool knownSessionProvider(std::string_view providerId) {
    return providerId == "anthropic" || providerId == "xai" || providerId == "moonshot";
}

void consumeSessionLogLine(std::vector<DailyTokens>& days, std::unordered_map<std::string, SeenUse>& seen, std::string_view line) {
    if (jsonFieldEquals(line, "sessionUpdate", "turn_completed")) {
        const auto usage = jsonObjectContaining(line, "usage", "\"totalTokens\"");
        const auto body = usage ? *usage : jsonObjectContaining(line, "usage", "\"inputTokens\"").value_or(std::string_view{});
        if (body.empty()) return;
        const auto when = timeFromTimestamp(line);
        if (!when) return;
        double tokens = 0.0;
        if (const auto total = jsonNumberIn(body, "totalTokens"); total && *total > 0.0) tokens = *total;
        else tokens = positiveSum(body, {"inputTokens", "outputTokens"});
        auto prompt = jsonStringIn(line, "prompt_id");
        if (prompt.empty()) prompt = jsonStringIn(line, "promptId");
        if (prompt.empty()) prompt = "#" + std::to_string(seen.size()) + ":" + std::to_string(static_cast<long long>(tokens));
        noteOnce(days, seen, "g:" + prompt, localCivilDay(*when), tokens);
        return;
    }

    if (jsonFieldEquals(line, "type", "usage.record")) {
        const auto scope = jsonStringIn(line, "usageScope");
        if (!scope.empty() && scope != "turn") return;
        const auto usage = jsonObjectContaining(line, "usage", "\"inputOther\"");
        const auto body = usage ? *usage : jsonObjectContaining(line, "usage", "\"output\"").value_or(std::string_view{});
        if (body.empty()) return;
        const auto when = timeFromTimestamp(line);
        if (!when) return;
        const double tokens = positiveSum(body, {"inputOther", "output", "inputCacheRead", "inputCacheCreation"});
        if (tokens > 0.0) addDaily(days, localCivilDay(*when), tokens);
        return;
    }

    if (!jsonFieldEquals(line, "type", "assistant") || line.find("\"input_tokens\"") == std::string_view::npos) return;
    const auto usage = jsonObjectContaining(line, "usage", "\"input_tokens\"");
    if (!usage) return;
    const auto when = timeFromTimestamp(line);
    if (!when) return;
    const double tokens = positiveSum(*usage, {"input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens"});
    auto request = jsonStringIn(line, "requestId");
    if (request.empty()) request = "#" + std::to_string(seen.size()) + ":" + std::to_string(static_cast<long long>(tokens));
    noteOnce(days, seen, "c:" + request, localCivilDay(*when), tokens);
}

std::vector<DailyTokens> parseSessionLogStream(std::istream& input) {
    std::vector<DailyTokens> days;
    std::unordered_map<std::string, SeenUse> seen;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() > 64 * 1024 * 1024) continue;
        if (line.find("\"input_tokens\"") == std::string::npos && line.find("turn_completed") == std::string::npos
            && line.find("usage.record") == std::string::npos) {
            continue;
        }
        consumeSessionLogLine(days, seen, line);
    }
    return days;
}

std::string pathKey(const std::filesystem::path& path) {
    const auto normal = path.lexically_normal().generic_u8string();
    return std::string(normal.begin(), normal.end());
}

bool underHome(std::string_view path, std::string_view home) {
    return path.size() > home.size() && path.starts_with(home) && path[home.size()] == '/';
}

std::int64_t modifiedStamp(const std::filesystem::file_time_type& time) {
    return static_cast<std::int64_t>(time.time_since_epoch().count());
}

const char* providerForSessionFile(const std::filesystem::path& home, const std::filesystem::path& file) {
    const auto key = pathKey(file);
    const auto root = pathKey(home);
    const std::string claude = root + "/.claude/projects/";
    const std::string grok = root + "/.grok/sessions/";
    const std::string kimi = root + "/.kimi-code/sessions/";
    const auto name = file.filename().generic_u8string();
    const std::string filename(name.begin(), name.end());
    if (key.starts_with(claude) && filename.ends_with(".jsonl")) return "anthropic";
    if (key.starts_with(grok) && filename == "updates.jsonl") return "xai";
    if (key.starts_with(kimi) && filename == "wire.jsonl") return "moonshot";
    return nullptr;
}

bool walkListed(const std::filesystem::path& root, const auto& visit) {
    std::error_code error;
    const bool directory = std::filesystem::is_directory(root, error);
    if (error) return false;
    if (!directory) return true;
    std::filesystem::recursive_directory_iterator it(root, std::filesystem::directory_options::skip_permission_denied, error);
    if (error) return false;
    const std::filesystem::recursive_directory_iterator end;
    while (it != end) {
        error.clear();
        if (it->is_regular_file(error) && !error) visit(it->path());
        error.clear();
        it.increment(error);
        if (error) return false;
    }
    return true;
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
        auto match = dayIt;
        while (match != history.days.end() && match->day == day && match->providerId != observation.providerId) ++match;
        if (match != history.days.end() && match->day == day) match->tokens += delta;
        else {
            auto insertAt = dayIt;
            while (insertAt != history.days.end() && insertAt->day == day && insertAt->providerId < observation.providerId) ++insertAt;
            history.days.insert(insertAt, DailyTokens{day, delta, observation.providerId});
        }
        const auto deltaIt = std::ranges::upper_bound(history.deltas, observation.observedAt, {}, &TokenDelta::at);
        history.deltas.insert(deltaIt, TokenDelta{observation.observedAt, delta, observation.providerId});
        changed = true;
    }
    return changed;
}

std::optional<std::vector<DailyTokens>> parseCodexDailyTokens(std::string_view json) {
    const auto dataKey = json.find("\"data\"");
    if (dataKey == std::string_view::npos) return std::nullopt;
    const auto colon = json.find(':', dataKey + 6);
    if (colon == std::string_view::npos) return std::nullopt;
    std::size_t at = colon + 1;
    while (at < json.size() && (json[at] == ' ' || json[at] == '\t' || json[at] == '\r' || json[at] == '\n')) ++at;
    if (at >= json.size() || json[at] != '[') return std::nullopt;

    std::vector<DailyTokens> days;
    int depth = 1;
    for (std::size_t index = at + 1; index < json.size() && depth > 0;) {
        const char character = json[index];
        if (character == '"') {
            skipJsonString(json, index);
            continue;
        }
        if (character == '[') {
            ++depth;
            ++index;
            continue;
        }
        if (character == ']') {
            --depth;
            ++index;
            continue;
        }
        if (character == '{' && depth == 1) {
            const auto end = matchingJsonBrace(json, index);
            if (end <= index) break;
            const auto row = json.substr(index, end - index);
            CivilDay day;
            const auto totals = jsonObjectIn(row, "totals");
            if (parseDate(jsonStringIn(row, "date"), day) && totals) addDaily(days, day, tokensInCodexTotals(*totals));
            index = end;
            continue;
        }
        ++index;
    }
    return days;
}

std::vector<DailyTokens> parseSessionLogTokens(std::string_view jsonl) {
    std::istringstream input{std::string(jsonl)};
    return parseSessionLogStream(input);
}

SessionLogScan refreshSessionLogCache(SessionLogCache& cache, const std::filesystem::path& home) {
    std::error_code error;
    if (!std::filesystem::is_directory(home, error) || error) return SessionLogScan::Unavailable;
    const auto homeKey = pathKey(home);
    if (homeKey.empty()) return SessionLogScan::Unavailable;

    struct Root {
        const char* provider;
        std::filesystem::path path;
    };
    const Root roots[] = {
        {"anthropic", home / ".claude" / "projects"},
        {"xai", home / ".grok" / "sessions"},
        {"moonshot", home / ".kimi-code" / "sessions"},
    };

    std::unordered_map<std::string, SessionLogCacheEntry> kept;
    kept.reserve(cache.entries.size());
    for (auto& entry : cache.entries) kept.emplace(entry.path, std::move(entry));

    bool changed = false;
    for (const auto& root : roots) {
        std::unordered_map<std::string, bool> live;
        const bool listed = walkListed(root.path, [&](const std::filesystem::path& file) {
            const char* provider = providerForSessionFile(home, file);
            if (provider == nullptr || std::string_view{provider} != root.provider) return;
            error.clear();
            const auto size = std::filesystem::file_size(file, error);
            if (error) return;
            error.clear();
            const auto modified = std::filesystem::last_write_time(file, error);
            if (error) return;
            const auto key = pathKey(file);
            const auto stamp = modifiedStamp(modified);
            live.emplace(key, true);
            const auto found = kept.find(key);
            if (found != kept.end() && found->second.providerId == root.provider && found->second.modified == stamp
                && found->second.size == size) {
                return;
            }
            std::ifstream input(file, std::ios::binary);
            if (!input) return;
            SessionLogCacheEntry entry;
            entry.providerId = root.provider;
            entry.path = key;
            entry.modified = stamp;
            entry.size = static_cast<std::uint64_t>(size);
            entry.days = parseSessionLogStream(input);
            if (!input.eof() && input.fail()) return;
            if (found == kept.end()) kept.emplace(key, std::move(entry));
            else found->second = std::move(entry);
            changed = true;
        });
        if (!listed) continue;
        for (auto it = kept.begin(); it != kept.end();) {
            if (it->second.providerId == root.provider && underHome(it->first, homeKey) && !live.contains(it->first)) {
                it = kept.erase(it);
                changed = true;
            } else {
                ++it;
            }
        }
    }

    cache.entries.clear();
    cache.entries.reserve(kept.size());
    for (auto& [path, entry] : kept) {
        (void)path;
        cache.entries.push_back(std::move(entry));
    }
    std::ranges::sort(cache.entries, [](const SessionLogCacheEntry& left, const SessionLogCacheEntry& right) {
        return left.path < right.path;
    });
    return changed ? SessionLogScan::Updated : SessionLogScan::Unchanged;
}

std::vector<LocalSessionImport> sessionLogImports(const SessionLogCache& cache) {
    std::vector<LocalSessionImport> imports;
    for (const char* provider : {"anthropic", "xai", "moonshot"}) {
        LocalSessionImport import;
        import.providerId = provider;
        for (const auto& entry : cache.entries) {
            if (entry.providerId != provider) continue;
            for (const auto& day : entry.days) addDaily(import.days, day.day, day.tokens);
        }
        imports.push_back(std::move(import));
    }
    return imports;
}

std::string serializeSessionLogCache(const SessionLogCache& cache) {
    std::string text = "HLSL1\n";
    for (const auto& entry : cache.entries) {
        if (!knownSessionProvider(entry.providerId) || entry.path.empty() || entry.path.find('\n') != std::string::npos) continue;
        text += "E ";
        text += entry.providerId;
        text += ' ';
        text += std::to_string(entry.modified);
        text += ' ';
        text += std::to_string(entry.size);
        text += ' ';
        text += std::to_string(entry.days.size());
        text += '\n';
        text += entry.path;
        text += '\n';
        for (const auto& day : entry.days) {
            text += formatDate(day.day);
            text += ' ';
            text += formatDouble(day.tokens);
            text += '\n';
        }
    }
    return text;
}

SessionLogCache parseSessionLogCache(std::string_view text) {
    SessionLogCache cache;
    std::size_t lineStart = 0;
    auto nextLine = [&](std::string_view& line) {
        if (lineStart > text.size()) return false;
        const auto end = text.find('\n', lineStart);
        line = text.substr(lineStart, end == std::string_view::npos ? std::string_view::npos : end - lineStart);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        lineStart = end == std::string_view::npos ? text.size() + 1 : end + 1;
        return true;
    };
    std::string_view line;
    if (!nextLine(line) || line != "HLSL1") return {};
    std::set<std::string> paths;
    while (nextLine(line)) {
        if (line.empty()) continue;
        if (!line.starts_with("E ")) return {};
        std::string_view rest = line.substr(2);
        const auto providerField = takeField(rest);
        const auto modifiedField = takeField(rest);
        const auto sizeField = takeField(rest);
        const auto countField = takeField(rest);
        if (!providerField || !modifiedField || !sizeField || !countField || !rest.empty()) return {};
        if (!knownSessionProvider(*providerField)) return {};
        long long modified = 0;
        unsigned long long size = 0;
        unsigned long long count = 0;
        if (!parseInt(*modifiedField, modified)) return {};
        {
            const auto parsed = std::from_chars(sizeField->data(), sizeField->data() + sizeField->size(), size);
            if (parsed.ec != std::errc{} || parsed.ptr != sizeField->data() + sizeField->size()) return {};
        }
        {
            const auto parsed = std::from_chars(countField->data(), countField->data() + countField->size(), count);
            if (parsed.ec != std::errc{} || parsed.ptr != countField->data() + countField->size()) return {};
        }
        if (count > 100000) return {};
        if (!nextLine(line) || line.empty() || line.find('\r') != std::string_view::npos) return {};
        SessionLogCacheEntry entry;
        entry.providerId = std::string(*providerField);
        entry.path = std::string(line);
        entry.modified = modified;
        entry.size = size;
        if (!paths.insert(entry.path).second) return {};
        entry.days.reserve(static_cast<std::size_t>(count));
        for (unsigned long long index = 0; index < count; ++index) {
            if (!nextLine(line)) return {};
            const auto space = line.find(' ');
            if (space == std::string_view::npos) return {};
            CivilDay day;
            double tokens = 0.0;
            if (!parseDate(line.substr(0, space), day) || !parseDouble(line.substr(space + 1), tokens) || !(tokens > 0.0)) return {};
            entry.days.push_back(DailyTokens{day, tokens, {}});
        }
        cache.entries.push_back(std::move(entry));
    }
    return cache;
}

bool storeSessionLogCache(const SessionLogCache& cache, const std::filesystem::path& path) {
    std::error_code error;
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path(), error);
    std::filesystem::path temporary = path;
    temporary += ".tmp";
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) return false;
        const auto text = serializeSessionLogCache(cache);
        output.write(text.data(), static_cast<std::streamsize>(text.size()));
        if (!output) {
            std::filesystem::remove(temporary, error);
            return false;
        }
    }
    error.clear();
    std::filesystem::rename(temporary, path, error);
    if (error) {
        error.clear();
        std::filesystem::remove(path, error);
        error.clear();
        std::filesystem::rename(temporary, path, error);
    }
    if (error) std::filesystem::remove(temporary, error);
    return !error;
}

SessionLogCache loadSessionLogCache(const std::filesystem::path& path) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error || size > 16 * 1024 * 1024) return {};
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    std::ostringstream buffer;
    buffer << input.rdbuf();
    if (!input && !input.eof()) return {};
    return parseSessionLogCache(buffer.str());
}

bool replaceImportedDailyTokens(TokenHistory& history, std::string_view providerId, std::string_view accountId,
                                std::span<const DailyTokens> days) {
    if (!parseId(providerId) || !parseId(accountId)) return false;
    std::vector<DailyTokens> incoming;
    for (const auto& day : days) addDaily(incoming, day.day, day.tokens);

    const auto sameAccount = [&](const ImportedDailyTokens& row) {
        return row.providerId == providerId && row.accountId == accountId;
    };
    std::vector<DailyTokens> previous;
    for (const auto& row : history.imported) {
        if (sameAccount(row)) addDaily(previous, row.day, row.tokens);
    }
    bool changed = previous.size() != incoming.size();
    if (!changed) {
        for (std::size_t index = 0; index < previous.size(); ++index) {
            if (previous[index].day != incoming[index].day || std::abs(previous[index].tokens - incoming[index].tokens) > 0.000001) {
                changed = true;
                break;
            }
        }
    }
    if (!changed) return false;

    std::erase_if(history.imported, sameAccount);
    history.imported.reserve(history.imported.size() + incoming.size());
    for (const auto& day : incoming) {
        history.imported.push_back(ImportedDailyTokens{std::string(providerId), std::string(accountId), day.day, day.tokens});
    }
    std::ranges::sort(history.imported, [](const ImportedDailyTokens& left, const ImportedDailyTokens& right) {
        if (left.providerId != right.providerId) return left.providerId < right.providerId;
        if (left.accountId != right.accountId) return left.accountId < right.accountId;
        return left.day < right.day;
    });
    return true;
}

ActivityStats activityStats(const TokenHistory& history, TimePoint now, std::string_view providerId) {
    ActivityStats stats;
    int run = 0;
    bool inRun = false;
    CivilDay previous{};
    const auto days = combinedDailyTotals(history, providerId);
    for (const auto& day : days) {
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
    CivilDay cursor = tokensOn(history, today, providerId) > 0.0 ? today : shiftCivilDay(today, -1);
    while (tokensOn(history, cursor, providerId) > 0.0 && stats.currentStreakDays < 100000) {
        ++stats.currentStreakDays;
        cursor = shiftCivilDay(cursor, -1);
    }

    return stats;
}

ActivityCalendar activityCalendar(const TokenHistory& history, TimePoint now, std::string_view providerId) {
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
            cell.tokens = tokensOn(history, cursor, providerId);
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

std::string serializeTokenHistory(const TokenHistory& history) {
    auto days = history.days;
    std::ranges::sort(days, [](const DailyTokens& left, const DailyTokens& right) {
        if (left.day != right.day) return left.day < right.day;
        return left.providerId < right.providerId;
    });
    auto deltas = history.deltas;
    std::ranges::sort(deltas, [](const TokenDelta& left, const TokenDelta& right) {
        if (left.at != right.at) return left.at < right.at;
        return left.providerId < right.providerId;
    });
    auto baselines = history.baselines;
    std::ranges::sort(baselines, [](const TokenBaseline& left, const TokenBaseline& right) {
        if (left.providerId != right.providerId) return left.providerId < right.providerId;
        if (left.accountId != right.accountId) return left.accountId < right.accountId;
        return static_cast<int>(left.window) < static_cast<int>(right.window);
    });
    auto imported = history.imported;
    std::ranges::sort(imported, [](const ImportedDailyTokens& left, const ImportedDailyTokens& right) {
        if (left.providerId != right.providerId) return left.providerId < right.providerId;
        if (left.accountId != right.accountId) return left.accountId < right.accountId;
        return left.day < right.day;
    });

    std::string text = "HLHIST1\n";
    for (const auto& day : days) {
        if (!(day.tokens > 0.0) || !std::isfinite(day.tokens)) continue;
        if (!day.providerId.empty() && !parseId(day.providerId)) continue;
        text += "D ";
        text += formatDate(day.day);
        text += ' ';
        text += formatDouble(day.tokens);
        if (!day.providerId.empty()) {
            text += ' ';
            text += day.providerId;
        }
        text += '\n';
    }
    for (const auto& delta : deltas) {
        if (!(delta.tokens > 0.0) || !std::isfinite(delta.tokens)) continue;
        if (!delta.providerId.empty() && !parseId(delta.providerId)) continue;
        text += "T ";
        text += std::to_string(toUnixMilliseconds(delta.at));
        text += ' ';
        text += formatDouble(delta.tokens);
        if (!delta.providerId.empty()) {
            text += ' ';
            text += delta.providerId;
        }
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
    for (const auto& row : imported) {
        if (!parseId(row.providerId) || !parseId(row.accountId) || !(row.tokens > 0.0) || !std::isfinite(row.tokens)) continue;
        text += "I ";
        text += row.providerId;
        text += ' ';
        text += row.accountId;
        text += ' ';
        text += formatDate(row.day);
        text += ' ';
        text += formatDouble(row.tokens);
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
            if (!date || !amount) return {};
            std::optional<std::string_view> provider;
            if (!rest.empty()) {
                provider = takeField(rest);
                if (!provider || !rest.empty() || !parseId(*provider)) return {};
            }
            DailyTokens day;
            if (!parseDate(*date, day.day) || !parseDouble(*amount, day.tokens) || !(day.tokens > 0.0)) return {};
            if (provider) day.providerId = std::string{*provider};
            history.days.push_back(day);
        } else if (kind == 'T') {
            const auto stamp = takeField(rest);
            const auto amount = takeField(rest);
            if (!stamp || !amount) return {};
            std::optional<std::string_view> provider;
            if (!rest.empty()) {
                provider = takeField(rest);
                if (!provider || !rest.empty() || !parseId(*provider)) return {};
            }
            long long milliseconds = 0;
            TokenDelta delta;
            if (!parseInt(*stamp, milliseconds) || !parseDouble(*amount, delta.tokens) || !(delta.tokens > 0.0)) return {};
            delta.at = fromUnixMilliseconds(milliseconds);
            if (provider) delta.providerId = std::string{*provider};
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
        } else if (kind == 'I') {
            const auto provider = takeField(rest);
            const auto account = takeField(rest);
            const auto date = takeField(rest);
            const auto amount = takeField(rest);
            if (!provider || !account || !date || !amount || !rest.empty()) return {};
            if (!parseId(*provider) || !parseId(*account)) return {};
            ImportedDailyTokens row;
            if (!parseDate(*date, row.day) || !parseDouble(*amount, row.tokens) || !(row.tokens > 0.0)) return {};
            row.providerId = std::string{*provider};
            row.accountId = std::string{*account};
            history.imported.push_back(std::move(row));
        } else {
            return {};
        }
        if (last) break;
    }
    if (!anyLine || !header) return {};

    std::ranges::sort(history.days, [](const DailyTokens& left, const DailyTokens& right) {
        if (left.day != right.day) return left.day < right.day;
        return left.providerId < right.providerId;
    });
    for (std::size_t index = 1; index < history.days.size(); ++index) {
        if (history.days[index].day == history.days[index - 1].day
            && history.days[index].providerId == history.days[index - 1].providerId) {
            return {};
        }
    }
    std::ranges::sort(history.deltas, [](const TokenDelta& left, const TokenDelta& right) {
        if (left.at != right.at) return left.at < right.at;
        return left.providerId < right.providerId;
    });
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
    std::ranges::sort(history.imported, [](const ImportedDailyTokens& left, const ImportedDailyTokens& right) {
        if (left.providerId != right.providerId) return left.providerId < right.providerId;
        if (left.accountId != right.accountId) return left.accountId < right.accountId;
        return left.day < right.day;
    });
    for (std::size_t index = 1; index < history.imported.size(); ++index) {
        const auto& previous = history.imported[index - 1];
        const auto& current = history.imported[index];
        if (previous.providerId == current.providerId && previous.accountId == current.accountId && previous.day == current.day) {
            return {};
        }
    }
    return history;
}

} // namespace hypelimits
