#include "provider_parsing.hpp"

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>

namespace hypelimits {
namespace {

std::optional<double> numberAt(std::string_view json, std::string_view key, std::size_t start) {
    const std::string needle = "\"" + std::string(key) + "\"";
    const auto keyAt = json.find(needle, start);
    if (keyAt == std::string_view::npos) return std::nullopt;
    auto at = json.find(':', keyAt + needle.size());
    if (at == std::string_view::npos) return std::nullopt;
    ++at;
    while (at < json.size() && (json[at] == ' ' || json[at] == '\t' || json[at] == '\r' || json[at] == '\n' || json[at] == '"')) ++at;
    std::string tail(json.substr(at, 64));
    char* end{};
    const double value = std::strtod(tail.c_str(), &end);
    if (end == tail.c_str() || !std::isfinite(value)) return std::nullopt;
    return value;
}

std::optional<double> objectNumber(std::string_view json, std::string_view key, std::size_t start) {
    const std::string needle = "\"" + std::string(key) + "\"";
    const auto keyAt = json.find(needle, start);
    if (keyAt == std::string_view::npos) return std::nullopt;
    if (const auto direct = numberAt(json, key, keyAt)) return direct;
    return numberAt(json, "val", keyAt);
}

std::string stringAt(std::string_view json, std::string_view key, std::size_t start) {
    const std::string needle = "\"" + std::string(key) + "\"";
    const auto keyAt = json.find(needle, start);
    if (keyAt == std::string_view::npos) return {};
    const auto colon = json.find(':', keyAt + needle.size());
    if (colon == std::string_view::npos) return {};
    const auto first = json.find('"', colon + 1);
    if (first == std::string_view::npos) return {};
    const auto last = json.find('"', first + 1);
    if (last == std::string_view::npos) return {};
    return std::string(json.substr(first + 1, last - first - 1));
}

bool looksLikeUnix(std::string_view value) {
    if (value.empty()) return false;
    std::size_t i = 0;
    if (value[0] == '-') return false;
    for (; i < value.size(); ++i) {
        if (value[i] < '0' || value[i] > '9') return false;
    }
    return i >= 9;
}

TimePoint fromUtcTm(std::tm utc) {
#ifdef _WIN32
    const std::time_t raw = _mkgmtime(&utc);
#else
    const std::time_t raw = timegm(&utc);
#endif
    if (raw == static_cast<std::time_t>(-1)) return {};
    return std::chrono::system_clock::from_time_t(raw);
}

UsageWindow percentWindow(double usedPercent, std::optional<TimePoint> reset) {
    usedPercent = std::clamp(usedPercent, 0.0, 100.0);
    return UsageWindow{usedPercent, 100.0, "%", reset};
}

std::optional<UsageWindow> windowFromObject(std::string_view json, std::size_t start, std::size_t span = 480) {
    const auto slice = json.substr(start, std::min(span, json.size() - start));
    std::optional<double> used = numberAt(slice, "used_percent", 0);
    if (!used) used = numberAt(slice, "utilization", 0);
    if (!used) used = numberAt(slice, "percent", 0);
    if (!used) used = numberAt(slice, "used", 0);
    std::optional<double> capacity = numberAt(slice, "limit", 0);
    if (!capacity) capacity = numberAt(slice, "capacity", 0);
    if (!used || *used < 0.0) return std::nullopt;
    auto reset = parseTimestamp(stringAt(slice, "resets_at", 0));
    if (!reset) reset = parseTimestamp(stringAt(slice, "reset_at", 0));
    if (!reset) reset = parseTimestamp(stringAt(slice, "resetTime", 0));
    if (!reset) {
        if (const auto unix = numberAt(slice, "reset_at", 0)) reset = parseTimestamp(std::to_string(static_cast<long long>(*unix)));
    }
    if (capacity && *capacity > 0.0 && *used <= *capacity * 2.0 && *capacity != 100.0) {
        return UsageWindow{*used, *capacity, "requests", reset};
    }
    return percentWindow(*used, reset);
}

} // namespace

std::optional<std::string> jsonString(std::string_view json, std::string_view key, std::size_t start) {
    auto value = stringAt(json, key, start);
    if (value.empty()) return std::nullopt;
    return value;
}

std::optional<double> jsonNumber(std::string_view json, std::string_view key, std::size_t start) {
    return numberAt(json, key, start);
}

std::optional<TimePoint> parseTimestamp(std::string_view value) {
    if (value.empty()) return std::nullopt;
    if (looksLikeUnix(value)) {
        const auto seconds = std::strtoll(std::string(value).c_str(), nullptr, 10);
        if (seconds <= 0) return std::nullopt;
        return TimePoint{std::chrono::seconds{seconds}};
    }
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (std::sscanf(std::string(value).c_str(), "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second) < 3) { // NOLINT
        return std::nullopt;
    }
    std::tm utc{};
    utc.tm_year = year - 1900;
    utc.tm_mon = month - 1;
    utc.tm_mday = day;
    utc.tm_hour = hour;
    utc.tm_min = minute;
    utc.tm_sec = second;
    utc.tm_isdst = 0;
    const auto point = fromUtcTm(utc);
    if (point.time_since_epoch().count() == 0 && year > 1970) return std::nullopt;
    return point;
}

std::optional<BalanceValue> parseMoonshotBalance(std::string_view json) {
    const auto value = numberAt(json, "available_balance", 0);
    if (!value) return std::nullopt;
    return BalanceValue{*value, "$", std::nullopt, std::nullopt};
}

std::optional<BalanceValue> parseDeepSeekBalance(std::string_view json) {
    std::optional<BalanceValue> fallback;
    std::size_t position = 0;
    while ((position = json.find("\"currency\"", position)) != std::string_view::npos) {
        const std::string currency = stringAt(json, "currency", position);
        const auto amount = numberAt(json, "topped_up_balance", position);
        if (amount && !currency.empty()) {
            BalanceValue value{*amount, currency == "USD" ? "$" : currency + " ", std::nullopt, std::nullopt};
            if (currency == "USD") return value;
            if (!fallback) fallback = value;
        }
        ++position;
    }
    return fallback;
}

std::optional<BalanceValue> parseXaiPrepaidBalance(std::string_view json) {
    const auto totalAt = json.find("\"total\"");
    if (totalAt == std::string_view::npos) return std::nullopt;
    auto amount = numberAt(json, "val", totalAt);
    if (!amount) amount = numberAt(json, "total", 0);
    if (!amount) return std::nullopt;
    return BalanceValue{std::abs(*amount) / 100.0, "$", std::nullopt, std::nullopt};
}

std::optional<ProviderUsage> parseClaudeUsage(std::string_view json) {
    ProviderUsage usage;
    if (const auto five = json.find("\"five_hour\""); five != std::string_view::npos) {
        if (const auto window = windowFromObject(json, five)) usage.session = window;
    }
    if (const auto seven = json.find("\"seven_day\""); seven != std::string_view::npos) {
        if (json.compare(seven, 16, "\"seven_day_sonnet") != 0 && json.compare(seven, 14, "\"seven_day_opus") != 0) {
            if (const auto window = windowFromObject(json, seven)) usage.weekly = window;
        }
    }
    std::size_t kindAt = 0;
    while ((kindAt = json.find("\"kind\"", kindAt)) != std::string_view::npos) {
        const auto kind = stringAt(json, "kind", kindAt);
        const auto objectStart = json.rfind('{', kindAt);
        const auto window = windowFromObject(json, objectStart == std::string_view::npos ? kindAt : objectStart, 560);
        if (window) {
            if (kind == "session" && !usage.session) usage.session = window;
            if ((kind == "weekly_all" || kind == "weekly") && !usage.weekly) usage.weekly = window;
        }
        ++kindAt;
    }
    if (const auto extra = json.find("\"extra_usage\""); extra != std::string_view::npos) {
        const auto used = numberAt(json, "used_credits", extra);
        auto limit = numberAt(json, "monthly_limit", extra);
        if (used && limit && *limit > 0.0) {
            double scale = *limit >= 1000.0 ? 100.0 : 1.0;
            const double remaining = std::max(0.0, (*limit - *used) / scale);
            usage.credit = BalanceValue{remaining, "$", *used / scale, *limit / scale};
        }
    }
    if (!usage.session && !usage.weekly && !usage.credit) return std::nullopt;
    return usage;
}

std::optional<ProviderUsage> parseCodexUsage(std::string_view json) {
    ProviderUsage usage;
    const auto rate = json.find("\"rate_limit\"");
    if (rate == std::string_view::npos && json.find("\"primary_window\"") == std::string_view::npos) {
        if (json.find("\"credits\"") == std::string_view::npos) return std::nullopt;
    }
    auto assignWindow = [&](std::string_view key, bool preferSession) {
        const auto at = json.find("\"" + std::string(key) + "\"");
        if (at == std::string_view::npos) return;
        const auto window = windowFromObject(json, at);
        if (!window) return;
        const auto seconds = numberAt(json.substr(at, 400), "limit_window_seconds", 0);
        const bool session = seconds ? *seconds <= 12 * 3600 : preferSession;
        if (session) usage.session = window;
        else usage.weekly = window;
    };
    assignWindow("primary_window", true);
    assignWindow("secondary_window", false);
    if (const auto credits = json.find("\"credits\""); credits != std::string_view::npos) {
        if (const auto balance = numberAt(json, "balance", credits)) {
            usage.credit = BalanceValue{*balance, "$", std::nullopt, std::nullopt};
        }
    }
    if (!usage.session && !usage.weekly && !usage.credit) return std::nullopt;
    return usage;
}

std::optional<ProviderUsage> parseGrokBilling(std::string_view json) {
    ProviderUsage usage;
    const auto configAt = json.find("\"config\"");
    const std::size_t start = configAt == std::string_view::npos ? 0 : configAt;
    auto used = objectNumber(json, "creditUsagePercent", start);
    auto reset = parseTimestamp(stringAt(json, "billingPeriodEnd", start));
    if (!reset) reset = parseTimestamp(stringAt(json, "end", start));
    if (used && *used >= 0.0) {
        usage.weekly = percentWindow(*used, reset);
    } else {
        const auto consumed = objectNumber(json, "used", start);
        const auto limit = objectNumber(json, "monthlyLimit", start);
        if (consumed && limit && *limit > 0.0) {
            usage.weekly = UsageWindow{*consumed, *limit, "credits", reset};
        } else {
            const auto onDemandUsed = objectNumber(json, "onDemandUsed", start);
            const auto onDemandCap = objectNumber(json, "onDemandCap", start);
            if (onDemandUsed && onDemandCap && *onDemandCap > 0.0) {
                usage.credit = BalanceValue{std::max(0.0, *onDemandCap - *onDemandUsed), "$", std::nullopt, std::nullopt};
            }
        }
    }
    if (!usage.session && !usage.weekly && !usage.credit) return std::nullopt;
    return usage;
}

std::optional<ProviderUsage> parseKimiCodingUsage(std::string_view json) {
    ProviderUsage usage;
    const auto usageAt = json.find("\"usage\"");
    if (usageAt != std::string_view::npos) {
        const auto used = numberAt(json, "used", usageAt);
        const auto limit = numberAt(json, "limit", usageAt);
        const auto remaining = numberAt(json, "remaining", usageAt);
        auto reset = parseTimestamp(stringAt(json, "resetTime", usageAt));
        if (used && limit && *limit > 0.0) {
            usage.weekly = UsageWindow{*used, *limit, "requests", reset};
        } else if (remaining && limit && *limit > 0.0) {
            usage.weekly = UsageWindow{*limit - *remaining, *limit, "requests", reset};
        }
    }
    std::size_t windowAt = 0;
    while ((windowAt = json.find("\"window\"", windowAt)) != std::string_view::npos) {
        const auto duration = numberAt(json, "duration", windowAt);
        const auto detailAt = json.find("\"detail\"", windowAt);
        const auto window = windowFromObject(json, detailAt == std::string_view::npos ? windowAt : detailAt);
        if (window && duration) {
            if (*duration <= 12 * 60) usage.session = window;
            else if (!usage.weekly) usage.weekly = window;
        }
        ++windowAt;
    }
    if (!usage.session && !usage.weekly && !usage.credit) return std::nullopt;
    return usage;
}

std::optional<ProviderUsage> parseAntigravityAssist(std::string_view json) {
    ProviderUsage usage;
    const auto available = numberAt(json, "availablePromptCredits", 0);
    const auto monthly = numberAt(json, "monthlyPromptCredits", 0);
    if (available && monthly && *monthly > 0.0) {
        usage.weekly = UsageWindow{*monthly - *available, *monthly, "credits", std::nullopt};
    } else if (available) {
        usage.credit = BalanceValue{*available, "$", std::nullopt, std::nullopt};
    }
    if (!usage.session && !usage.weekly && !usage.credit) return std::nullopt;
    return usage;
}

std::optional<ProviderUsage> parseAntigravityModels(std::string_view json) {
    ProviderUsage usage;
    std::optional<double> lowestRemaining;
    std::optional<TimePoint> reset;
    std::size_t pos = 0;
    while ((pos = json.find("\"remainingFraction\"", pos)) != std::string_view::npos) {
        const auto remaining = numberAt(json, "remainingFraction", pos);
        if (remaining) {
            if (!lowestRemaining || *remaining < *lowestRemaining) {
                lowestRemaining = remaining;
                reset = parseTimestamp(stringAt(json, "resetTime", pos));
            }
        }
        ++pos;
    }
    if (!lowestRemaining) return std::nullopt;
    const double remainingPercent = std::clamp(*lowestRemaining, 0.0, 1.0) * 100.0;
    usage.session = UsageWindow{100.0 - remainingPercent, 100.0, "%", reset};
    return usage;
}

} // namespace hypelimits
