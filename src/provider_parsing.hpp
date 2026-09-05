#pragma once

#include "model.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace hypelimits {

struct BalanceValue {
    double amount{};
    std::string currency;
    std::optional<double> used;
    std::optional<double> capacity;
};

struct UsageWindow {
    double used{};
    double capacity{};
    std::string unit{"%"};
    std::optional<TimePoint> resetAt;
};

struct ProviderUsage {
    std::optional<UsageWindow> session;
    std::optional<UsageWindow> weekly;
    std::optional<BalanceValue> credit;
};

[[nodiscard]] std::optional<std::string> jsonString(std::string_view json, std::string_view key, std::size_t start = 0);
[[nodiscard]] std::optional<double> jsonNumber(std::string_view json, std::string_view key, std::size_t start = 0);
[[nodiscard]] std::optional<TimePoint> parseTimestamp(std::string_view value);

[[nodiscard]] std::optional<BalanceValue> parseMoonshotBalance(std::string_view json);
[[nodiscard]] std::optional<BalanceValue> parseDeepSeekBalance(std::string_view json);
[[nodiscard]] std::optional<BalanceValue> parseXaiPrepaidBalance(std::string_view json);
[[nodiscard]] std::optional<ProviderUsage> parseClaudeUsage(std::string_view json);
[[nodiscard]] std::optional<ProviderUsage> parseCodexUsage(std::string_view json);
[[nodiscard]] std::optional<ProviderUsage> parseGrokBilling(std::string_view json);
[[nodiscard]] std::optional<ProviderUsage> parseKimiCodingUsage(std::string_view json);
[[nodiscard]] std::optional<ProviderUsage> parseAntigravityAssist(std::string_view json);
[[nodiscard]] std::optional<ProviderUsage> parseAntigravityModels(std::string_view json);

} // namespace hypelimits
