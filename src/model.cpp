#include "model.hpp"

#include <algorithm>
#include <cmath>
#include <ranges>
#include <string_view>

namespace hypelimits {

std::optional<double> Metric::remainingFraction() const {
    if (state != MetricState::Current && state != MetricState::Stale && state != MetricState::Refreshing
        && state != MetricState::Error && state != MetricState::AuthenticationRequired) {
        return std::nullopt;
    }
    if (kind == MetricKind::ApiCredit && remaining) {
        const double full = (barFullAmount && *barFullAmount > 0.0) ? *barFullAmount : 100.0;
        return std::clamp(*remaining / full, 0.0, 1.0);
    }
    if (capacity && *capacity > 0.0) {
        if (remaining) {
            return std::clamp(*remaining / *capacity, 0.0, 1.0);
        }
        if (used) {
            return std::clamp(1.0 - (*used / *capacity), 0.0, 1.0);
        }
    }
    return std::nullopt;
}

bool Metric::contributesToAggregate() const {
    return kind != MetricKind::ApiCredit && remainingFraction().has_value();
}

bool Metric::visibleOnMonitor() const {
    const bool hasValue = used.has_value() || remaining.has_value() || (capacity && *capacity > 0.0);
    if (!hasValue) return false;
    switch (state) {
    case MetricState::Current:
    case MetricState::Refreshing:
    case MetricState::Stale:
    case MetricState::Error:
    case MetricState::AuthenticationRequired:
        return true;
    case MetricState::Unavailable:
    case MetricState::Unsupported:
        return false;
    }
    return false;
}

bool monitorIncludesProvider(const ProviderSnapshot& provider) {
    if (!provider.enabled) {
        return false;
    }
    return std::ranges::any_of(provider.metrics, [](const Metric& metric) { return metric.visibleOnMonitor(); });
}

bool providerAuthenticationFailed(const ProviderSnapshot& provider) {
    return std::ranges::any_of(provider.metrics, [](const Metric& metric) {
        return metric.visibleOnMonitor() && metric.state == MetricState::AuthenticationRequired;
    });
}

bool shouldAutoReauthenticate(bool providerSupportsOfficialSignIn, bool accountUsedOfficialSignIn, bool alreadyTried) {
    return providerSupportsOfficialSignIn && accountUsedOfficialSignIn && !alreadyTried;
}

std::optional<std::string> extractAuthorizationCode(std::string_view text) {
    auto takeToken = [](std::string_view raw) -> std::optional<std::string> {
        while (!raw.empty() && (raw.back() == '\r' || raw.back() == '\n' || raw.back() == '"' || raw.back() == '\'')) {
            raw.remove_suffix(1);
        }
        if (raw.size() < 8) return std::nullopt;
        return std::string{raw};
    };
    const auto keyed = text.find("code=");
    if (keyed != std::string_view::npos) {
        auto rest = text.substr(keyed + 5);
        const auto end = rest.find_first_of("&?#\"' <>");
        if (auto code = takeToken(end == std::string_view::npos ? rest : rest.substr(0, end))) return code;
    }
    const auto hash = text.find('#');
    if (hash != std::string_view::npos && hash >= 8) {
        auto start = text.find_last_of(" \n\r\"'=<>", hash);
        start = (start == std::string_view::npos) ? 0 : start + 1;
        if (auto code = takeToken(text.substr(start, hash - start))) return code;
    }
    return std::nullopt;
}

std::optional<double> Metric::alertRemainingFraction() const {
    if (kind == MetricKind::ApiCredit && remaining && lowBalanceThreshold && *lowBalanceThreshold > 0.0) {
        return std::clamp(*remaining / (*lowBalanceThreshold * 10.0), 0.0, 1.0);
    }
    return remainingFraction();
}

AggregateStatus aggregateStatus(const std::vector<ProviderSnapshot>& providers) {
    AggregateStatus result;
    for (const auto& provider : providers) {
        if (!provider.enabled) {
            continue;
        }
        for (const auto& metric : provider.metrics) {
            const auto fraction = metric.remainingFraction();
            if (!metric.contributesToAggregate() || !fraction) {
                continue;
            }
            if (!result.remainingFraction || *fraction < *result.remainingFraction) {
                result.remainingFraction = fraction;
                result.providerId = provider.id;
                result.kind = metric.kind;
            }
        }
    }
    return result;
}

RgbColor statusColor(double remaining) {
    remaining = std::clamp(remaining, 0.0, 1.0);
    if (remaining >= 0.5) {
        const double t = (remaining - 0.5) * 2.0;
        return {static_cast<int>(255 * (1.0 - t)), static_cast<int>(255 * (0.78 + 0.17 * t)), 38};
    }
    const double t = remaining * 2.0;
    return {static_cast<int>(255 * (0.92 + 0.08 * t)), static_cast<int>(255 * (0.18 + 0.60 * t)), 31};
}

RgbColor applyUsageActivity(RgbColor color, bool drawingDown) {
    auto channel = [](int value, double factor, int lift) {
        return std::clamp(static_cast<int>(std::lround(value * factor + lift)), 0, 255);
    };
    if (drawingDown) return {channel(color.red, 1.14, 20), channel(color.green, 1.14, 20), channel(color.blue, 1.14, 14)};
    return {channel(color.red, 0.52, 0), channel(color.green, 0.52, 0), channel(color.blue, 0.52, 0)};
}

bool usageDrewDownSince(const Metric& previous, const Metric& current) {
    constexpr double kEpsilon = 0.05;
    if (current.used && previous.used && *current.used > *previous.used + kEpsilon) return true;
    if (current.remaining && previous.remaining && *current.remaining + kEpsilon < *previous.remaining) return true;
    return false;
}

std::string_view metricKindName(MetricKind kind) {
    switch (kind) {
    case MetricKind::Session: return "Session";
    case MetricKind::Weekly: return "Weekly";
    case MetricKind::ApiCredit: return "API credit";
    }
    return "Unknown";
}

std::string_view metricStateName(MetricState state) {
    switch (state) {
    case MetricState::Current: return "Current";
    case MetricState::Refreshing: return "Refreshing";
    case MetricState::Stale: return "Stale";
    case MetricState::Unavailable: return "Unavailable";
    case MetricState::Unsupported: return "Unsupported";
    case MetricState::Error: return "Error";
    case MetricState::AuthenticationRequired: return "Authentication required";
    }
    return "Unknown";
}

} // namespace hypelimits
