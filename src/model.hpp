#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace hypelimits {

using TimePoint = std::chrono::system_clock::time_point;

enum class MetricKind { Session, Weekly, ApiCredit };
enum class MetricState { Current, Refreshing, Stale, Unavailable, Unsupported, Error, AuthenticationRequired };

struct Metric {
    MetricKind kind{MetricKind::Session};
    MetricState state{MetricState::Unavailable};
    std::optional<double> used;
    std::optional<double> capacity;
    std::optional<double> remaining;
    std::string unit;
    std::string currency;
    std::optional<TimePoint> observedAt;
    std::optional<TimePoint> resetAt;
    std::string diagnostic;
    std::optional<double> lowBalanceThreshold;
    std::optional<double> barFullAmount;
    bool drawingDown{false};

    [[nodiscard]] std::optional<double> remainingFraction() const;
    [[nodiscard]] std::optional<double> alertRemainingFraction() const;
    [[nodiscard]] bool contributesToAggregate() const;
    [[nodiscard]] bool visibleOnMonitor() const;
};

struct ProviderSnapshot {
    std::string id;
    std::string displayName;
    bool enabled{true};
    std::vector<Metric> metrics;
    std::optional<TimePoint> lastSuccessfulRefresh;
};

struct AggregateStatus {
    std::optional<double> remainingFraction;
    std::string providerId;
    MetricKind kind{MetricKind::Session};
};

struct RgbColor {
    int red;
    int green;
    int blue;
};

[[nodiscard]] AggregateStatus aggregateStatus(const std::vector<ProviderSnapshot>& providers);
[[nodiscard]] bool monitorIncludesProvider(const ProviderSnapshot& provider);
[[nodiscard]] RgbColor statusColor(double remainingFraction);
[[nodiscard]] RgbColor applyUsageActivity(RgbColor color, bool drawingDown);
[[nodiscard]] bool usageDrewDownSince(const Metric& previous, const Metric& current);
[[nodiscard]] std::string_view metricKindName(MetricKind kind);
[[nodiscard]] std::string_view metricStateName(MetricState state);

} // namespace hypelimits
