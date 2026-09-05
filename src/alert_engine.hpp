#pragma once

#include "model.hpp"

#include <map>
#include <string>
#include <vector>

namespace hypelimits {

enum class AlertKind { Warning, AllowanceReset };

struct AlertEvent {
    AlertKind kind;
    std::string providerId;
    MetricKind metricKind;
};

class AlertEngine {
public:
    [[nodiscard]] std::vector<AlertEvent> observe(const ProviderSnapshot& snapshot);
    void restoreWarning(const std::string& providerId, MetricKind kind, TimePoint period = {});

private:
    struct History {
        std::optional<double> remaining;
        std::optional<TimePoint> resetAt;
        std::optional<TimePoint> warnedPeriod;
        int increaseObservations{0};
    };
    std::map<std::string, History> history_;
};

} // namespace hypelimits
