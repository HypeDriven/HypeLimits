#include "alert_engine.hpp"

namespace hypelimits {

void AlertEngine::restoreWarning(const std::string& providerId, MetricKind kind, TimePoint period) {
    const auto key = providerId + ":" + std::to_string(static_cast<int>(kind));
    history_[key].warnedPeriod = period;
}

std::vector<AlertEvent> AlertEngine::observe(const ProviderSnapshot& snapshot) {
    std::vector<AlertEvent> events;
    for (const auto& metric : snapshot.metrics) {
        const auto remaining = metric.alertRemainingFraction();
        if (!remaining) {
            continue;
        }

        const auto key = snapshot.id + ":" + std::to_string(static_cast<int>(metric.kind));
        auto& prior = history_[key];
        // A new period only earns the reset sound when the old one was constrained. The tolerance absorbs the small
        // shifts some providers make to the same reset time between polls.
        constexpr auto kResetTolerance = std::chrono::minutes(1);
        bool reset = prior.resetAt && metric.resetAt && *metric.resetAt > *prior.resetAt + kResetTolerance
            && prior.remaining && *prior.remaining <= 0.10;

        if (!reset && *remaining >= 0.50 &&
            ((prior.remaining && *prior.remaining <= 0.10) || prior.increaseObservations > 0)) {
            ++prior.increaseObservations;
            reset = prior.increaseObservations >= 2;
        } else if (*remaining < 0.50) {
            prior.increaseObservations = 0;
        }

        if (reset) {
            events.push_back({AlertKind::AllowanceReset, snapshot.id, metric.kind});
            prior.warnedPeriod.reset();
            prior.increaseObservations = 0;
        }

        if (*remaining <= 0.10) {
            const auto period = metric.resetAt.value_or(TimePoint{});
            const bool samePeriod = prior.warnedPeriod
                && (*prior.warnedPeriod > period ? *prior.warnedPeriod - period : period - *prior.warnedPeriod) <= kResetTolerance;
            if (!samePeriod) {
                events.push_back({AlertKind::Warning, snapshot.id, metric.kind});
                prior.warnedPeriod = period;
            }
        }

        prior.remaining = remaining;
        prior.resetAt = metric.resetAt;
    }
    return events;
}

} // namespace hypelimits
