#include "activity_history.hpp"
#include "alert_engine.hpp"
#include "model.hpp"
#include "provider_parsing.hpp"
#include "token_sync.hpp"
#include "windows_command_line.hpp"

#include <algorithm>
#include <ranges>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace hypelimits;

namespace {
int failures = 0;

void check(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

Metric percentage(MetricKind kind, double used, double capacity, TimePoint reset = {}) {
    return Metric{kind, MetricState::Current, used, capacity, std::nullopt, "tokens", {},
                  TimePoint{}, reset, {}};
}

TokenObservation observation(std::string provider, std::string account, AllowanceWindow window, CounterUnit unit,
                             double used, MetricState state, TimePoint at) {
    return TokenObservation{std::move(provider), std::move(account), window, unit, used, state, at};
}

void recordOne(TokenHistory& history, TokenObservation sample) {
    const TokenObservation batch[]{sample};
    recordTokenObservations(history, batch);
}

void testActivityHistory() {
    const CivilDay today{2026, 6, 15};
    const auto now = timePointOnLocalDay(today, 15, 0);
    check(localCivilDay(now) == today, "local noon helper stays on the requested civil day");
    check(sundayIndex(CivilDay{2026, 6, 14}) == 0, "Sunday is the first row of the calendar");

    const auto at = [&](int dayOffset, int hour = 12) {
        return timePointOnLocalDay(shiftCivilDay(today, dayOffset), hour, 0);
    };

    {
        TokenHistory history;
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 0, MetricState::Current, at(0, 10)));
        recordOne(history, observation("openai", "1", AllowanceWindow::Session, CounterUnit::Tokens, 0, MetricState::Current, at(0, 10)));
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 40, MetricState::Current, at(0, 11)));
        recordOne(history, observation("openai", "1", AllowanceWindow::Session, CounterUnit::Tokens, 25, MetricState::Current, at(0, 11)));
        const auto stats = activityStats(history, now);
        check(std::abs(stats.lifetimeTokens - 65.0) < 0.001, "cross-provider token deltas sum on the local day");
        check(history.days.size() == 2 && history.days[0].day == today && history.days[1].day == today,
              "deltas land on the later observation's local day");
        check(history.days[0].providerId == "anthropic" && history.days[0].accountId == "0"
                  && std::abs(history.days[0].tokens - 40.0) < 0.001
                  && history.days[1].providerId == "openai" && history.days[1].accountId == "1"
                  && std::abs(history.days[1].tokens - 25.0) < 0.001,
              "each provider account keeps its own daily total");
        check(std::abs(activityStats(history, now, "anthropic", "0").lifetimeTokens - 40.0) < 0.001
                  && activityStats(history, now, "anthropic", "1").lifetimeTokens == 0.0,
              "an account filter keeps that account and leaves out the provider's other accounts");
        check(std::abs(stats.peakTokensPerDay - 65.0) < 0.001, "the all-providers peak is the summed day");
        check(std::abs(activityStats(history, now, "anthropic").lifetimeTokens - 40.0) < 0.001
                  && std::abs(activityStats(history, now, "openai").lifetimeTokens - 25.0) < 0.001,
              "a provider filter keeps only that provider's tokens");
        check(activityStats(history, now, "xai").lifetimeTokens == 0.0, "a provider with no tokens contributes nothing");
        const auto providerCalendar = activityCalendar(history, now, "anthropic");
        const auto aggregateCalendar = activityCalendar(history, now);
        double providerToday = -1.0;
        double aggregateToday = -1.0;
        for (const auto& week : providerCalendar.weeks) {
            for (const auto& cell : week.days) {
                if (cell && cell->day == today) providerToday = cell->tokens;
            }
        }
        for (const auto& week : aggregateCalendar.weeks) {
            for (const auto& cell : week.days) {
                if (cell && cell->day == today) aggregateToday = cell->tokens;
            }
        }
        check(std::abs(providerToday - 40.0) < 0.001, "the provider calendar shows only that provider");
        check(std::abs(aggregateToday - 65.0) < 0.001, "the aggregate calendar still sums every provider");
    }

    {
        TokenHistory history;
        const TokenObservation batch[]{
            observation("anthropic", "0", AllowanceWindow::Session, CounterUnit::Tokens, 100, MetricState::Current, at(-1, 9)),
            observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 100, MetricState::Current, at(-1, 9)),
            observation("anthropic", "0", AllowanceWindow::Session, CounterUnit::Tokens, 180, MetricState::Current, at(-1, 10)),
            observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 180, MetricState::Current, at(-1, 10)),
            observation("openai", "3", AllowanceWindow::Session, CounterUnit::Tokens, 0, MetricState::Current, at(-1, 9)),
            observation("openai", "3", AllowanceWindow::Session, CounterUnit::Tokens, 15, MetricState::Current, at(-1, 10)),
        };
        recordTokenObservations(history, batch);
        const auto stats = activityStats(history, now);
        check(std::abs(stats.lifetimeTokens - 95.0) < 0.001, "weekly is preferred over session so the same tokens are not doubled");
    }

    {
        TokenHistory history;
        const auto earlier = at(-3, 8);
        const auto later = at(-3, 9);
        for (const auto unit : {CounterUnit::Percent, CounterUnit::Requests, CounterUnit::Credits, CounterUnit::Currency}) {
            recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, unit, 10, MetricState::Current, earlier));
            recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, unit, 90, MetricState::Current, later));
        }
        check(activityStats(history, now).lifetimeTokens == 0.0, "percent, request, credit, and currency counters add zero");
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 500, MetricState::Current, earlier));
        check(activityStats(history, now).lifetimeTokens == 0.0, "the first token sample is a baseline and adds nothing");
        check(history.deltas.empty(), "a baseline does not store a delta");
    }

    {
        TokenHistory history;
        recordOne(history, observation("anthropic", "1", AllowanceWindow::Weekly, CounterUnit::Tokens, 0, MetricState::Current, at(-4, 8)));
        recordOne(history, observation("anthropic", "1", AllowanceWindow::Weekly, CounterUnit::Tokens, 100, MetricState::Current, at(-4, 9)));
        recordOne(history, observation("anthropic", "1", AllowanceWindow::Weekly, CounterUnit::Tokens, 10, MetricState::Current, at(-4, 10)));
        recordOne(history, observation("anthropic", "1", AllowanceWindow::Weekly, CounterUnit::Tokens, 40, MetricState::Current, at(-4, 11)));
        const auto stats = activityStats(history, now);
        check(std::abs(stats.lifetimeTokens - 130.0) < 0.001, "a used drop does not subtract and the next rise is the delta from the new baseline");
    }

    {
        TokenHistory history;
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Session, CounterUnit::Tokens, 5, MetricState::Stale, at(-2, 8)));
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Session, CounterUnit::Tokens, 5, MetricState::Current, at(-2, 9)));
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Session, CounterUnit::Tokens, 80, MetricState::Refreshing, at(-2, 10)));
        check(activityStats(history, now).lifetimeTokens == 0.0, "a non-current observation adds nothing");
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Session, CounterUnit::Tokens, 9, MetricState::Current, at(-2, 11)));
        check(std::abs(activityStats(history, now).lifetimeTokens - 4.0) < 0.001,
              "a non-current reading does not move the baseline");
    }

    {
        TokenHistory history;
        const auto positive = [&](int offset, double usedBefore, double usedAfter) {
            recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, usedBefore, MetricState::Current, at(offset, 8)));
            recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, usedAfter, MetricState::Current, at(offset, 18)));
        };
        positive(-10, 0, 5);
        positive(-9, 5, 8);
        positive(-8, 8, 11);
        positive(-7, 11, 14);
        positive(-6, 14, 20);
        positive(-2, 0, 3);
        positive(-1, 3, 6);
        const auto stats = activityStats(history, now);
        check(stats.longestStreakDays == 5, "a zero day breaks a streak and the longest streak is the longest positive run");
        check(stats.currentStreakDays == 2, "the current streak keeps yesterday when today is still zero");
        check(std::abs(stats.lifetimeTokens - 26.0) < 0.001, "lifetime equals the sum of stored daily totals");
        check(std::abs(stats.peakTokensPerDay - 6.0) < 0.001, "peak equals the max daily total");
    }

    {
        TokenHistory history;
        recordOne(history, observation("openai", "0", AllowanceWindow::Session, CounterUnit::Tokens, 0, MetricState::Current, at(-4, 8)));
        recordOne(history, observation("openai", "0", AllowanceWindow::Session, CounterUnit::Tokens, 4, MetricState::Current, at(-4, 12)));
        const auto stats = activityStats(history, now);
        check(stats.currentStreakDays == 0, "the current streak is zero when yesterday is also zero");
        check(stats.longestStreakDays == 1, "a single positive day is a streak of one");
    }

    {
        TokenHistory history;
        recordOne(history, observation("openai", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 0, MetricState::Current, at(-1, 8)));
        recordOne(history, observation("openai", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 2, MetricState::Current, at(-1, 12)));
        recordOne(history, observation("openai", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 2, MetricState::Current, at(0, 8)));
        recordOne(history, observation("openai", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 9, MetricState::Current, at(0, 12)));
        check(activityStats(history, now).currentStreakDays == 2, "the current streak counts backward from today when today is positive");
    }

    {
        const ActivityStats empty = activityStats(TokenHistory{}, now);
        check(empty.lifetimeTokens == 0.0 && empty.peakTokensPerDay == 0.0 && empty.longestStreakDays == 0
                  && empty.currentStreakDays == 0,
              "empty history statistics are all zero");
        const auto calendar = activityCalendar(TokenHistory{}, now);
        int cells = 0;
        double total = 0;
        for (const auto& week : calendar.weeks) {
            for (const auto& cell : week.days) {
                if (!cell) continue;
                ++cells;
                total += cell->tokens;
                check(cell->level == 0 && cell->tokens == 0.0, "empty history leaves every cell empty");
            }
        }
        check(calendar.yearTokens == 0.0 && total == 0.0, "an empty year total is zero");
        check(cells >= 365 && calendar.weeks.size() <= 53, "an empty calendar still covers the trailing year");
    }

    {
        TokenHistory history;
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 0, MetricState::Current, at(-400, 8)));
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 70, MetricState::Current, at(-400, 12)));
        const double amounts[] = {1, 2, 3, 4, 10, 10, 8};
        double used = 0;
        double inYear = 0;
        for (int index = 0; index < 7; ++index) {
            const double next = used + amounts[index];
            recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, used, MetricState::Current, at(-20 + index, 8)));
            recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, next, MetricState::Current, at(-20 + index, 18)));
            used = next;
            inYear += amounts[index];
        }
        const auto calendar = activityCalendar(history, now);
        std::vector<CalendarCell> cells;
        int labeledWeeks = 0;
        bool sundayAligned = !calendar.weeks.empty();
        for (std::size_t week = 0; week < calendar.weeks.size(); ++week) {
            if (!calendar.weeks[week].monthLabel.empty()) ++labeledWeeks;
            bool gap = false;
            for (int row = 0; row < 7; ++row) {
                const auto& cell = calendar.weeks[week].days[static_cast<std::size_t>(row)];
                if (!cell) {
                    gap = true;
                    continue;
                }
                if (gap) sundayAligned = false;
                if (sundayIndex(cell->day) != row) sundayAligned = false;
                cells.push_back(*cell);
            }
        }
        check(sundayAligned, "the calendar is Sunday-aligned");
        check(cells.size() >= 365 && calendar.weeks.size() <= 53, "the calendar covers at least 365 local days and at most 53 weeks");
        check(!cells.empty() && cells.back().day == today, "the calendar runs through today");
        bool onePerDay = cells.size() >= 2;
        for (std::size_t index = 1; index < cells.size(); ++index) {
            if (cells[index].day != shiftCivilDay(cells[index - 1].day, 1)) onePerDay = false;
        }
        check(onePerDay, "the calendar has one cell per day");

        bool levelsOk = true;
        int darkest = 0;
        double busiest = 0;
        double ranged = 0;
        for (const auto& cell : cells) {
            if (cell.level < 0 || cell.level > 4) levelsOk = false;
            if (cell.tokens <= 0.0) {
                if (cell.level != 0) levelsOk = false;
            } else if (cell.level < 1) {
                levelsOk = false;
            }
            darkest = std::max(darkest, cell.level);
            busiest = std::max(busiest, cell.tokens);
            ranged += cell.tokens;
        }
        for (const auto& left : cells) {
            for (const auto& right : cells) {
                if (left.tokens > right.tokens && left.level < right.level) levelsOk = false;
                if (left.tokens == right.tokens && left.level != right.level) levelsOk = false;
            }
        }
        for (const auto& cell : cells) {
            if (cell.tokens == busiest && busiest > 0.0 && cell.level != darkest) levelsOk = false;
        }
        check(levelsOk, "levels are 0-4, monotonic, and 0 only for zero tokens");
        check(std::abs(calendar.yearTokens - ranged) < 0.001, "the year total equals the sum of days inside the range");
        check(std::abs(calendar.yearTokens - inYear) < 0.001, "the year total leaves out older stored days");
        check(labeledWeeks >= 8, "month labels sit on the week columns");
        const auto stats = activityStats(history, now);
        double stored = 0;
        double peak = 0;
        for (const auto& day : history.days) {
            stored += day.tokens;
            peak = std::max(peak, day.tokens);
        }
        check(std::abs(stats.lifetimeTokens - stored) < 0.001, "lifetime equals the sum of stored daily totals");
        check(std::abs(stats.peakTokensPerDay - peak) < 0.001, "peak equals the max daily total");
    }

    {
        TokenHistory history;
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 0, MetricState::Current, at(-2, 9)));
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 12, MetricState::Current, at(-2, 15)));
        recordOne(history, observation("openai", "2", AllowanceWindow::Session, CounterUnit::Tokens, 3, MetricState::Current, at(-1, 9)));
        recordOne(history, observation("openai", "2", AllowanceWindow::Session, CounterUnit::Tokens, 8, MetricState::Current, at(-1, 11)));
        const auto text = serializeTokenHistory(history);
        check(text.find("sk-") == std::string::npos && text.find("Bearer") == std::string::npos && text.find("secret") == std::string::npos,
              "credentials are not written into the history");
        const auto restored = parseTokenHistory(text);
        check(restored.days.size() == history.days.size(), "a round trip restores every daily total");
        for (std::size_t index = 0; index < history.days.size(); ++index) {
            check(restored.days[index].day == history.days[index].day, "a round trip restores the local day");
            check(std::abs(restored.days[index].tokens - history.days[index].tokens) < 0.001, "a round trip restores the daily total");
            check(restored.days[index].providerId == history.days[index].providerId, "a round trip restores which provider the day belongs to");
            check(restored.days[index].accountId == history.days[index].accountId, "a round trip restores which account the day belongs to");
        }
        check(restored.deltas.size() == history.deltas.size(), "a round trip restores every delta");
        for (std::size_t index = 0; index < history.deltas.size(); ++index) {
            check(restored.deltas[index].at == history.deltas[index].at, "a round trip restores the delta time");
            check(std::abs(restored.deltas[index].tokens - history.deltas[index].tokens) < 0.001, "a round trip restores the delta size");
            check(restored.deltas[index].providerId == history.deltas[index].providerId, "a round trip restores which provider the delta belongs to");
            check(restored.deltas[index].accountId == history.deltas[index].accountId, "a round trip restores which account the delta belongs to");
        }
        check(restored.baselines.size() == history.baselines.size(), "a round trip restores baselines");
        auto continued = restored;
        recordOne(continued, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 18, MetricState::Current, at(0, 12)));
        check(std::abs(activityStats(continued, now).lifetimeTokens - 23.0) < 0.001,
              "reloaded baselines continue from the saved counter");

        const auto malformed = parseTokenHistory("HLHIST1\nD 2026-06-01 50\nNOPE\n");
        const auto malformedStats = activityStats(malformed, now);
        check(malformed.days.empty() && malformed.deltas.empty() && malformedStats.lifetimeTokens == 0.0,
              "malformed input yields an empty history instead of a fabricated total");
        check(parseTokenHistory("").days.empty(), "empty saved data is an empty history");
        check(parseTokenHistory("this is not history").days.empty(), "a missing header yields an empty history");
        check(parseTokenHistory("HLHIST1\nD 2026-99-01 4\n").days.empty(), "an impossible date yields an empty history");
        check(parseTokenHistory("HLHIST1\nD 2026-06-01 -5\n").days.empty(), "a negative total yields an empty history");
        check(parseTokenHistory("HLHIST1\nD 2026-06-01 5\nD 2026-06-01 9\n").days.empty(), "a duplicate day yields an empty history");
        check(parseTokenHistory("HLHIST1\nD 2026-06-01\n").days.empty(), "truncated saved data yields an empty history");
    }

    {
        const char* report = R"({
            "data": [
                {"date":"2026-06-14","totals":{"text_total_tokens":100,"cached_text_input_tokens":40,"uncached_text_input_tokens":30,"text_output_tokens":20},
                 "clients":[{"client_id":"codex","text_total_tokens":999,"cached_text_input_tokens":999}]},
                {"date":"2026-06-15","totals":{"text_total_tokens":0,"cached_text_input_tokens":10,"uncached_text_input_tokens":5,"text_output_tokens":2}},
                {"date":"2026-06-13","totals":{"credits":3,"turns":1}},
                {"date":"not-a-date","totals":{"text_total_tokens":50}}
            ]
        })";
        const auto parsed = parseCodexDailyTokens(report);
        check(parsed.has_value(), "a Codex daily report with a data array is accepted");
        check(parsed && parsed->size() == 2, "only days with absolute tokens are kept");
        if (parsed && parsed->size() == 2) {
            check(parsed->front().day == CivilDay{2026, 6, 14} && std::abs(parsed->front().tokens - 100.0) < 0.001,
                  "text_total_tokens is used and nested client tokens are not added again");
            check(parsed->back().day == CivilDay{2026, 6, 15} && std::abs(parsed->back().tokens - 17.0) < 0.001,
                  "a zero text total falls back to cached, uncached, and output tokens");
        }
        check(!parseCodexDailyTokens(R"({"error":"nope"})"), "a body without a data array does not replace saved days");
        const auto emptyReport = parseCodexDailyTokens(R"({"data":[]})");
        check(emptyReport && emptyReport->empty(), "an empty data array is a real empty report");

        TokenHistory history;
        const std::vector<DailyTokens> importedDays = parsed.value_or(std::vector<DailyTokens>{});
        check(parsed && replaceImportedDailyTokens(history, "openai", "1", importedDays), "the first Codex import is stored");
        check(std::abs(activityStats(history, now).lifetimeTokens - 117.0) < 0.001, "imported daily tokens count toward lifetime");
        const auto calendar = activityCalendar(history, now);
        double ranged = 0.0;
        for (const auto& week : calendar.weeks) {
            for (const auto& cell : week.days) {
                if (!cell) continue;
                if (cell->day == CivilDay{2026, 6, 14}) check(std::abs(cell->tokens - 100.0) < 0.001, "the calendar shows the imported day");
                ranged += cell->tokens;
            }
        }
        check(std::abs(ranged - 117.0) < 0.001, "imported days inside the visible year are summed");
        std::vector<DailyTokens> replacement{{CivilDay{2026, 6, 14}, 40.0}};
        check(replaceImportedDailyTokens(history, "openai", "1", replacement), "a later report replaces that account's imported days");
        check(!replaceImportedDailyTokens(history, "openai", "1", replacement), "the same report does not count twice");
        check(std::abs(activityStats(history, now).lifetimeTokens - 40.0) < 0.001, "replacement does not add to the previous import");

        recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 0, MetricState::Current, at(0, 9)));
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 7, MetricState::Current, at(0, 12)));
        check(std::abs(activityStats(history, now).lifetimeTokens - 47.0) < 0.001,
              "a live token delta is added beside imported days");
        check(replaceImportedDailyTokens(history, "openai", "1", {}), "clearing one account leaves the other provider's deltas");
        check(std::abs(activityStats(history, now).lifetimeTokens - 7.0) < 0.001, "clearing an import removes only that account");

        const std::vector<DailyTokens> both{{CivilDay{2026, 6, 15}, 17.0}};
        replaceImportedDailyTokens(history, "openai", "1", both);
        const auto text = serializeTokenHistory(history);
        check(text.find("sk-") == std::string::npos && text.find("Bearer") == std::string::npos, "an import stores no credential");
        const auto restored = parseTokenHistory(text);
        check(restored.imported.size() == 1 && restored.imported.front().providerId == "openai"
                  && restored.imported.front().accountId == "1"
                  && restored.imported.front().day == CivilDay{2026, 6, 15}
                  && std::abs(restored.imported.front().tokens - 17.0) < 0.001,
              "a round trip restores the imported day");
        check(std::abs(activityStats(restored, now).lifetimeTokens - 24.0) < 0.001,
              "a reloaded import still adds to recorded deltas");
        check(parseTokenHistory("HLHIST1\nI openai 0 2026-06-14 5\nI openai 0 2026-06-14 9\n").days.empty(),
              "a duplicate imported day yields an empty history");
        check(parseTokenHistory("HLHIST1\nI openai 0 2026-06-14\n").imported.empty(), "a truncated import yields an empty history");
    }

    {
        const auto when = timePointOnLocalDay(CivilDay{2026, 6, 14}, 15, 0);
        const auto seconds = std::chrono::floor<std::chrono::seconds>(when);
        const auto days = std::chrono::floor<std::chrono::days>(seconds);
        const std::chrono::year_month_day ymd{days};
        const auto timeOfDay = seconds - days;
        const auto hours = std::chrono::duration_cast<std::chrono::hours>(timeOfDay);
        const auto minutes = std::chrono::duration_cast<std::chrono::minutes>(timeOfDay - hours);
        const auto secs = std::chrono::duration_cast<std::chrono::seconds>(timeOfDay - hours - minutes);
        const auto stamp = std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", static_cast<int>(ymd.year()),
                                        static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day()),
                                        static_cast<int>(hours.count()), static_cast<int>(minutes.count()),
                                        static_cast<int>(secs.count()));
        const auto unixSeconds = std::chrono::duration_cast<std::chrono::seconds>(when.time_since_epoch()).count();
        const auto unixMillis = std::chrono::duration_cast<std::chrono::milliseconds>(when.time_since_epoch()).count();
        const auto claudeLog = std::format(
            R"({{"type":"user","message":{{"content":[{{"type":"text","text":"hello"}}]}}}}
{{"message":{{"content":[{{"type":"text","text":"sk-ant-secret"}}],"usage":{{"input_tokens":2,"cache_creation_input_tokens":10,"cache_read_input_tokens":20,"output_tokens":3,"output_tokens_details":{{"thinking_tokens":1}}}}}},"requestId":"req_a","type":"assistant","timestamp":"{0}"}}
{{"message":{{"usage":{{"input_tokens":2,"cache_creation_input_tokens":10,"cache_read_input_tokens":20,"output_tokens":3}}}},"requestId":"req_a","type":"assistant","timestamp":"{0}"}}
{{"message":{{"usage":{{"input_tokens":1,"output_tokens":1}}}},"requestId":"req_b","type":"assistant","timestamp":"{0}"}}
)",
            stamp);
        const auto grokLog = std::format(
            R"({{"timestamp":{0},"method":"session/update","params":{{"update":{{"sessionUpdate":"turn_completed","prompt_id":"p1","usage":{{"inputTokens":8,"outputTokens":2,"totalTokens":10,"cachedReadTokens":80,"modelUsage":{{"grok":{{"totalTokens":999}}}}}}}}}}}}}}
{{"timestamp":{0},"method":"session/update","params":{{"update":{{"sessionUpdate":"turn_completed","prompt_id":"p1","usage":{{"totalTokens":40,"inputTokens":1,"outputTokens":1,"modelUsage":{{"grok":{{"totalTokens":999}}}}}}}}}}}}}}
{{"timestamp":{0},"method":"session/update","params":{{"update":{{"sessionUpdate":"turn_completed","prompt_id":"p2","usage":{{"totalTokens":0,"inputTokens":5,"outputTokens":1}}}}}}}}
{{"timestamp":{0},"method":"session/update","params":{{"update":{{"sessionUpdate":"tool_call"}},"_meta":{{"totalTokens":1000}}}}}}
{{"message":"see \"sessionUpdate\":\"turn_completed\" totalTokens 99999"}}
)",
            unixSeconds);
        const auto kimiLog = std::format(
            R"({{"type":"usage.record","usage":{{"inputOther":10,"output":4,"inputCacheRead":6,"inputCacheCreation":1}},"usageScope":"turn","time":{0}}}
{{"type":"usage.record","usage":{{"inputOther":1000,"output":1000}},"usageScope":"session","time":{0}}}
{{"type":"token_counting.measured","tokens":5000,"time":{0}}}
)",
            unixMillis);
        const std::string logs = claudeLog + grokLog + kimiLog + "{\"type\":\"token_usage_record\",\"payload\":{\"usage\":{\"total_tokens\":5000}}}\n";
        const auto parsed = parseSessionLogTokens(logs);
        const auto expectedDay = localCivilDay(when);
        double total = 0.0;
        bool dayOk = !parsed.empty();
        for (const auto& day : parsed) {
            total += day.tokens;
            if (day.day != expectedDay) dayOk = false;
        }
        check(dayOk && std::abs(total - (37.0 + 46.0 + 21.0)) < 0.001,
              "local logs count Claude once per request, Grok once per turn, and Kimi turn records");

        namespace fs = std::filesystem;
        const auto root = fs::temp_directory_path() / "hl-session-logs";
        const auto home = root / "win";
        const auto other = root / "wsl";
        std::error_code removeError;
        fs::remove_all(root, removeError);
        fs::create_directories(home / ".claude" / "projects" / "demo");
        fs::create_directories(home / ".grok" / "sessions" / "demo");
        fs::create_directories(home / ".kimi-code" / "sessions" / "demo" / "agents" / "main");
        fs::create_directories(home / ".codex" / "sessions");
        fs::create_directories(other / ".claude" / "projects" / "demo");
        {
            std::ofstream claude(home / ".claude" / "projects" / "demo" / "session.jsonl");
            claude << claudeLog;
            std::ofstream grok(home / ".grok" / "sessions" / "demo" / "updates.jsonl");
            grok << grokLog;
            std::ofstream kimi(home / ".kimi-code" / "sessions" / "demo" / "agents" / "main" / "wire.jsonl");
            kimi << kimiLog;
            std::ofstream codex(home / ".codex" / "sessions" / "rollout.jsonl");
            codex << R"({"type":"token_usage_record","payload":{"usage":{"total_tokens":5000}}})";
            std::ofstream extra(other / ".claude" / "projects" / "demo" / "session.jsonl");
            extra << std::format(
                R"({{"message":{{"usage":{{"input_tokens":8,"output_tokens":2}}}},"requestId":"req_other","type":"assistant","timestamp":"{}"}})",
                stamp);
        }
        auto tokensFor = [](const std::vector<LocalSessionImport>& imports, std::string_view provider) {
            double sum = 0.0;
            for (const auto& import : imports) {
                if (import.providerId != provider) continue;
                for (const auto& day : import.days) sum += day.tokens;
            }
            return sum;
        };
        SessionLogCache cache;
        check(refreshSessionLogCache(cache, home) == SessionLogScan::Updated, "the first read of a home records its session logs");
        check(refreshSessionLogCache(cache, other) == SessionLogScan::Updated, "a second home is recorded beside the first");
        auto imports = sessionLogImports(cache);
        check(imports.size() == 3, "local imports cover Claude, Grok, and Kimi");
        check(std::ranges::all_of(imports, [](const LocalSessionImport& import) { return import.accountId == kLocalSessionAccount; }),
              "logs that name no organization stay on the local account");
        check(std::abs(tokensFor(imports, "anthropic") - (37.0 + 10.0)) < 0.001, "Claude files from both homes are summed");
        check(std::abs(tokensFor(imports, "xai") - 46.0) < 0.001, "Grok completed turns are summed without the per-model breakdown");
        check(std::abs(tokensFor(imports, "moonshot") - 21.0) < 0.001, "Kimi turn usage is summed and session snapshots are not");
        check(std::ranges::none_of(cache.entries, [](const SessionLogCacheEntry& entry) { return entry.providerId == "openai"; }),
              "Codex rollout logs are not a second copy of the daily API");
        const auto saved = serializeSessionLogCache(cache);
        check(saved.find("sk-ant-secret") == std::string::npos && saved.find("hello") == std::string::npos,
              "the scan cache stores totals, not log text or secrets");
        const auto restored = parseSessionLogCache(saved);
        check(restored.entries.size() == cache.entries.size(), "a scan-cache round trip keeps every file");
        check(saved.starts_with("HLSL2\n"), "the scan cache records which organization a file named");
        check(std::ranges::all_of(restored.entries, [](const SessionLogCacheEntry& entry) { return entry.accountId == "local"; }),
              "a log that names no organization stays unattributed in the scan cache");
        check(parseSessionLogCache("HLSL1\nE anthropic 1 1 1\n/tmp/a\n").entries.empty(), "a truncated scan cache is empty");
        check(parseSessionLogCache("HLSL1\nE anthropic 1 1 0 local\n/tmp/a\n").entries.empty(),
              "an older scan cache has no organization field");
        check(parseSessionLogCache("HLSL2\nE anthropic 1 1 0\n/tmp/a\n").entries.empty(), "a scan cache entry needs its organization field");
        check(parseSessionLogCache("HLSL2\nE anthropic 1 1 0 nope\n/tmp/a\n").entries.empty(), "an unknown organization field is rejected");
        const auto pending = parseSessionLogCache("HLSL1\nE anthropic 1 2 0\n/tmp/claude.jsonl\n");
        check(pending.entries.size() == 1 && pending.entries.front().accountId.empty(),
              "an older scan cache leaves the organization unread");
        check(parseSessionLogCache("nope").entries.empty(), "a scan cache without its header is empty");
        const auto cacheFile = root / "cache.txt";
        check(storeSessionLogCache(cache, cacheFile), "the scan cache can be written");
        check(loadSessionLogCache(cacheFile).entries.size() == cache.entries.size(), "the scan cache can be read back");
        check(refreshSessionLogCache(cache, home) == SessionLogScan::Unchanged, "an unchanged home is not read again");
        check(refreshSessionLogCache(cache, root / "missing") == SessionLogScan::Unavailable, "a missing home leaves the cache alone");
        check(std::abs(tokensFor(sessionLogImports(cache), "xai") - 46.0) < 0.001, "a missing home does not drop tokens already read");

        {
            std::ofstream claude(home / ".claude" / "projects" / "demo" / "session.jsonl", std::ios::app);
            claude << std::format(
                "\n{{\"message\":{{\"usage\":{{\"input_tokens\":4}}}},\"requestId\":\"req_c\",\"type\":\"assistant\",\"timestamp\":\"{}\"}}\n",
                stamp);
        }
        check(refreshSessionLogCache(cache, home) == SessionLogScan::Updated, "an appended session log is reread");
        check(std::abs(tokensFor(sessionLogImports(cache), "anthropic") - (37.0 + 10.0 + 4.0)) < 0.001,
              "an appended request adds its tokens once");
        fs::remove(home / ".kimi-code" / "sessions" / "demo" / "agents" / "main" / "wire.jsonl");
        check(refreshSessionLogCache(cache, home) == SessionLogScan::Updated, "removing a log updates the cache");
        check(tokensFor(sessionLogImports(cache), "moonshot") == 0.0, "a removed Kimi log drops its tokens");
        check(std::abs(tokensFor(sessionLogImports(cache), "anthropic") - (37.0 + 10.0 + 4.0)) < 0.001,
              "removing one provider's log leaves the others");

        TokenHistory history;
        for (const auto& import : sessionLogImports(cache)) {
            replaceImportedDailyTokens(history, import.providerId, kLocalSessionAccount, import.days);
        }
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Percent, 10, MetricState::Current, when));
        recordOne(history, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Percent, 40, MetricState::Current, when));
        const double expected = 37.0 + 10.0 + 4.0 + 46.0;
        check(std::abs(activityStats(history, now).lifetimeTokens - expected) < 0.001,
              "local session totals count, and percent allowance counters still do not");
        const auto historyText = serializeTokenHistory(history);
        check(historyText.find("sk-ant") == std::string::npos, "local session imports store no secret");
        const auto historyRestored = parseTokenHistory(historyText);
        check(std::abs(activityStats(historyRestored, now).lifetimeTokens - expected) < 0.001,
              "a reloaded local import keeps the session totals");
        check(std::abs(activityStats(history, now, "anthropic").lifetimeTokens - (37.0 + 10.0 + 4.0)) < 0.001,
              "a provider filter keeps that provider's local session totals");
        check(activityStats(history, now, "openai").lifetimeTokens == 0.0,
              "a provider filter leaves out other providers' session totals");
        check(std::abs(activityStats(history, now, "anthropic", "local").lifetimeTokens - (37.0 + 10.0 + 4.0)) < 0.001,
              "session logs stay on the local account");
        check(activityStats(history, now, "anthropic", "0").lifetimeTokens == 0.0,
              "a saved account does not receive another account's session logs");
        fs::remove_all(root, removeError);
    }

    {
        constexpr std::string_view kOrgA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        constexpr std::string_view kOrgB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        constexpr std::string_view kAccountA = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        constexpr std::string_view kAccountB = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        constexpr std::string_view kSessionA = "11111111-1111-4111-8111-111111111111";
        constexpr std::string_view kSessionB = "22222222-2222-4222-8222-222222222222";
        constexpr std::string_view kSessionC = "33333333-3333-4333-8333-333333333333";
        constexpr std::string_view kSessionD = "44444444-4444-4444-8444-444444444444";
        const auto assistant = [](std::string_view request, int tokens) {
            return std::format(
                "{{\"type\":\"assistant\",\"requestId\":\"{}\",\"timestamp\":\"2026-06-14T15:00:00Z\","
                "\"message\":{{\"usage\":{{\"input_tokens\":{}}}}}}}\n",
                request, tokens);
        };
        const auto organizationLine = [](std::string_view organization) {
            return std::format(
                "{{\"type\":\"attachment\",\"attachment\":{{\"type\":\"credential_org\",\"organizationUuid\":\"{}\"}}}}\n",
                organization);
        };
        namespace fs = std::filesystem;
        const auto root = fs::temp_directory_path() / "hl-claude-orgs";
        const auto home = root / "home";
        std::error_code removeError;
        fs::remove_all(root, removeError);
        const auto sessionA = home / ".claude" / "projects" / "demo" / (std::string(kSessionA) + ".jsonl");
        const auto sessionAChild = home / ".claude" / "projects" / "demo" / std::string(kSessionA) / "subagents" / "agent.jsonl";
        const auto sessionB = home / ".claude" / "projects" / "demo" / (std::string(kSessionB) + ".jsonl");
        const auto sessionBChild = home / ".claude" / "projects" / "demo" / std::string(kSessionB) / "subagents" / "agent.jsonl";
        const auto sessionC = home / ".claude" / "projects" / "demo" / (std::string(kSessionC) + ".jsonl");
        const auto sessionCOne = home / ".claude" / "projects" / "demo" / std::string(kSessionC) / "subagents" / "one.jsonl";
        const auto sessionCTwo = home / ".claude" / "projects" / "demo" / std::string(kSessionC) / "subagents" / "two.jsonl";
        const auto sessionD = home / ".claude" / "projects" / "demo" / (std::string(kSessionD) + ".jsonl");
        fs::create_directories(sessionAChild.parent_path());
        fs::create_directories(sessionBChild.parent_path());
        fs::create_directories(sessionCOne.parent_path());
        {
            std::ofstream parent(sessionA);
            parent << organizationLine(kOrgA) << assistant("a-parent", 10);
            std::ofstream child(sessionAChild);
            child << assistant("a-child", 4);
            std::ofstream parentB(sessionB);
            parentB << assistant("b-parent", 7);
            std::ofstream childB(sessionBChild);
            childB << organizationLine(kOrgB) << assistant("b-child", 1);
            std::ofstream parentC(sessionC);
            parentC << organizationLine(kOrgA) << assistant("c-a", 2);
            std::ofstream one(sessionCOne);
            one << organizationLine(kOrgB) << assistant("c-b", 3);
            std::ofstream two(sessionCTwo);
            two << assistant("c-none", 5);
            std::ofstream mixed(sessionD);
            mixed << organizationLine(kOrgA) << organizationLine(kOrgB) << assistant("mixed", 6);
        }
        {
            std::ofstream config(home / ".claude.json");
            config << std::format(
                "{{\"oauthAccount\":{{\"accountUuid\":\"{}\",\"emailAddress\":\"person@example.com\","
                "\"organizationUuid\":\"{}\"}}}}\n",
                kAccountA, kOrgA);
            fs::create_directories(home / ".claude" / "backups");
            std::ofstream backup(home / ".claude" / "backups" / ".claude.json.backup.1");
            backup << std::format(
                "{{\"oauthAccount\":{{\"accountUuid\":\"{}\",\"organizationUuid\":\"{}\"}}}}\n", kAccountB, kOrgB);
            std::ofstream ignored(home / ".claude" / "backups" / "credentials.json");
            ignored << "{\"oauthAccount\":{\"accountUuid\":\"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee\","
                       "\"organizationUuid\":\"ffffffff-ffff-4fff-8fff-ffffffffffff\"},\"accessToken\":\"secret-token\"}";
            std::ofstream credentials(home / ".claude" / ".credentials.json");
            credentials << "{\"claudeAiOauth\":{\"accessToken\":\"secret-token\"}}";
        }

        auto tokensForAccount = [](const std::vector<LocalSessionImport>& imports, std::string_view provider,
                                    std::string_view account) {
            double sum = 0.0;
            for (const auto& import : imports) {
                if (import.providerId != provider || import.accountId != account) continue;
                for (const auto& day : import.days) sum += day.tokens;
            }
            return sum;
        };
        auto accountForPath = [](const SessionLogCache& cache, std::string_view suffix) {
            for (const auto& entry : cache.entries) {
                if (entry.path.ends_with(suffix)) return entry.accountId;
            }
            return std::string{};
        };

        SessionLogCache cache;
        check(refreshSessionLogCache(cache, home) == SessionLogScan::Updated, "Claude logs that name an organization are read");
        check(accountForPath(cache, std::string(kSessionA) + ".jsonl") == kOrgA,
              "a transcript keeps the organization it names");
        check(accountForPath(cache, std::string(kSessionA) + "/subagents/agent.jsonl") == "local",
              "a sibling with no organization does not copy one into the cache");
        check(accountForPath(cache, std::string(kSessionB) + ".jsonl") == "local",
              "a parent with no organization stays unmarked in the cache");
        check(accountForPath(cache, std::string(kSessionD) + ".jsonl") == "mixed",
              "a transcript that names two organizations is not given to either");
        const auto imports = sessionLogImports(cache);
        check(std::abs(tokensForAccount(imports, "anthropic", kOrgA) - 16.0) < 0.001,
              "a session's single organization covers the sibling that names none");
        check(std::abs(tokensForAccount(imports, "anthropic", kOrgB) - 11.0) < 0.001,
              "the other organization keeps its own transcripts");
        check(std::abs(tokensForAccount(imports, "anthropic", "local") - 11.0) < 0.001,
              "a session with two organizations leaves an unnamed file unattributed");
        check(std::abs(tokensForAccount(imports, "anthropic", kOrgA) + tokensForAccount(imports, "anthropic", kOrgB)
                       + tokensForAccount(imports, "anthropic", "local") - 38.0)
                  < 0.001,
              "splitting Claude logs does not drop or double a request");

        const auto links = claudeOrganizationLinks(home);
        check(links.size() == 2, "Claude config and its backups contribute one link each");
        check(std::ranges::any_of(links, [&](const OrganizationAccountLink& link) {
                  return link.accountUuid == kAccountA && link.organizationUuid == kOrgA;
              }),
              "the current Claude config pairs its account with its organization");
        check(std::ranges::none_of(links, [](const OrganizationAccountLink& link) {
                  return link.accountUuid.find('@') != std::string::npos || link.organizationUuid.find("secret") != std::string::npos;
              }),
              "organization links do not keep an email address or a token");

        const std::vector<SavedAccountSlot> slots{{"0", std::string(kAccountA)}, {"1", std::string(kAccountB)}};
        const auto assigned = assignClaudeSessionImports(imports, links, slots);
        check(std::abs(tokensForAccount(assigned, "anthropic", "0") - 16.0) < 0.001,
              "the linked organization is stored on that saved login");
        check(std::abs(tokensForAccount(assigned, "anthropic", "1") - 11.0) < 0.001,
              "the one remaining organization is stored on the one remaining login");
        check(std::abs(tokensForAccount(assigned, "anthropic", "local") - 11.0) < 0.001,
              "unattributed Claude logs stay off both logins");

        TokenHistory history;
        const std::vector<DailyTokens> previous{{CivilDay{2026, 6, 14}, 38.0}};
        check(replaceImportedDailyTokens(history, "anthropic", kLocalSessionAccount, previous), "the previous local total is stored");
        for (const auto& import : assigned) {
            replaceImportedDailyTokens(history, import.providerId, import.accountId, import.days);
        }
        const auto now = timePointOnLocalDay(today, 18, 0);
        check(std::abs(activityStats(history, now).lifetimeTokens - 38.0) < 0.001,
              "moving Claude logs onto logins replaces the old local total");
        check(std::abs(activityStats(history, now, "anthropic", "0").lifetimeTokens - 16.0) < 0.001,
              "the first login shows only its own Claude logs");
        check(std::abs(activityStats(history, now, "anthropic", "1").lifetimeTokens - 11.0) < 0.001,
              "the second login shows only its own Claude logs");

        std::string older;
        older += "HLSL1\n";
        for (const auto& entry : cache.entries) {
            if (entry.providerId != "anthropic") continue;
            older += std::format("E anthropic {} {} 1\n{}\n2026-06-01 1\n", entry.modified, entry.size, entry.path);
        }
        auto loaded = parseSessionLogCache(older);
        check(!loaded.entries.empty() && std::ranges::all_of(loaded.entries, [](const SessionLogCacheEntry& entry) {
                  return entry.accountId.empty() && entry.days.size() == 1 && std::abs(entry.days.front().tokens - 1.0) < 0.001;
              }),
              "an older scan cache keeps its totals and has no organization yet");
        check(refreshSessionLogCache(loaded, home) == SessionLogScan::Updated, "an older cache is scanned for organizations");
        check(accountForPath(loaded, std::string(kSessionA) + ".jsonl") == kOrgA,
              "the organization scan fills the id without rereading token totals");
        check(std::ranges::all_of(loaded.entries, [](const SessionLogCacheEntry& entry) {
                  return entry.days.size() == 1 && entry.days.front().day == CivilDay{2026, 6, 1}
                      && std::abs(entry.days.front().tokens - 1.0) < 0.001;
              }),
              "the organization scan leaves saved daily totals unchanged");

        const std::vector<SavedAccountSlot> unnamed{{"0", {}}, {"1", {}}};
        check(matchOrganizationsToSlots(links, unnamed, std::vector<std::string>{std::string(kOrgA), std::string(kOrgB)}).empty(),
              "logins with no saved account id are not paired by guess");
        const std::vector<OrganizationAccountLink> noLinks;
        const std::vector<std::string> bothOrganizations{std::string(kOrgA), std::string(kOrgB)};
        check(matchOrganizationsToSlots(noLinks, slots, bothOrganizations).empty(),
              "two unpaired organizations are not divided between two logins");
        const auto oneLeft = matchOrganizationsToSlots(noLinks, std::vector<SavedAccountSlot>{{"0", std::string(kAccountA)}},
                                                       std::vector<std::string>{std::string(kOrgB)});
        check(oneLeft.size() == 1 && oneLeft.front().organizationId == kOrgB && oneLeft.front().slotId == "0",
              "one remaining organization pairs with the one remaining login");
        const std::vector<OrganizationAccountLink> sameOrganization{{std::string(kAccountA), std::string(kOrgA)},
                                                                    {std::string(kAccountB), std::string(kOrgA)}};
        check(matchOrganizationsToSlots(sameOrganization, slots, std::vector<std::string>{std::string(kOrgA)}).empty(),
              "one organization is not stored on two logins");

        SessionLogCache pending;
        pending.entries.push_back(SessionLogCacheEntry{"anthropic", "/tmp/a.jsonl", 1, 2, {}, {}});
        const auto pendingText = serializeSessionLogCache(pending);
        const auto pendingRestored = parseSessionLogCache(pendingText);
        check(pendingText.starts_with("HLSL2\n") && pendingRestored.entries.size() == 1
                  && pendingRestored.entries.front().accountId.empty(),
              "a Claude file that has not been scanned stays pending across a round trip");
        fs::remove_all(root, removeError);
    }

    {
        TokenHistory accounts;
        recordOne(accounts, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 0, MetricState::Current, at(0, 9)));
        recordOne(accounts, observation("anthropic", "1", AllowanceWindow::Weekly, CounterUnit::Tokens, 0, MetricState::Current, at(0, 9)));
        recordOne(accounts, observation("anthropic", "0", AllowanceWindow::Weekly, CounterUnit::Tokens, 10, MetricState::Current, at(0, 12)));
        recordOne(accounts, observation("anthropic", "1", AllowanceWindow::Weekly, CounterUnit::Tokens, 6, MetricState::Current, at(0, 12)));
        check(accounts.days.size() == 2, "each account of a provider keeps its own daily total");
        check(accounts.days[0].accountId == "0" && std::abs(accounts.days[0].tokens - 10.0) < 0.001
                  && accounts.days[1].accountId == "1" && std::abs(accounts.days[1].tokens - 6.0) < 0.001,
              "account totals stay in slot order");
        check(std::abs(activityStats(accounts, now).lifetimeTokens - 16.0) < 0.001, "the aggregate still adds every account");
        check(std::abs(activityStats(accounts, now, "anthropic").lifetimeTokens - 16.0) < 0.001,
              "a provider filter still adds every account of that provider");
        const std::vector<DailyTokens> firstAccount{{today, 5.0}};
        const std::vector<DailyTokens> secondAccount{{today, 9.0}};
        const std::vector<DailyTokens> localAccount{{today, 100.0}};
        check(replaceImportedDailyTokens(accounts, "anthropic", "0", firstAccount), "the first account import is stored");
        check(replaceImportedDailyTokens(accounts, "anthropic", "1", secondAccount), "the second account import is stored");
        check(replaceImportedDailyTokens(accounts, "anthropic", kLocalSessionAccount, localAccount), "a local import stays separate");
        check(std::abs(activityStats(accounts, now, "anthropic", "0").lifetimeTokens - 15.0) < 0.001,
              "an account view adds that account's recorded and imported days");
        check(std::abs(activityStats(accounts, now, "anthropic", "1").lifetimeTokens - 15.0) < 0.001,
              "the other account view does not include the first account");
        check(std::abs(activityStats(accounts, now, "anthropic", "local").lifetimeTokens - 100.0) < 0.001,
              "local session days are their own account");
        check(std::abs(activityStats(accounts, now).lifetimeTokens - 130.0) < 0.001, "the aggregate counts each account once");
        const auto savedAccounts = serializeTokenHistory(accounts);
        const auto restoredAccounts = parseTokenHistory(savedAccounts);
        check(std::abs(activityStats(restoredAccounts, now, "anthropic", "0").lifetimeTokens - 15.0) < 0.001
                  && std::abs(activityStats(restoredAccounts, now, "anthropic", "1").lifetimeTokens - 15.0) < 0.001,
              "a reloaded history keeps the accounts apart");

        const auto legacy = parseTokenHistory("HLHIST1\nD 2026-06-14 10\nT 1 10\n");
        check(legacy.days.size() == 1 && legacy.days.front().providerId.empty() && legacy.deltas.front().providerId.empty(),
              "an older daily total has no provider");
        check(std::abs(activityStats(legacy, now).lifetimeTokens - 10.0) < 0.001, "an unlabeled day stays in the aggregate");
        check(activityStats(legacy, now, "anthropic").lifetimeTokens == 0.0, "an unlabeled day is not assigned to a provider");

        const auto mixed = parseTokenHistory(
            "HLHIST1\n"
            "D 2026-06-14 10\n"
            "D 2026-06-14 4 anthropic\n"
            "D 2026-06-15 3 openai\n"
            "I anthropic local 2026-06-14 7\n"
            "I openai 1 2026-06-15 2\n");
        check(std::abs(activityStats(mixed, now).lifetimeTokens - 26.0) < 0.001, "aggregate adds unlabeled, recorded, and imported days");
        check(std::abs(activityStats(mixed, now, "anthropic").lifetimeTokens - 11.0) < 0.001,
              "a provider filter adds that provider's recorded and imported days");
        check(std::abs(activityStats(mixed, now, "openai").lifetimeTokens - 5.0) < 0.001,
              "another provider filter does not include the first provider or unlabeled days");
        check(activityStats(mixed, now, "anthropic", "0").lifetimeTokens == 0.0,
              "a provider total saved without an account is not given to one account");
        check(std::abs(activityStats(mixed, now, "openai", "1").lifetimeTokens - 2.0) < 0.001,
              "an account filter keeps that account's import and leaves the unlabeled provider day");
        auto tokensOnDay = [](const ActivityCalendar& calendar, CivilDay day) {
            for (const auto& week : calendar.weeks) {
                for (const auto& cell : week.days) {
                    if (cell && cell->day == day) return cell->tokens;
                }
            }
            return -1.0;
        };
        check(std::abs(tokensOnDay(activityCalendar(mixed, now), CivilDay{2026, 6, 14}) - 21.0) < 0.001,
              "the aggregate calendar keeps the unlabeled part of a day");
        check(std::abs(tokensOnDay(activityCalendar(mixed, now, "anthropic"), CivilDay{2026, 6, 14}) - 11.0) < 0.001,
              "the provider calendar omits the unlabeled part of a day");
        check(parseTokenHistory("HLHIST1\nD 2026-06-14 4 anthropic\nD 2026-06-14 9 anthropic\n").days.empty(),
              "a duplicate provider day yields an empty history");
        check(parseTokenHistory("HLHIST1\nD 2026-06-14 4 anthropic 0\nD 2026-06-14 9 anthropic 0\n").days.empty(),
              "a duplicate account day yields an empty history");
        check(parseTokenHistory("HLHIST1\nD 2026-06-14 4 anthropic 0\nD 2026-06-14 9 anthropic 1\n").days.size() == 2,
              "the same day may belong to two accounts");
        check(parseTokenHistory("HLHIST1\nD 2026-06-14 4 anthropic\nD 2026-06-14 9 openai\n").days.size() == 2,
              "the same day may belong to two providers");
        const auto namedAccount = parseTokenHistory("HLHIST1\nD 2026-06-14 4 anthropic extra\n");
        check(namedAccount.days.size() == 1 && namedAccount.days.front().accountId == "extra",
              "the field after the provider is the account");
        check(parseTokenHistory("HLHIST1\nD 2026-06-14 4 anthropic 0 extra\n").days.empty(),
              "an extra account field yields an empty history");
    }
}
} // namespace

int main() {
    Metric metric = percentage(MetricKind::Session, 75.0, 100.0);
    check(metric.remainingFraction().has_value(), "known capacity produces a fraction");
    check(std::abs(*metric.remainingFraction() - 0.25) < 0.0001, "remaining is normalized");

    metric.used = 150.0;
    check(*metric.remainingFraction() == 0.0, "remaining is clamped at zero");
    metric.state = MetricState::Unavailable;
    check(!metric.remainingFraction(), "unavailable values do not appear current");

    metric.state = MetricState::Stale;
    check(metric.remainingFraction().has_value(), "stale metrics retain their last known value");

    Metric credit;
    credit.kind = MetricKind::ApiCredit;
    credit.state = MetricState::Current;
    credit.remaining = 9.0;
    credit.lowBalanceThreshold = 10.0;
    check(*credit.alertRemainingFraction() == 0.09, "API threshold maps to the warning boundary");
    check(!credit.contributesToAggregate(), "unbudgeted API credit does not affect the tray aggregate");
    credit.remaining = 50.0;
    check(credit.remainingFraction().has_value() && std::abs(*credit.remainingFraction() - 0.50) < 0.0001,
          "API credit bar treats $100 as full by default");
    credit.barFullAmount = 200.0;
    check(std::abs(*credit.remainingFraction() - 0.25) < 0.0001, "API credit bar uses the configured full amount");
    credit.remaining = 250.0;
    credit.barFullAmount = 100.0;
    check(*credit.remainingFraction() == 1.0, "API credit bar clamps at the configured full amount");

    const auto green = statusColor(1.0);
    const auto yellow = statusColor(0.5);
    const auto red = statusColor(0.0);
    check(green.green > green.red && green.green > green.blue, "full allowance is green");
    check(yellow.red > 200 && yellow.green > 150, "half allowance is yellow");
    check(red.red > red.green && red.red > red.blue, "empty allowance is red");
    const auto mid = statusColor(0.75);
    const auto idle = applyUsageActivity(mid, 0.0);
    const auto active = applyUsageActivity(mid, 1.0);
    const auto fading = applyUsageActivity(mid, 0.5);
    check(idle.red < mid.red && idle.green < mid.green, "idle usage darkens the row color");
    check(active.red > mid.red && active.green > mid.green, "drawdown brightens the row color");
    check(fading.red > idle.red && fading.red < active.red, "partial activity sits between idle and bright");
    const auto recent = TimePoint{std::chrono::seconds{1'000'000}};
    check(usageActivityBrightness(std::nullopt, recent) == 0.0, "no drawdown is fully idle");
    check(usageActivityBrightness(recent, recent) == 1.0, "a fresh drawdown is fully bright");
    const auto halfway = usageActivityBrightness(recent - kUsageActivityFade / 2, recent);
    check(halfway > 0.4 && halfway < 0.6, "brightness is about half after half the fade");
    check(usageActivityBrightness(recent - kUsageActivityFade, recent) == 0.0, "brightness is idle once the fade ends");
    const auto early = usageActivityBrightness(recent - kUsageActivityFade / 4, recent);
    check(early > halfway, "recent activity stays brighter than the midpoint");
    Metric before = percentage(MetricKind::Session, 20, 100);
    Metric after = percentage(MetricKind::Session, 28, 100);
    check(usageDrewDownSince(before, after), "higher used counts as drawdown");
    after.used = 20.0;
    check(!usageDrewDownSince(before, after), "unchanged used is idle");
    after.used = 5.0;
    check(!usageDrewDownSince(before, after), "a reset to lower used is not drawdown");
    Metric creditBefore;
    creditBefore.remaining = 40.0;
    Metric creditAfter;
    creditAfter.remaining = 32.0;
    check(usageDrewDownSince(creditBefore, creditAfter), "lower remaining credit counts as drawdown");

    ProviderSnapshot polled;
    polled.metrics = {percentage(MetricKind::Session, 10, 100), Metric{MetricKind::ApiCredit, MetricState::Stale}};
    check(!providerPollFailed(polled), "partial results keep the normal poll cadence");
    polled.metrics[0].state = MetricState::AuthenticationRequired;
    check(providerPollFailed(polled), "a provider with nothing current backs off");
    polled.metrics = {Metric{MetricKind::Session, MetricState::Unsupported}};
    check(!providerPollFailed(polled), "unsupported-only results are not a failure");

    const auto moonshot = parseMoonshotBalance(R"({"code":0,"data":{"available_balance":49.58894,"cash_balance":3.0},"status":true})");
    check(moonshot && std::abs(moonshot->amount - 49.58894) < 0.000001 && moonshot->currency == "$",
          "Moonshot sanitized balance fixture parses");
    const auto deepseek = parseDeepSeekBalance(R"({"balance_infos":[{"currency":"CNY","topped_up_balance":"100.00"},{"currency":"USD","topped_up_balance":"7.25"}]})");
    check(deepseek && deepseek->amount == 7.25 && deepseek->currency == "$",
          "DeepSeek sanitized balance fixture prefers USD");
    check(!parseDeepSeekBalance(R"({"error":"redacted"})"), "malformed balance response is rejected");

    const auto claude = parseClaudeUsage(R"({"five_hour":{"utilization":35.0,"resets_at":"2026-02-06T22:00:00Z"},"seven_day":{"utilization":14.0,"resets_at":"2026-02-12T20:00:00Z"},"extra_usage":{"is_enabled":true,"monthly_limit":100000,"used_credits":2500.0}})");
    check(claude && claude->session && std::abs(claude->session->used - 35.0) < 0.001, "Claude session utilization parses");
    check(claude && claude->weekly && std::abs(claude->weekly->used - 14.0) < 0.001, "Claude weekly utilization parses");
    check(claude && claude->credit && std::abs(claude->credit->amount - 975.0) < 0.001, "Claude extra usage is remaining dollars");

    const auto claudeLive = parseClaudeUsage(R"LIVE({"five_hour":{"utilization":11.0,"resets_at":"2026-10-02T12:29:59.926893+00:00","limit_dollars":null,"used_dollars":null,"remaining_dollars":null,"locked_reason":null},"seven_day":{"utilization":48.0,"resets_at":"2026-10-05T22:59:59.926913+00:00","limit_dollars":null,"used_dollars":null,"remaining_dollars":null,"locked_reason":null},"seven_day_oauth_apps":null,"seven_day_opus":null,"seven_day_sonnet":null,"seven_day_cowork":null,"seven_day_omelette":null,"tangelo":null,"iguana_necktie":null,"omelette_promotional":null,"nimbus_quill":null,"cinder_cove":null,"copper_kite":null,"brass_thimble":null,"harbor_lantern":null,"wattle_ember":null,"amber_ladder":null,"amber_cistern":null,"juniper_tide":null,"cedar_ember":null,"amber_gauge":null,"extra_usage":{"is_enabled":false,"monthly_limit":null,"used_credits":null,"utilization":null,"currency":null,"decimal_places":null,"disabled_reason":null,"user_disabled":true,"spend_limit_reached":false,"credits_ever_enabled":true,"daily":null,"weekly":null},"limits":[{"kind":"session","group":"session","percent":11,"severity":"normal","resets_at":"2026-10-02T12:29:59.926893+00:00","scope":null,"is_active":false},{"kind":"weekly_all","group":"weekly","percent":48,"severity":"normal","resets_at":"2026-10-05T22:59:59.926913+00:00","scope":null,"is_active":true},{"kind":"weekly_scoped","group":"weekly","percent":0,"severity":"normal","resets_at":"2026-10-05T23:00:00+00:00","scope":{"model":{"id":null,"display_name":"Fable"},"surface":null},"is_active":false}],"spend":{"used":{"amount_minor":0,"currency":"USD","exponent":2},"limit":null,"percent":0,"severity":"normal","enabled":false,"disabled_reason":null,"cap":null,"balance":null,"auto_reload":null,"disclaimer":"Usage credits cover you when you hit your plan limits. [Learn more](https://support.claude.com/articles/12429409)","can_purchase_credits":false,"can_toggle":false},"member_dashboard_available":false,"seven_day_breakdown":{"as_of":"2026-10-02T12:14:13.952167+00:00","window_started_at":"2026-09-28T22:59:59.926913+00:00","rows":[{"key":"claude_code","display_name":"Claude Code","percent":100},{"key":"chat","display_name":"Chats","percent":0},{"key":"cowork","display_name":"Cowork","percent":0},{"key":"other","display_name":"Other","percent":0}]}})LIVE");
    check(claudeLive && claudeLive->session && claudeLive->session->used == 11.0, "Claude live response session parses");
    check(claudeLive && claudeLive->weekly && claudeLive->weekly->used == 48.0, "Claude live response weekly parses");

    const auto claudeLimits = parseClaudeUsage(R"({"limits":[{"kind":"session","percent":40.0,"resets_at":"2026-03-01T00:00:00Z"},{"kind":"weekly_all","percent":22.0,"resets_at":"2026-03-07T00:00:00Z"}]})");
    check(claudeLimits && claudeLimits->session && claudeLimits->session->used == 40.0, "Claude structured session limit parses");
    check(claudeLimits && claudeLimits->weekly && claudeLimits->weekly->used == 22.0, "Claude structured weekly limit parses");

    const auto codex = parseCodexUsage(R"({"plan_type":"plus","rate_limit":{"primary_window":{"used_percent":6,"reset_at":1738300000,"limit_window_seconds":18000},"secondary_window":{"used_percent":24,"reset_at":1738900000,"limit_window_seconds":604800}},"credits":{"has_credits":true,"balance":5.39}})");
    check(codex && codex->session && codex->session->used == 6.0, "Codex 5-hour window parses");
    check(codex && codex->weekly && codex->weekly->used == 24.0, "Codex weekly window parses");
    check(codex && codex->credit && std::abs(codex->credit->amount - 5.39) < 0.001, "Codex extra credit parses");

    const auto grok = parseGrokBilling(R"({"config":{"monthlyLimit":{"val":60000},"used":{"val":4277},"billingPeriodEnd":"2026-06-01T00:00:00Z"}})");
    check(grok && grok->weekly && grok->weekly->used == 4277.0 && grok->weekly->capacity == 60000.0, "Grok billing credits parse");

    const auto xaiPrepaid = parseXaiPrepaidBalance(R"({"changes":[],"total":{"val":"-4500"}})");
    check(xaiPrepaid && std::abs(xaiPrepaid->amount - 45.0) < 0.001 && xaiPrepaid->currency == "$", "xAI prepaid ledger cents parse");

    const auto kimi = parseKimiCodingUsage(R"({"usage":{"limit":"2048","used":"214","remaining":"1834","resetTime":"2026-01-09T15:23:13Z"},"limits":[{"window":{"duration":300,"timeUnit":"TIME_UNIT_MINUTE"},"detail":{"limit":"200","used":"139","remaining":"61","resetTime":"2026-01-06T13:33:02Z"}}]})");
    check(kimi && kimi->weekly && kimi->weekly->used == 214.0 && kimi->weekly->capacity == 2048.0, "Kimi Code weekly quota parses");
    check(kimi && kimi->session && kimi->session->used == 139.0 && kimi->session->capacity == 200.0, "Kimi Code 5-hour window parses");

    const auto antigravity = parseAntigravityAssist(R"({"availablePromptCredits":850,"planInfo":{"monthlyPromptCredits":1000,"planType":"FREE"}})");
    check(antigravity && antigravity->weekly && antigravity->weekly->used == 150.0 && antigravity->weekly->capacity == 1000.0,
          "Antigravity prompt credits parse");
    const auto models = parseAntigravityModels(R"({"models":{"gemini":{"quotaInfo":{"remainingFraction":0.25,"resetTime":"2026-04-01T00:00:00Z"}},"flash":{"quotaInfo":{"remainingFraction":0.8}}}})");
    check(models && models->session && std::abs(models->session->used - 75.0) < 0.001, "Antigravity most exhausted model quota parses");

    ProviderSnapshot a{"a", "A", true, {percentage(MetricKind::Session, 20, 100)}};
    ProviderSnapshot b{"b", "B", true, {percentage(MetricKind::Weekly, 95, 100)}};
    ProviderSnapshot disabled{"c", "C", false, {percentage(MetricKind::Weekly, 100, 100)}};
    auto aggregate = aggregateStatus({a, b, disabled});
    check(aggregate.providerId == "b", "aggregate selects the most exhausted enabled provider");
    check(std::abs(*aggregate.remainingFraction - 0.05) < 0.0001, "aggregate retains remaining fraction");

    Metric unsupported;
    unsupported.state = MetricState::Unsupported;
    check(!unsupported.visibleOnMonitor(), "unsupported metrics stay off the monitor");
    Metric authRequired;
    authRequired.state = MetricState::AuthenticationRequired;
    check(!authRequired.visibleOnMonitor(), "unauthenticated metrics without a value stay off the monitor");
    Metric authNotice = authRequired;
    authNotice.announceAuthentication = true;
    check(authNotice.visibleOnMonitor(), "a rejected credential is shown even without a last value");
    Metric authWithLast = percentage(MetricKind::Session, 40, 100);
    authWithLast.state = MetricState::AuthenticationRequired;
    check(authWithLast.visibleOnMonitor(), "authentication failure keeps last known usage on the monitor");
    check(authWithLast.remainingFraction().has_value() && std::abs(*authWithLast.remainingFraction() - 0.60) < 0.0001,
          "authentication failure still reports the last remaining fraction");
    ProviderSnapshot authFailed{"af", "AF", true, {authWithLast}};
    check(monitorIncludesProvider(authFailed), "accounts with last known usage stay on the monitor after auth failure");
    check(providerAuthenticationFailed(authFailed), "visible authentication-required metrics mark the provider as failed");
    check(!providerAuthenticationFailed(a), "current usage is not an authentication failure");
    ProviderSnapshot mixedAuth{"ma", "MA", true, {percentage(MetricKind::Session, 20, 100), authWithLast}};
    check(providerAuthenticationFailed(mixedAuth), "any visible authentication-required metric marks the provider row");
    ProviderSnapshot authHidden{"ah", "AH", true, {authRequired}};
    check(!providerAuthenticationFailed(authHidden), "authentication-required metrics without a value do not mark the row");
    ProviderSnapshot authAnnounced{"aa", "AA", true, {authNotice}};
    check(monitorIncludesProvider(authAnnounced), "a rejected credential stays on the monitor without a last value");
    check(providerAuthenticationFailed(authAnnounced), "announced authentication failure marks the provider row");
    check(shouldAutoReauthenticate(true, true, false), "official sign-in accounts auto-reauthenticate once");
    check(!shouldAutoReauthenticate(true, true, true), "auto-reauth runs only once per failure");
    check(!shouldAutoReauthenticate(true, false, false), "paste-only API keys are not auto-reauthenticated");
    check(!shouldAutoReauthenticate(false, true, false), "providers without official sign-in are not auto-reauthenticated");
    check(extractAuthorizationCode("https://example/cb?code=ABCDEFGH1234&state=s").value_or("") == "ABCDEFGH1234",
          "OAuth redirect codes are extracted");
    check(extractAuthorizationCode("ABCDEFGH1234#state-value").value_or("") == "ABCDEFGH1234",
          "Claude code#state paste form is extracted");
    check(!extractAuthorizationCode("no-code-here"), "text without an authorization code is rejected");
    Metric unavailable;
    unavailable.state = MetricState::Unavailable;
    check(!unavailable.visibleOnMonitor(), "unavailable metrics stay off the monitor");
    check(percentage(MetricKind::Session, 20, 100).visibleOnMonitor(), "current metrics appear on the monitor");
    Metric stale = percentage(MetricKind::ApiCredit, 0, 0);
    stale.state = MetricState::Stale;
    stale.remaining = 4.5;
    stale.capacity.reset();
    stale.used.reset();
    check(stale.visibleOnMonitor(), "stale configured metrics remain visible");
    Metric error;
    error.state = MetricState::Error;
    check(!error.visibleOnMonitor(), "error metrics without a value stay off the monitor");
    error.remaining = 2.0;
    check(error.visibleOnMonitor(), "error metrics with a last known value remain visible");
    Metric refreshing;
    refreshing.state = MetricState::Refreshing;
    refreshing.kind = MetricKind::ApiCredit;
    check(!refreshing.visibleOnMonitor(), "refreshing metrics without a value do not occupy a usage row");
    refreshing.remaining = 9.0;
    check(refreshing.visibleOnMonitor(), "refreshing metrics keep their row when a value is already known");
    check(monitorIncludesProvider(a), "enabled providers with data appear on the monitor");
    check(!monitorIncludesProvider(disabled), "disabled providers are omitted even with data");
    ProviderSnapshot unconfigured{"u", "U", true, {authRequired, unavailable}};
    check(!monitorIncludesProvider(unconfigured), "enabled providers without configured data are omitted");

    const auto period1 = TimePoint{std::chrono::seconds{100}};
    const auto period2 = TimePoint{std::chrono::seconds{200}};
    AlertEngine alerts;
    ProviderSnapshot warning{"a", "A", true, {percentage(MetricKind::Session, 91, 100, period1)}};
    check(alerts.observe(warning).size() == 1, "threshold crossing warns once");
    check(alerts.observe(warning).empty(), "warning is deduplicated in one period");
    AlertEngine restoredAlerts;
    restoredAlerts.restoreWarning("a", MetricKind::Session, period1);
    check(restoredAlerts.observe(warning).empty(), "persisted warning state remains deduplicated after restart");
    warning.metrics[0] = percentage(MetricKind::Session, 1, 100, period2);
    auto resetEvents = alerts.observe(warning);
    check(resetEvents.size() == 1 && resetEvents[0].kind == AlertKind::AllowanceReset,
          "changed reset period produces one reset event");

    AlertEngine inferred;
    ProviderSnapshot sample{"a", "A", true, {percentage(MetricKind::Session, 95, 100)}};
    const auto initialEvents = inferred.observe(sample);
    check(initialEvents.size() == 1, "initial exhausted observation warns");
    sample.metrics[0] = percentage(MetricKind::Session, 10, 100);
    check(inferred.observe(sample).empty(), "one large increase does not infer a reset");
    check(inferred.observe(sample).size() == 1, "two consecutive increases infer one reset");

    const std::int64_t nowMs = 1'700'000'000'000LL;
    TokenRecord fresh;
    fresh.accessToken = "access-fresh";
    fresh.refreshToken = "refresh-fresh";
    fresh.expiresAtMs = nowMs + 3'600'000;
    TokenRecord expiredBare;
    expiredBare.accessToken = "access-expired";
    expiredBare.expiresAtMs = nowMs - 1'000;
    TokenRecord stillRefreshable;
    stillRefreshable.accessToken = "access-stale";
    stillRefreshable.refreshToken = "refresh-stale";
    stillRefreshable.expiresAtMs = nowMs - 1'000;
    TokenRecord empty;
    check(pickLatestValidToken(fresh, expiredBare, nowMs) == TokenPick::Left, "later unexpired token beats expired token without refresh");
    check(pickLatestValidToken(stillRefreshable, empty, nowMs) == TokenPick::Left, "still-refreshable token beats empty record");
    check(pickLatestValidToken(expiredBare, stillRefreshable, nowMs) == TokenPick::Right, "refreshable expired token beats expired access-only token");
    TokenRecord sameA = fresh;
    TokenRecord sameB = fresh;
    sameB.expiresAtMs = nowMs + 9'000'000;
    check(pickLatestValidToken(sameA, sameB, nowMs) == TokenPick::Tie, "equal access and refresh tokens are a no-op");

    check(cliLoginMayRecoverSlot("acct-2", "acct-2", true, false, false), "matching identity recovers an unselected slot");
    check(!cliLoginMayRecoverSlot("acct-2", "acct-1", true, true, false), "a different account never recovers a known slot");
    check(!cliLoginMayRecoverSlot("acct-2", "", true, true, false), "an unidentified login never recovers a known slot");
    check(cliLoginMayRecoverSlot("", "acct-1", false, true, false), "single-account providers adopt any live CLI login");
    check(cliLoginMayRecoverSlot("", "acct-1", true, true, false), "selected unidentified slot adopts the CLI login");
    check(!cliLoginMayRecoverSlot("", "acct-1", true, false, false), "unselected unidentified slot is never guessed");
    check(!cliLoginMayRecoverSlot("", "acct-1", true, true, true), "a login owned by another slot is not adopted");
    TokenRecord codexLike;
    codexLike.accessToken = "cli-codex-access";
    codexLike.refreshToken = "cli-codex-refresh";
    TokenRecord storedWithExpiry;
    storedWithExpiry.accessToken = "hl-access";
    storedWithExpiry.refreshToken = "hl-refresh";
    storedWithExpiry.expiresAtMs = nowMs + 3'600'000;
    check(pickLatestValidToken(codexLike, storedWithExpiry, nowMs) != TokenPick::Right,
          "Codex-like token with no expiry does not automatically lose to a stored token that only has a future expires_at");
    const char* codexRecent = R"({"tokens":{"access_token":"cli-new","refresh_token":"cli-new-r"},"last_refresh":"2026-01-01T12:00:00Z"})";
    const auto parsedRecent = parseCliTokenRecord(CliCredentialFormat::CodexTokens, codexRecent);
    TokenRecord olderStored;
    olderStored.accessToken = "hl-old";
    olderStored.refreshToken = "hl-old-r";
    olderStored.expiresAtMs = nowMs + 3'600'000;
    check(parsedRecent.observedAtMs.has_value(), "Codex last_refresh is parsed as recency");
    check(pickLatestValidToken(parsedRecent, olderStored, nowMs) == TokenPick::Left,
          "newer Codex last_refresh beats a stored token that only has a future expiry");
    check(cliFormatForProvider("deepseek") == std::nullopt, "DeepSeek has no CLI config path");
    check(cliHomeRelativePaths("openai").size() == 1 && cliHomeRelativePaths("openai")[0] == ".codex/auth.json",
          "Codex CLI path is relative to the user home");
    check(cliHomeRelativePaths("anthropic")[0] == ".claude/.credentials.json", "Claude CLI path is relative to the user home");
    check(cliHomeRelativePaths("deepseek").empty(), "DeepSeek has no CLI relative path");
    const auto kimiPaths = cliHomeRelativePaths("moonshot");
    check(std::find(kimiPaths.begin(), kimiPaths.end(), ".kimi-code/credentials/kimi-code.json") != kimiPaths.end(),
          "Kimi Code CLI OAuth path is relative to the user home");
    check(std::find(kimiPaths.begin(), kimiPaths.end(), ".kimi/credentials/kimi-code.json") != kimiPaths.end(),
          "legacy Kimi CLI OAuth path is still searched");
    const auto kimiOauth = parseCliTokenRecord(CliCredentialFormat::KimiCredentials,
        R"({"access_token":"kimi-access","refresh_token":"kimi-r","expires_at":1738000000,"token_type":"Bearer","scope":"kimi-code"})");
    check(kimiOauth.accessToken == "kimi-access" && kimiOauth.refreshToken == "kimi-r",
          "Kimi Code credentials JSON parses access and refresh tokens");
    const auto kimiKey = parseCliTokenRecord(CliCredentialFormat::KimiCredentials, R"({"api_key":"sk-kimi"})");
    check(kimiKey.accessToken == "sk-kimi", "Kimi api_key is accepted as a CLI credential");
    TokenRecord expiredKimi;
    expiredKimi.accessToken = "expired-access";
    expiredKimi.refreshToken = "kimi-refresh";
    expiredKimi.expiresAtMs = nowMs - 60'000;
    check(tokenRecordUsable(expiredKimi, nowMs), "expired Kimi access token remains usable when a refresh token is present");
    check(kimiOauth.expiresAtMs.has_value() && *kimiOauth.expiresAtMs == 1'738'000'000'000LL,
          "Kimi expires_at seconds are converted to milliseconds");
    check(wslUserSettingKey("Ubuntu-24.04", "albert") == "WslUser.Ubuntu-24.04/albert",
          "WSL user setting key is distro/user");
    check(quoteWindowsCommandLineArgument(L"Ubuntu 24.04") == L"\"Ubuntu 24.04\"",
          "Windows command arguments with spaces are quoted");
    check(quoteWindowsCommandLineArgument(L"Ubuntu\"; calc.exe") == L"\"Ubuntu\\\"; calc.exe\"",
          "embedded quotes cannot terminate a Windows command argument");
    check(quoteWindowsCommandLineArgument(L"C:\\WSL home\\") == L"\"C:\\WSL home\\\\\"",
          "trailing backslashes are escaped before a closing Windows command quote");
    check(quoteWindowsCommandLineArgument(L"") == L"\"\"", "empty Windows command arguments are preserved");
    std::wstring wslCommand;
    appendWindowsCommandLineArgument(wslCommand, L"wsl.exe");
    appendWindowsCommandLineArgument(wslCommand, L"-d");
    appendWindowsCommandLineArgument(wslCommand, L"Ubuntu 24.04");
    check(wslCommand == L"\"wsl.exe\" \"-d\" \"Ubuntu 24.04\"",
          "Windows command arguments remain separately quoted");
    const auto wslReadCommand = buildWslCatCommandLine(
        L"wsl.exe", L"Ubuntu 24.04", L"alice", L"/home/alice/.config/token$(id).json");
    check(wslReadCommand
              == L"\"wsl.exe\" -d \"Ubuntu 24.04\" -u \"alice\" --exec cat -- \"/home/alice/.config/token$(id).json\"",
          "WSL credential reads pass flags unquoted so wsl.exe does not hand them to bash");
    TokenRecord oldest;
    oldest.accessToken = "a";
    oldest.refreshToken = "ar";
    oldest.observedAtMs = nowMs - 3'000;
    TokenRecord middle = oldest;
    middle.accessToken = "b";
    middle.refreshToken = "br";
    middle.observedAtMs = nowMs - 2'000;
    TokenRecord newest = oldest;
    newest.accessToken = "c";
    newest.refreshToken = "cr";
    newest.observedAtMs = nowMs - 1'000;
    const TokenRecord three[] = {oldest, newest, middle};
    check(pickLatestValidTokenIndex(three, nowMs) == 1, "latest among several CLI records is the newest observed token");

    const char* claudeExisting = R"({"claudeAiOauth":{"accessToken":"old-access","refreshToken":"old-refresh","expiresAt":111,"subscriptionType":"max"},"mcpOAuth":{"server":"kept"}})";
    TokenRecord claudeWinner;
    claudeWinner.accessToken = "new-access";
    claudeWinner.refreshToken = "new-refresh";
    claudeWinner.expiresAtMs = 222;
    const auto claudeMerged = mergeCliCredentialJson(CliCredentialFormat::ClaudeOauth, claudeExisting, claudeWinner);
    const auto claudeParsed = parseCliTokenRecord(CliCredentialFormat::ClaudeOauth, claudeMerged);
    check(claudeParsed.accessToken == "new-access" && claudeParsed.refreshToken == "new-refresh" && claudeParsed.expiresAtMs == 222,
          "Claude write-back updates OAuth access, refresh, and expiry");
    check(claudeMerged.find("\"mcpOAuth\"") != std::string::npos && claudeMerged.find("\"server\":\"kept\"") != std::string::npos
              && claudeMerged.find("\"subscriptionType\":\"max\"") != std::string::npos,
          "Claude write-back leaves extra keys intact");

    const char* codexExisting = R"({"tokens":{"id_token":"keep-id","access_token":"old","refresh_token":"old-r"},"last_refresh":"keep-meta","account_id":"acct-1"})";
    TokenRecord codexWinner;
    codexWinner.accessToken = "codex-new";
    codexWinner.refreshToken = "codex-new-r";
    codexWinner.accountId = "acct-2";
    const auto codexMerged = mergeCliCredentialJson(CliCredentialFormat::CodexTokens, codexExisting, codexWinner);
    const auto codexParsed = parseCliTokenRecord(CliCredentialFormat::CodexTokens, codexMerged);
    check(codexParsed.accessToken == "codex-new" && codexParsed.refreshToken == "codex-new-r" && codexParsed.accountId == "acct-2",
          "Codex write-back updates tokens.access_token and refresh_token");
    check(codexMerged.find("\"id_token\":\"\"") != std::string::npos && codexMerged.find("\"last_refresh\":\"keep-meta\"") != std::string::npos,
          "Codex account switch clears old identity while preserving unrelated metadata");
    TokenRecord codexRefreshed = codexWinner;
    codexRefreshed.observedAtMs = 1790945000000; // 2026-10-02T12:43:20Z
    const auto stampedMerged = mergeCliCredentialJson(CliCredentialFormat::CodexTokens, codexExisting, codexRefreshed);
    check(stampedMerged.find("\"last_refresh\":\"2026-10-02T12:43:20.000Z\"") != std::string::npos
              && parseCliTokenRecord(CliCredentialFormat::CodexTokens, stampedMerged).observedAtMs == codexRefreshed.observedAtMs,
          "Codex write-back stamps last_refresh for the tokens it writes");

    // Payload: {"https://api.openai.com/auth":{"chatgpt_account_id":"acct-jwt"}}
    const std::string codexJwt = "e30.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9hY2NvdW50X2lkIjoiYWNjdC1qd3QifX0.sig";
    check(chatgptAccountIdFromJwt(codexJwt) == "acct-jwt" && chatgptAccountIdFromJwt("opaque-token").empty(),
          "ChatGPT account id decodes from the JWT payload");
    TokenRecord codexNoAccount;
    codexNoAccount.accessToken = codexJwt;
    codexNoAccount.refreshToken = "codex-new-r";
    const auto jwtMerged = mergeCliCredentialJson(CliCredentialFormat::CodexTokens, codexExisting, codexNoAccount);
    check(jwtMerged.find("\"account_id\":\"\"") == std::string::npos
              && parseCliTokenRecord(CliCredentialFormat::CodexTokens, jwtMerged).accountId == "acct-jwt",
          "Codex write-back without an account id takes it from the access token");

    const char* agyExisting = R"({"token":{"access_token":"agy-old","token_type":"Bearer","refresh_token":"agy-old-r","expiry":"2026-09-28T09:50:34.322532681Z"},"auth_method":"consumer"})";
    const auto agyParsed = parseCliTokenRecord(CliCredentialFormat::GeminiOauth, agyExisting);
    check(agyParsed.accessToken == "agy-old" && agyParsed.refreshToken == "agy-old-r" && agyParsed.expiresAtMs && *agyParsed.expiresAtMs > 1'000'000'000'000LL,
          "Antigravity CLI nested oauth token parses access, refresh, and expiry");
    TokenRecord agyWinner;
    agyWinner.accessToken = "agy-new";
    agyWinner.refreshToken = "agy-new-r";
    agyWinner.expiresAtMs = 1'758'000'000'000LL;
    const auto agyMerged = mergeCliCredentialJson(CliCredentialFormat::GeminiOauth, agyExisting, agyWinner);
    const auto agyRoundTrip = parseCliTokenRecord(CliCredentialFormat::GeminiOauth, agyMerged);
    check(agyRoundTrip.accessToken == "agy-new" && agyRoundTrip.refreshToken == "agy-new-r" && agyRoundTrip.expiresAtMs && *agyRoundTrip.expiresAtMs == 1'758'000'000'000LL,
          "Antigravity CLI write-back updates the nested token");
    check(agyMerged.find("\"auth_method\":\"consumer\"") != std::string::npos && agyMerged.find("\"token_type\":\"Bearer\"") != std::string::npos,
          "Antigravity CLI write-back leaves the agy envelope intact");
    const auto antigravityPaths = cliHomeRelativePaths("antigravity");
    check(std::ranges::find(antigravityPaths, ".gemini/antigravity-cli/antigravity-oauth-token") != antigravityPaths.end(),
          "Antigravity CLI credential path is discovered");

    const char* geminiExisting = R"({"access_token":"old","refresh_token":"old-r","token_type":"Bearer","scope":"keep-scope","expiry_date":1})";
    TokenRecord geminiWinner;
    geminiWinner.accessToken = "gem-new";
    geminiWinner.refreshToken = "gem-new-r";
    geminiWinner.expiresAtMs = 999;
    const auto geminiMerged = mergeCliCredentialJson(CliCredentialFormat::GeminiOauth, geminiExisting, geminiWinner);
    const auto geminiParsed = parseCliTokenRecord(CliCredentialFormat::GeminiOauth, geminiMerged);
    check(geminiParsed.accessToken == "gem-new" && geminiParsed.refreshToken == "gem-new-r" && geminiParsed.expiresAtMs == 999,
          "Gemini/Antigravity write-back updates access, refresh, and expiry");
    check(geminiMerged.find("\"token_type\":\"Bearer\"") != std::string::npos && geminiMerged.find("\"scope\":\"keep-scope\"") != std::string::npos,
          "Gemini write-back leaves extra keys intact");

    TokenRecord fromEmpty;
    fromEmpty.accessToken = "created";
    fromEmpty.refreshToken = "created-r";
    const auto fromEmptyJson = mergeCliCredentialJson(CliCredentialFormat::ClaudeOauth, "", fromEmpty);
    const auto fromEmptyParsed = parseCliTokenRecord(CliCredentialFormat::ClaudeOauth, fromEmptyJson);
    check(fromEmptyParsed.accessToken == "created" && fromEmptyJson.find("claudeAiOauth") != std::string::npos,
          "empty CLI body becomes a well-formed Claude credential file");
    const char* malformed = "NOT-JSON leftover structure mcpOAuth";
    const auto fromMalformed = mergeCliCredentialJson(CliCredentialFormat::ClaudeOauth, malformed, fromEmpty);
    const auto fromMalformedParsed = parseCliTokenRecord(CliCredentialFormat::ClaudeOauth, fromMalformed);
    check(fromMalformedParsed.accessToken == "created" && fromMalformed.find("NOT-JSON") == std::string::npos,
          "malformed CLI body is not a destructive overlay of leftover text");


    TokenRecord firstAccount;
    firstAccount.accessToken = "first-token";
    firstAccount.refreshToken = "first-refresh";
    firstAccount.accountId = "first-account";
    TokenRecord secondAccount = firstAccount;
    secondAccount.accountId = "second-account";
    check(!sameCredentialAccount(firstAccount, secondAccount), "different account IDs cannot overwrite each other");
    secondAccount = firstAccount;
    secondAccount.accessToken = "renewed-token";
    check(sameCredentialAccount(firstAccount, secondAccount), "renewed token remains in its account");
    secondAccount.accountId.clear();
    check(sameCredentialAccount(firstAccount, secondAccount), "matching refresh token proves identity without account ID");
    secondAccount.refreshToken = "other-refresh";
    check(!sameCredentialAccount(firstAccount, secondAccount), "unidentified newer CLI login cannot replace selected account");
    check(!sameCredentialAccount(TokenRecord{}, TokenRecord{}), "empty credentials do not prove identity");
    codexWinner.idToken = "new-account-identity";
    const auto identityMerged = mergeCliCredentialJson(CliCredentialFormat::CodexTokens, codexExisting, codexWinner);
    check(parseCliTokenRecord(CliCredentialFormat::CodexTokens, identityMerged).idToken == "new-account-identity",
          "Codex ID token follows selected account");
    codexWinner.accountId.clear();
    const auto clearedIdentity = mergeCliCredentialJson(CliCredentialFormat::CodexTokens, identityMerged, codexWinner);
    check(parseCliTokenRecord(CliCredentialFormat::CodexTokens, clearedIdentity).accountId.empty(),
          "missing new account ID never retains previous account ID");

    TokenRecord apiAccount;
    apiAccount.accessToken = "sk-test-account";
    const auto apiMerged = mergeCliCredentialJson(CliCredentialFormat::CodexTokens, identityMerged, apiAccount);
    check(parseCliTokenRecord(CliCredentialFormat::CodexTokens, apiMerged).accessToken == apiAccount.accessToken,
          "Codex API key selection replaces OAuth credentials");
    const auto oauthAgain = mergeCliCredentialJson(CliCredentialFormat::CodexTokens, apiMerged, codexWinner);
    check(parseCliTokenRecord(CliCredentialFormat::CodexTokens, oauthAgain).accessToken == codexWinner.accessToken,
          "Codex OAuth selection removes overriding API key");
    const auto unknownExpiry = mergeCliCredentialJson(CliCredentialFormat::GeminiOauth, geminiExisting, firstAccount);
    check(!parseCliTokenRecord(CliCredentialFormat::GeminiOauth, unknownExpiry).expiresAtMs,
          "new account does not inherit another account's expiry");

    ProviderSnapshot rotating;
    Metric limit;
    const auto rotationNow = std::chrono::system_clock::now();
    limit.state = MetricState::Current;
    limit.observedAt = rotationNow;
    limit.remaining = 0;
    limit.resetAt = rotationNow + std::chrono::hours(2);
    rotating.metrics = {limit};
    check(exhaustedUntil(rotating, rotationNow) == limit.resetAt, "confirmed exhaustion waits for reset");
    rotating.metrics[0].state = MetricState::Stale;
    check(!exhaustedUntil(rotating, rotationNow), "stale exhaustion cannot rotate accounts");
    rotating.metrics[0].state = MetricState::AuthenticationRequired;
    check(!exhaustedUntil(rotating, rotationNow), "authentication failure is not quota exhaustion");
    rotating.metrics[0] = limit;
    rotating.metrics[0].remaining = 1;
    check(!exhaustedUntil(rotating, rotationNow), "low positive allowance does not rotate");
    rotating.metrics[0] = limit;
    rotating.metrics[0].resetAt.reset();
    check(exhaustedUntil(rotating, rotationNow) == TimePoint::max(), "unknown reset does not cause rotation loops");
    rotating.metrics.push_back(limit);
    check(exhaustedUntil(rotating, rotationNow) == TimePoint::max(), "all blocking limits must recover");
    rotating.metrics = {limit};
    rotating.metrics[0].observedAt = rotationNow - std::chrono::hours(1);
    check(!exhaustedUntil(rotating, rotationNow), "old observations cannot rotate");

    check(shouldBackgroundSyncProvider(true, true), "enabled connected providers keep CLI sync");
    check(!shouldBackgroundSyncProvider(false, true), "disabled providers do not background-sync");
    check(!shouldBackgroundSyncProvider(true, false), "disconnected providers do not background-sync until Connect");
    check(!shouldBackgroundSyncProvider(false, false), "disabled disconnected providers stay unsynced");

    testActivityHistory();

    if (failures == 0) {
        std::cout << "All core tests passed\n";
    }
    return failures == 0 ? 0 : 1;
}
