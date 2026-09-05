#include "alert_engine.hpp"
#include "model.hpp"
#include "provider_parsing.hpp"
#include "token_sync.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>
#include <string>

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
    const auto idle = applyUsageActivity(mid, false);
    const auto active = applyUsageActivity(mid, true);
    check(idle.red < mid.red && idle.green < mid.green, "idle usage darkens the row color");
    check(active.red > mid.red && active.green > mid.green, "drawdown brightens the row color");
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
    Metric authWithLast = percentage(MetricKind::Session, 40, 100);
    authWithLast.state = MetricState::AuthenticationRequired;
    check(authWithLast.visibleOnMonitor(), "authentication failure keeps last known usage on the monitor");
    check(authWithLast.remainingFraction().has_value() && std::abs(*authWithLast.remainingFraction() - 0.60) < 0.0001,
          "authentication failure still reports the last remaining fraction");
    ProviderSnapshot authFailed{"af", "AF", true, {authWithLast}};
    check(monitorIncludesProvider(authFailed), "accounts with last known usage stay on the monitor after auth failure");
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
    check(codexMerged.find("\"id_token\":\"keep-id\"") != std::string::npos && codexMerged.find("\"last_refresh\":\"keep-meta\"") != std::string::npos,
          "Codex write-back leaves extra keys intact");

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

    if (failures == 0) {
        std::cout << "All core tests passed\n";
    }
    return failures == 0 ? 0 : 1;
}
