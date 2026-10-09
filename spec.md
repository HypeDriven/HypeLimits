# HypeLimits Specification

## 1. Purpose

HypeLimits is a lightweight system tray application that gives users one place to monitor AI subscription allowances. It tracks session limits, weekly limits, and remaining prepaid or topped-up API funds where providers expose that data.

Initial provider targets:

- Anthropic Claude
- OpenAI Codex
- Moonshot Kimi
- DeepSeek
- xAI Grok
- Google Antigravity

Provider capabilities differ. The application must show unavailable metrics as unsupported or unknown rather than estimating or presenting stale values as current.

## 2. Technology and Platforms

- The application is written in modern C++ (C++23 preferred; C++20 minimum).
- The application uses Windows APIs for tray integration, windows, menus, settings, networking, notifications, audio, credential storage, launch-at-login, and official sign-in. It has no third-party runtime or build dependencies. The Windows WebView2 runtime and the current user's installed-browser cookie and credential stores may be used for official OAuth and device-code sign-in. Login, MFA, and consent pages are completed by the user; the application does not auto-click those controls.
- CMake is used for builds and dependency management.
- The desktop target is Windows 11.
- Provider integrations are isolated behind a stable adapter interface so they can evolve independently.
- The process stays background-class in every scheduler the OS exposes: idle CPU class, disabled priority boost, low memory and page priority, EcoQoS execution-speed power throttling, and a background-mode worker thread for network refresh (lowest thread priority, thread EcoQoS, background I/O). It must not raise timer resolution or request multimedia or foreground priority.

## 3. Core Behavior

### 3.1 Allowance monitoring

For every configured provider, HypeLimits should retrieve and display each metric the provider officially makes available:

- Session allowance used and remaining, including the reset time.
- Weekly allowance used and remaining, including the reset time.
- Remaining topped-up or prepaid API credit, including currency.

Each metric stores its value, capacity where known, observation time, reset time where known, and state: current, refreshing, stale, unavailable, unsupported, or error.

Data refreshes on startup, on a configurable polling interval, when the user selects **Refresh now**, and after network connectivity returns. Polling must use bounded timeouts, exponential backoff, provider rate-limit guidance, and small randomized jitter. Backoff is per provider: a provider whose poll returned nothing current (stale, errored, or rejected) skips scheduled polls for up to 32 intervals, while every other provider keeps the base interval. Partial results do not count as failure, and Refresh now, reconnects, account switches, and network-change refreshes poll every provider. A scheduled poll that cannot start (for example while a sign-in owns the UI) is rescheduled rather than dropped, so polling never stops silently. A failed refresh must retain the last successful value, mark it stale, and expose a short diagnostic message. An authentication failure (rejected or missing credential) must likewise retain the last successful usage, mark the metric authentication-required, and keep it visible until a new value is fetched.

When a stored access token is rejected or expired, first obtain a new access token with the stored refresh token (silent, no UI). If that refresh is missing or rejected, and the account was connected with the provider's official OAuth or device-code login, try silent re-auth only: CLI session, imported cookies, stored credentials, and a hidden WebView that must not appear on screen. Automatic re-auth must not open a visible browser or WebView. If it cannot finish unattended, leave the orange row and wait. Clicking that row, or Connect in Options, is a manual flow the user started: show the official login UI and let the user click every control. Do not auto-click login, MFA, or consent.

### 3.2 Normalized status

For each percentage-based limit:

`exhaustion = used / capacity * 100`

`remaining = 100 - exhaustion`

The aggregate tray status is the most exhausted currently available percentage-based limit across all enabled providers. Currency balances without a configured budget or low-balance threshold do not contribute to this aggregate.

The tray icon transitions continuously from bright green at 100% remaining to yellow at 50% remaining and red at 0% remaining. Unknown or disconnected status uses neutral gray. This color appears on a simple monochrome gauge-style tray glyph with adequate contrast.

The tray tooltip summarizes the most constrained limit, its remaining percentage, and its reset time. Right-clicking the tray icon opens a menu containing **Show/Hide Monitor**, **Activity**, **Refresh now**, **Options**, and **Quit**. **Activity** opens the token history in §4.3. **Options** opens the detailed provider view described below.

### 3.3 Alerts and reset detection

- Play a short, unobtrusive warning tone when a percentage-based limit first reaches or exceeds 90% exhaustion (10% or less remaining).
- A configured API-credit low-balance threshold is treated as 90% exhaustion for alerting purposes.
- Alert once per metric per reset period; do not replay the warning on every poll.
- When a previously depleted or constrained limit refreshes to a new allowance period, play a distinct short, cheerful sound.
- Detect refreshes primarily through a changed provider reset period or reset timestamp. If unavailable, detect a large increase in remaining allowance only when supported by consecutive observations, to avoid false alerts.
- Sound alerts can be disabled independently. The settings view includes preview buttons and volume control, and respects the operating system's output device and mute state.

### 3.4 Multiple accounts and rotation

Each provider supports up to 100 credential slots in Windows Credential Manager, with one selected account. Existing credentials remain Account 1. **Add account** creates a separate slot through the existing subscription, pasted-token/API-key, or CLI-import flow; cancelling preserves the previous selection. **Log in / Connect** updates the selected slot. **Disconnect** removes that slot only. Slot numbers identify accounts in menus and Options.

Right-click a provider row in the floating monitor, or use **Choose account** in its Options tab, to select a saved credential. Explicit selection writes that credential to the provider's supported Windows CLI files and discovered WSL homes, respecting per-WSL-user exclusions. This action authorizes write-back independently of the general background-sync checkboxes. Existing alternate CLI paths are updated too, preserving unrelated JSON fields. Required parent directories are created. A failed write leaves the selection unchanged and attempts to roll back earlier writes; Options reports sync failures. DeepSeek has no supported official CLI credential file, so its selection applies within HypeLimits only. Already-running clients must support credential-file reload for seamless continuation; HypeLimits does not restart clients or retry their requests.

Selected accounts cannot be replaced by an unrelated newer CLI login. Background CLI imports must prove account identity through matching account IDs or tokens. Refresh-token renewal stays within the selected credential slot and propagates to its selected CLI targets. Unattended browser re-auth is disabled for managed accounts because it cannot guarantee account identity; a rejected refresh token requires manual sign-in. Cached usage, official-login flags, exhaustion deadlines, and alert identities are account-specific.

Each provider has an **Automatically rotate accounts when allowance runs out** checkbox, off by default. After polling returns a fresh, current zero remaining allowance (or used at least equal to a positive capacity), rotation chooses the next saved slot not known to be exhausted, syncs it, and polls again. Low-but-positive allowance, authentication errors, missing data, and stale observations do not trigger rotation. Exhausted slots remain excluded until every reported depleted limit resets; an unknown reset requires manual selection to retry. If all slots are depleted, retain the current account. Automatic sync errors are reported without opening a dialog. Selection and credential edits are blocked during refresh/sign-in to prevent results or renewed tokens crossing accounts.

## 4. User Interface

The interface is minimal, dark-mode-first, keyboard accessible, and visually quiet. It follows system scaling and uses the system font. Color is not the only status indicator.

### 4.1 Floating monitor

The primary interface is one compact floating window intended to remain open most of the time. It shows the smallest set of UI that is logically relevant: one small row per **configured provider**, showing its selected account, and only the metrics that have their prerequisite data.

A provider is configured when the user has completed the Options setup that supplies that account's connection data (for example a stored API key) and the provider remains enabled. Enabled-but-unconfigured providers, disabled providers, and providers with nothing displayable do not appear. Session, weekly, and API-credit bars are drawn only when that metric has a value to show (used, remaining, or capacity) in current, stale, refreshing, error, or authentication-required state. A refreshing, error, or authentication-required metric with no amount yet does not get a row, so bars are not shown and then hidden. Unsupported and unavailable metrics, and authentication-required metrics with no last known value, are omitted rather than shown as empty bars, placeholders, or "?".

When no account is configured, the monitor shows a short instruction to configure an account in Options, and nothing else.

Each visible row has the provider name and a thin labeled progress bar per visible metric. Bars include a concise text or icon label so their meaning and status do not depend on color alone. Labels, names, empty-state copy, and bar captions are measured and laid out so they fit in full; text is never ellipsized or clipped. If used increased or remaining fell since the last successful poll, that provider row is drawn a bit brighter; if usage looks idle, the row is drawn darker. With multiple accounts, a row that is neither the selected account nor drawing down is drawn at 50% strength so unused accounts stand out at a glance.

The floating monitor:

- Uses minimal chrome and consumes as little screen space as practical.
- Can be moved, shown or hidden from the tray menu, and optionally kept above other windows.
- Has a user-resizable width. Dragging the right edge, bottom edge, or bottom-right corner uniformly and smoothly scales the entire monitor: the layout is rendered to an offscreen bitmap and stretched with high-quality filtering, so resize does not reflow or crop. Height follows the scaled content, and there is no upper size limit. The chosen width is remembered across launches.
- Remembers its position, visibility, scale/width, and always-on-top preference across launches, while recovering onto a visible display if the saved display is unavailable.
- Shows concise stale, error, and authentication-failure states on configured accounts without expanding into a detailed dashboard. Last known usage remains visible when sign-in later fails. When any visible metric on a configured account is authentication-required, the entire provider row is tinted orange. Silent re-auth may run in the background with no login window. Clicking the row opens the manual, visible official sign-in for that provider.
- Opens the Options window when a provider row is activated (double-click), or when the empty-state instruction is activated.

Hovering over a provider row or progress bar displays a tooltip with the most useful details available for that metric, such as `x / y tokens used`, remaining percentage, `$x.xx credit left`, reset time, last successful refresh time, or a short error message. Unknown or unsupported values are never inferred and are not shown on the monitor.

### 4.2 Options window

Selecting **Options** from the tray icon's right-click menu opens the detailed configuration and status window. It has one tab for each provider so accounts can be connected. Controls whose prerequisite data is missing are hidden, not disabled-in-place: the API-credit threshold and bar-full amount appear only for providers with a balance API, and **Disconnect** appears only when a credential is stored. Tab labels and other visible strings are sized so they are fully readable.

Each provider tab contains:

- Detailed session, weekly, and API-credit information when applicable, including used, capacity, remaining amount or percentage, reset time, refresh state, and last successful refresh.
- Clear stale, unavailable, authentication-required, unsupported, and error labels with concise diagnostics.
- A **Log in** or **Connect** button. When the provider's official tools use OAuth or device-code subscription login (Claude, Codex, Grok, Kimi Code, Antigravity), HypeLimits runs that flow, stores the tokens in Windows Credential Manager, and reads the same session/weekly plan usage those tools show. The user can instead paste a token or API key, or reuse an official CLI login already on the PC. DeepSeek uses an API key. Opening a website alone does not connect the account: tokens must be received from the official token endpoint. After a first successful official login, later expiry re-runs that flow automatically by any method that can complete it for this user.
- On the Google Antigravity tab, a password field for the Google OAuth client secret. It is required for in-app Google sign-in and for refreshing a Google session. The field is hidden on other tabs. Paste a new value to replace a saved secret. Disconnecting the Google account does not remove this secret.
- Provider-specific controls such as show-on-monitor/refresh, refresh now, and, when their prerequisites exist, API-credit low-balance threshold, API-credit bar full amount (default $100), and disconnect. Unchecking **Show on the floating monitor and refresh this provider** stops polling and CLI token sync for that provider and omits it from the floating window until it is checked again. **Disconnect** removes the HypeLimits credential, stops CLI import/write-back for that provider, and hides it from the monitor until **Log in / Connect** (or using an existing CLI login from that dialog). Disconnect does not delete the official CLI files on disk. The $ progress bar is remaining balance divided by that full amount, clamped at 100%.

Shared application settings cover the refresh interval, sounds, thresholds, launch-at-login, terminal CLI token sync, WSL CLI token use, floating-window visibility, and always-on-top behavior. When WSL CLI tokens are enabled, Options lists each detected WSL distro username with a checkbox to include that home in token read (and in CLI write-back when terminal sync is on). Login and connection flows must clearly indicate success, cancellation, expiration, and authentication errors, and must not imply that opening a website alone connected the account. Automatic re-auth uses the same success, cancellation, and error reporting as a manual Connect.

After onboarding, the application starts in the tray and restores the floating monitor's saved visibility. It does not show a taskbar or dock entry unless a window is open, subject to platform conventions.

### 4.3 Activity history

**Show Activity** / **Hide Activity** on the tray menu toggles an optional floating window whose main graphic is a GitHub-style calendar of total token use, summed across every provider and account. The calendar is a trailing year of local calendar days: week columns, Sunday–Saturday rows, one cell per day, month labels on the week columns, and a less-to-more legend. It covers at least 365 local days through today and at most 53 weeks, aligned so each column starts on Sunday. The window states the token total for that visible year. Pointing at a day shows that day's token count and date.

Pointing at a row on the floating monitor limits the calendar, the year total, and the four statistics to that row. A provider with one account shows that provider. A provider with several accounts shows the account under the pointer: its imported days and the token increases recorded for that account. Those accounts are not added together on the row. Claude Code logs that name one organization are part of the saved login for that organization. A Claude Code log that names no organization, and Grok and Kimi Code session logs, are not tied to one saved login, so they stay in the all-accounts view when several accounts are shown. Daily totals saved before an account was stored with them stay in the wider view and are not divided among accounts. Pointing at empty monitor space, or leaving the monitor, shows the summed history again. While the pointer is over a row, the window names that provider, and the account number when several accounts are shown.

The activity window uses the same chrome as the usage monitor: no title bar, the same dark background, rounded corners, drag anywhere to move, and a right-edge, bottom-edge, or corner resize that scales the whole view uniformly. The calendar is drawn to an offscreen bitmap and stretched with high-quality filtering, so resize does not reflow or crop. Height follows that scale. There is no upper size limit. Position, width, and visibility are remembered, and a saved position on a missing display is moved back on screen. It stays hidden until the user shows it. It follows the same always-on-top setting as the monitor. Escape or close hides it.

A day with zero tokens is an empty cell. Positive days use four increasing green levels chosen from quartiles of the positive daily totals in that year. Equal counts share a level, a higher count is never a lower level, and the busiest day is the darkest level present. The legend shows all five levels, from empty through the darkest green.

The same window shows four statistics from the full stored history, not only the visible year:

- Lifetime token use, as one number.
- Peak tokens per day ever.
- Longest streak of using AI daily.
- Current streak of using AI daily.

A day counts toward a streak only when its token total is greater than zero. The longest streak is the longest run of consecutive positive local days. The current streak counts backward from today when today is positive, otherwise from yesterday, and stops at the first zero day. With no recorded use, every statistic is zero and every cell is empty.

Totals count only positive increases in an absolute token `used` counter between two current observations of the same provider account and the same allowance window. The increase is added to the local calendar day of the later observation. The first observation is a baseline and adds nothing. A drop, such as a window reset, adds nothing and becomes the new baseline. Percentage, request, credit, and currency metrics add nothing. Non-current observations add nothing. Session and weekly windows for one account are not both added; when both are absolute token counts, only the longer window (weekly) counts.

A connected account can also contribute days that its own authorized endpoint reports as absolute daily token totals. Those days are stored per provider account and added to the recorded daily totals. A later successful report for that account replaces its imported days instead of adding them again. An error, or a body that is not a daily report, leaves the saved import unchanged.

Codex is the account that exposes this. After a successful `/backend-api/wham/usage` read, HypeLimits requests `GET /backend-api/wham/analytics/daily-workspace-usage-counts` with the same ChatGPT bearer and account id (`group_by=day`, `end_date` exclusive). The window is the longest one that endpoint accepts: 364 days ending tomorrow. A gap of 365 days or more is rejected, and that rejection used to leave the calendar empty. If the long window is rejected, the same span is requested in 90-day pieces; a failed piece leaves the saved import unchanged. A day uses `text_total_tokens` when that value is positive; otherwise it uses the sum of cached input, uncached input, and output tokens. Client and model breakdowns are not added again. Credits, turns, and percentage breakdowns add nothing. The returned date is stored as that civil day.

Claude, Kimi, DeepSeek, Grok, and Antigravity, on the logins HypeLimits already holds, expose the live window only: percents, request counts, credits, or currency. Those values are not relabeled as tokens. Organization admin usage APIs that need a separate admin key are not called. No connected endpoint reports the start and end of a single task, so the activity window does not show a task duration.

Claude Code, Grok, and Kimi Code do record absolute tokens in their local session logs. HypeLimits reads those logs from the Windows user profile, and from each WSL home included by the WSL CLI sync checkboxes. A Claude Code transcript that names one organization is stored on the saved login for that organization. A sibling transcript in the same session that names no organization uses that session's organization when the session names exactly one. Transcripts that name no organization, and every Grok and Kimi Code total, are stored as imported days for account id `local`. A later scan replaces each of those accounts, including a saved login whose logs are gone. Unchanged files are not read again. The scan cache records the file path, its size, its modification time, that file's daily totals, and, for a Claude Code file, the organization id that file itself names. A cache saved before those ids were recorded is kept: the files are scanned for the organization id only, and their saved daily totals are not parsed again. The cache is a non-secret file under the local app data folder. It does not copy log text or credentials into the activity history. An organization is matched to a saved login when that login's account id is already paired with it. When exactly one organization and one saved login are the only ones left unpaired, they are paired. With no saved account ids, or with more than one of either left over, the remainder stays on account `local` and is not divided among the rows.

- Claude Code: each assistant request in `.claude/projects/**/*.jsonl`, including subagent transcripts. The same request id counts once. The total is input, cache creation, cache read, and output tokens. Thinking tokens are already inside output and are not added again.
- Grok: each completed turn in `.grok/sessions/**/updates.jsonl` whose `sessionUpdate` is `turn_completed`. That turn's `totalTokens` is used when it is positive; otherwise input plus output is used. A repeated prompt id keeps the larger total. Nested per-model breakdowns are not added again. A turn that has not finished yet has no completed record.
- Kimi Code: each `usage.record` with scope `turn` in `.kimi-code/sessions/**/wire.jsonl`. The total is input, cache read, cache creation, and output. Session-scope snapshots and token-counting estimates are not added.

Codex is not read from its local rollout logs. Its daily endpoint already supplies absolute tokens for that account, and adding the rollout would count the same tokens twice. Antigravity and DeepSeek session files on these logins do not contain an absolute token total, so they still do not fill the calendar from disk.

The history persists across restarts in the existing non-secret settings, including daily totals, positive deltas, imported daily totals (Codex and local session logs), and the last absolute token counter per provider account and window. A saved day or delta may name its provider and account. A day or delta that names a provider but no account counts for that provider as a whole, not for one account. A day or delta without a provider is an older total and counts only in the all-providers view. Reloading restores those daily totals, deltas, and imports. Malformed saved data yields an empty history instead of a crash or a fabricated total. Credentials are not written into that history. Days use the machine's local calendar, not UTC.

## 5. First Run and Launch at Login

On first run, prompt the user once to choose whether HypeLimits should start automatically when they log in. The prompt must offer **Enable**, **Not now**, and a way to change the choice later in Settings. Declining must not prompt again automatically.

Separately, the first time HypeLimits has no recorded answer, ask whether to keep the tokens in the user's terminal synced with HypeLimits. Persist the yes/no answer. Declining is not re-prompted automatically. Options can change the choice later.

If the user opts in, HypeLimits imports the latest still-usable token from that provider's official CLI config (Claude Code, Codex, Grok, Antigravity/Gemini, Kimi) into its own storage. Background sync never writes a CLI config: a CLI file is written only to pass on a refresh of the token that file already holds (files holding any other login are left alone, and missing files are not created), after an explicit subscription sign-in in HypeLimits, or on explicit account selection. This keeps a stale stored copy from replacing a newer CLI login. Codex write-back also stamps `last_refresh` for the tokens it writes. A provider with no CLI config path is skipped. Background import and write-back also skip a provider that is disabled or that the user disconnected from Options, until they connect that provider again. If the user opts out of terminal sync globally, CLI configs are not imported in the background, and an explicit sign-in is not written to them. Explicit account selection separately authorizes selected-account write-back as described in §3.4.

A separate Options checkbox includes official CLI configs from WSL, not only the Windows user profile. Detected WSL usernames appear as individual checkboxes (on by default); only checked users are read, and they are write targets for refresh propagation and explicit sign-in while terminal token sync is on, or when explicit account selection authorizes write-back. Unchecked WSL users are ignored. WSL-only logins, including Kimi Code OAuth under `~/.kimi-code/credentials/`, are enough for HypeLimits to show usage. WSL is not prompted on first run.

WSL discovery and fallback file reads must invoke only `wsl.exe` resolved from the Windows native system directory (through the `Sysnative` alias under WOW64) with an explicit application path. All WSL command-line arguments must use Windows command-line escaping, and fallback reads must use WSL `--exec` mode rather than a shell; the application must not locate `wsl.exe` through the current directory or `PATH`.

Autostart uses platform-native mechanisms and is changed only with explicit user action. The application must clearly report if the operating system rejects the change. When launch-at-login is already enabled, each start compares the registered autostart path with the running executable and rewrites it if the application has moved. That path repair does not change the user's enable/disable choice.

## 6. Provider Integration

Each provider adapter exposes:

- Provider identity and supported capabilities.
- Authentication/configuration validation.
- The provider's official login or account URL and any supported authorized sign-in flow.
- Asynchronous retrieval of limit and balance data.
- Normalized metrics and provider-specific diagnostics.
- Rate-limit and retry metadata where available.

Fetch each metric using the same authorized HTTPS endpoints the provider's own tools use (Claude Code `/api/oauth/usage`, Codex `/backend-api/wham/usage` and `/backend-api/wham/analytics/daily-workspace-usage-counts`, Grok CLI billing, Kimi Code `/coding/v1/usages`, Moonshot and DeepSeek balance APIs, xAI Management prepaid balance, Antigravity Cloud Code Assist). Connect with the provider's official OAuth or device-code subscription login when available so session and weekly plan usage is used; a pasted platform API key fetches prepaid credit only. Official CLI logins already on the machine can be reused. If a connected account's endpoint omits a metric, mark that metric unsupported rather than estimating it.

Access tokens are renewed with the stored refresh token, with no UI. When that refresh is missing or rejected, or the provider still returns 401/403, HypeLimits retries silent re-auth only (CLI session, imported cookies, stored credentials, hidden WebView). It must not pop a login window. A visible official sign-in runs only when the user clicks the orange row or Connect. Usage values still come only from the authorized HTTPS endpoints above. Do not scrape dashboards or other HTML for allowances.

Credentials and tokens must never be written to logs or to HypeLimits' own settings files. Store HypeLimits secrets in Windows Credential Manager. WebView profiles, imported browser cookies, and any other material used to automate sign-in are credentials: protect them the same way, and do not log them. The Google OAuth client secret is not compiled into the application; users paste it in Options at runtime. When the user has opted into terminal token sync or explicitly selected a saved account, HypeLimits may update the official CLI credential JSON files those tools already use, preserving unrelated keys. Network traffic must use TLS with certificate verification enabled.

## 7. Architecture

Suggested modules:

- `app`: lifecycle, single-instance enforcement, onboarding, and coordination.
- `providers`: adapter interface and one implementation per provider.
- `model`: normalized limits, balances, reset periods, and aggregate status.
- `polling`: scheduling, backoff, connectivity handling, and refresh orchestration.
- `alerts`: threshold transitions, deduplication, reset detection, and sounds.
- `ui`: tray icon/menu, floating monitor, activity history, provider-tabbed Options window, official sign-in, and accessible status presentation. The monitor and the activity window each render to an offscreen bitmap and stretch it when the user resizes width. Activity paints the token calendar and the four statistics from the portable history.
- `platform`: Windows Credential Manager, launch-at-login, WebView2 and installed-browser cookie/credential stores for official re-auth, plus background-class process/thread/memory/power priorities. Browser sign-in remains user-driven.
- `persistence`: non-secret settings and minimal cached observations.

Networking and provider parsing run off the UI thread. Updates are delivered to the UI through thread-safe signals or immutable snapshots. The application should remain responsive when any provider is slow or unavailable.

## 8. Privacy and Reliability

- Collect only information required to display allowance state.
- Send no telemetry by default.
- Redact authorization headers, tokens, account identifiers, and sensitive response fields from diagnostics.
- Cache only the minimum data needed to show the last known state, deduplicate alerts, and show token activity. The activity history stores daily totals, positive token deltas, imported daily token totals, and allowance baselines. It does not store credentials. Do not log tokens, refresh tokens, WebView cookies, imported browser cookies, or other sign-in material.
- Use atomic settings persistence and tolerate malformed or partially missing cached data.
- Keep functioning when one or more providers fail.
- Make provider polling independently disableable. Disconnecting or disabling a provider from Options must stop background CLI token sync for that provider until the user connects it again from Options.

## 9. Acceptance Criteria

- The application builds as a modern C++ Windows 11 desktop application without third-party dependencies.
- The tray icon and tooltip reflect the most exhausted available limit and update after refreshes.
- One compact floating monitor shows only configured accounts and only metrics that have prerequisite data, with fully visible unclipped text, a user-resizable width that uniformly scales the contents, remembered placement, visibility, and width, and show/hide from the tray menu.
- Unconfigured providers and metrics without data do not occupy monitor or Options chrome; Options still lists every provider so the user can connect an account. A disconnected or disabled provider stays off the floating monitor and is not polled or CLI-synced until Connect or the show-on-monitor checkbox is turned back on.
- Hovering over a provider row or bar shows available usage, remaining balance, reset, refresh, and status details in a tooltip without fabricating unknown values.
- Authentication-required provider rows on the floating monitor are tinted orange. After a silent refresh-token failure, official OAuth or device-code re-auth runs automatically by any available method. Clicking the row still opens that provider's connect flow if every automatic method fails or is cancelled.
- Right-clicking the tray icon and choosing **Options** opens a detailed window with one tab per provider.
- Right-clicking the tray icon and choosing **Show Activity** opens the optional floating token calendar and the lifetime, peak-day, longest-streak, and current-streak statistics described in §4.3. **Hide Activity** closes it. The window scales like the usage monitor and remembers position, width, and visibility. Pointing at a floating-monitor row shows that provider's history, or that account's history when the provider has several accounts. Claude Code logs that name an organization are included in the saved login for that organization. Leaving every row shows the summed history again. Only absolute token increases, absolute daily token totals a provider endpoint actually reports, and absolute tokens read from Claude Code, Grok, and Kimi Code session logs are counted. Codex rollout logs are not added on top of its daily endpoint. The history reloads from non-secret settings and never stores credentials.
- Every provider tab includes a login or connection button that opens the provider's official website and supports the safest authorized connection flow available.
- Supported session, weekly, and topped-up fund data appear per provider without fabricating unavailable values.
- Crossing 90% exhaustion produces exactly one warning sound per metric and reset period.
- A verified allowance refresh produces one happy sound.
- First run asks whether to launch at login, saves the answer, and Settings can change it. When that setting is on, a later start from a different executable path updates the registered autostart path without prompting.
- First run (or first launch after this feature) asks whether to keep terminal CLI tokens synced with HypeLimits, saves the answer without re-prompting after a decline, and Options can change it. When enabled, the latest valid token is applied to both HypeLimits storage and the official CLI config.
- Options can include WSL CLI configs. Detected WSL usernames are listed with per-user sync checkboxes; only selected users are read; they receive refresh propagation and explicit sign-in write-back when terminal token sync is on, and explicit account selection also authorizes write-back.
- WSL discovery and fallback file reads launch only `wsl.exe` resolved from the Windows native system directory (using `Sysnative` under WOW64) through an explicit application path, with independently quoted command-line arguments, WSL `--exec` mode for file reads, and no current-directory or `PATH` lookup.
- Secrets are stored using native credential storage and never appear in logs. The Google OAuth client secret is configured in Options and is not present in the distributed binary.
- When an official subscription login's refresh token is rejected, HypeLimits retries silent re-auth with no visible UI. If that cannot finish, the orange row stays; clicking it (or Connect) is a manual, visible official sign-in the user completes. Paste-only API-key accounts are not auto-reauthenticated this way.
- Provider and network failures are visible, non-blocking, and do not freeze the UI.
- Automated tests cover normalization, icon color interpolation, threshold deduplication, reset detection, stale data, adapter parsing with sanitized fixtures, which providers and metrics appear on the floating monitor, and the token activity history (daily deltas, streaks, the year calendar, Codex daily-token import, and local Claude, Grok, and Kimi session logs).

## 10. Implementation Status

- Dependency-free Windows 11 application shell implemented with native Win32 APIs.
- Floating monitor, tray menu, provider-tabbed Options window, login links, secure credential storage, refresh scheduling, stale-value caching, launch-at-login (including startup repair of a stale autostart path), and sound alerts implemented.
- Floating monitor shows only configured accounts and ready metrics, sizes text so it is not clipped, and scales from an offscreen bitmap when the user resizes its width. Usage rows appear only after a metric has a value to display. Authentication failure keeps the last known usage on the monitor instead of clearing the account, tints that entire provider row orange, and opens that provider's connect flow when the row is clicked. Rows that consumed allowance since the last poll are brighter; idle rows are darker; unselected accounts with no recent drawdown render at 50% strength. Switching accounts keeps the newly selected account's last values and drawdown time, so the next poll can already show it drawing down. The one-shot poll timer is re-armed whenever a scheduled refresh cannot start. A refresh requested while another is running (for example right after reconnecting) is queued and runs when the current one finishes, and every account row shows refreshing immediately, so a reconnect is never left showing the old rejected-credential state until the next poll. When the selected credential is rejected, HypeLimits also tries the other copy (Credential Manager or CLI file) before showing the orange row. Any account's rejected credential then recovers automatically from a live CLI login on this PC (Windows or a synced WSL home) for the same account: each slot records its account identity after a successful poll (the token's account id, or the Claude `/api/oauth/profile` account uuid), and a CLI login is adopted only when its identity matches. A slot with no recorded identity adopts a CLI login only if it is the selected account (or the provider has a single account) and no other slot owns that login. Recovery uses only unexpired CLI access tokens, so it never rotates a CLI's refresh token; the CLI-adoption step for the selected account applies the same identity check. Monitor tooltips and row clicks use the snapshot of the row under the cursor, and clicking a rejected non-selected account selects it before opening sign-in. Token handling never rotates a refresh token speculatively: an access token is refreshed only once it has expired (from the stored expiry or the token's own JWT `exp`; unknown expiry means no refresh), the CLI's newer unexpired token is adopted first, a refresh token the provider rejects is not retried for six hours, and background sync only imports from CLI files (see §5). Choosing "Use the official CLI login already on this PC" checks that login against the usage endpoint first and explains when the CLI's saved login has been signed out or revoked. Network-change refreshes are debounced to one per minute, and a re-auth that still yields rejected usage does not trigger another automatic round.
- Process, UI thread, refresh worker, memory, page, and EcoQoS power priorities are set to background/idle classes.
- Options hides threshold, API-credit bar full amount, and disconnect controls until their prerequisites exist. The $ monitor bar uses the configured full amount, defaulting to $100. The Google Antigravity tab includes a password field for the Google OAuth client secret; it is stored in Credential Manager separately from the account token and is not compiled into the binary.
- Usage retrieval implemented for every initial provider, using the same authorized endpoints as Claude Code, Codex, Grok CLI, Kimi Code, Moonshot, DeepSeek, xAI Management API, and Antigravity/Cloud Code Assist. Connect runs the official OAuth or device-code subscription login for Claude, Codex, Grok, Kimi Code, and Antigravity so session/weekly plan usage is used; access tokens refresh automatically from the stored refresh token. Claude uses the same authorize page (`claude.com/cai/oauth/authorize`), manual redirect (`platform.claude.com/oauth/code/callback`), scopes, and token endpoint (`platform.claude.com/v1/oauth/token`) as the current Claude Code CLI. Kimi Code uses the same `auth.kimi.com` device-code login as the official CLI (`/api/oauth/device_authorization` then `/api/oauth/token`); the Connect button and orange-row click open that flow at kimi.com / kimi.ai rather than only offering a pasted Moonshot API key. Automatic re-auth is silent (no visible login window). Clicking the orange row or Connect is a manual, visible official sign-in. HypeLimits does not auto-click login, MFA, or consent. After a refresh-token failure, it retries CLI reuse and imported cookies in the background, then waits on the orange row if a person is needed. One automatic round runs per failure. Paste-only API keys are not auto-reauthenticated. Antigravity in-app Google sign-in and Google token refresh require the client secret from Options. Kimi Code CLI OAuth (15-minute access tokens) is refreshed at `auth.kimi.com` using the stored refresh token. Official CLI logins can be reused, or a token/API key can be pasted. Metrics a connected endpoint does not return are marked unsupported.
- Optional bidirectional sync of official CLI credential JSON files: first-run prompt with persisted yes/no, Options checkbox, extra-key-preserving merge, and no legacy background CLI writes when opted out; explicit account selection separately authorizes write-back. Disconnect and the per-provider show-on-monitor checkbox stop that provider's background CLI import until Connect or the checkbox is on again. Optional WSL CLI inclusion with a detected-username list and per-user checkboxes (on by default); selected WSL homes are read for tokens and written only for refresh propagation, explicit sign-in, or explicit account selection. Kimi Code CLI credentials are read from `~/.kimi-code/credentials/` and the legacy `~/.kimi/credentials/` paths. Enabling WSL sync reloads connections and refreshes usage. WSL discovery and fallback file reads use only the explicitly selected native system `wsl.exe` (including `Sysnative` under WOW64), with each command argument safely quoted and `--exec` used to avoid shell evaluation.
- Portable core and sanitized provider-parser tests implemented; the application builds and tests with Visual Studio Build Tools.
- Activity history is implemented. The tray **Show Activity** / **Hide Activity** command toggles an optional floating Sunday-aligned year calendar of total token use and the four statistics in §4.3. The window matches the usage monitor: no title bar, drag to move, uniform bitmap scaling, and remembered position, width, and visibility. It stays hidden until shown. Startup loads that history from non-secret settings. A new absolute token delta, a replaced Codex daily import, or a replaced local session-log import saves it back. After a successful Codex usage read, absolute daily tokens are imported from `/backend-api/wham/analytics/daily-workspace-usage-counts` for the longest range that endpoint accepts, 364 days through today. Claude Code, Grok, and Kimi Code session logs are scanned from the Windows profile and from WSL homes included in CLI sync. Claude Code transcripts that name an organization are stored on the matching saved login. Other Claude Code transcripts, and Grok and Kimi Code totals, are stored as imported days for account `local`. Each of those accounts is replaced on the next scan. Codex rollout logs are not scanned. Antigravity and DeepSeek logs do not carry absolute token totals. Pointing at a monitor row shows that provider's calendar and statistics. When the provider has several accounts, the row shows that account alone. Leaving the rows shows every account again. Token increases are stored per account. Older days saved without an account stay in the wider view only. Malformed saved data is ignored. Credentials are not stored in the history.

- Multiple credential slots, Options account controls and per-provider rotation checkbox, floating-row account menu, account-isolated persistence, and explicit Windows/WSL selection sync implemented. Portable tests cover exhaustion eligibility, reset handling, account identity isolation, and Codex identity replacement. Native Windows builds and core tests pass; live sign-in, WSL write-back, and running-client reload behavior require interactive integration validation.
