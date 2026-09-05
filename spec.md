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
- The application uses Windows APIs for tray integration, windows, menus, settings, networking, notifications, audio, credential storage, and launch-at-login. It has no third-party runtime or build dependencies.
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

Data refreshes on startup, on a configurable polling interval, when the user selects **Refresh now**, and after network connectivity returns. Polling must use bounded timeouts, exponential backoff, provider rate-limit guidance, and small randomized jitter. A failed refresh must retain the last successful value, mark it stale, and expose a short diagnostic message. An authentication failure (rejected or missing credential) must likewise retain the last successful usage, mark the metric authentication-required, and keep it visible until a new value is fetched.

### 3.2 Normalized status

For each percentage-based limit:

`exhaustion = used / capacity * 100`

`remaining = 100 - exhaustion`

The aggregate tray status is the most exhausted currently available percentage-based limit across all enabled providers. Currency balances without a configured budget or low-balance threshold do not contribute to this aggregate.

The tray icon transitions continuously from bright green at 100% remaining to yellow at 50% remaining and red at 0% remaining. Unknown or disconnected status uses neutral gray. This color appears on a simple monochrome gauge-style tray glyph with adequate contrast.

The tray tooltip summarizes the most constrained limit, its remaining percentage, and its reset time. Right-clicking the tray icon opens a menu containing **Show/Hide Monitor**, **Refresh now**, **Options**, and **Quit**. **Options** opens the detailed provider view described below.

### 3.3 Alerts and reset detection

- Play a short, unobtrusive warning tone when a percentage-based limit first reaches or exceeds 90% exhaustion (10% or less remaining).
- A configured API-credit low-balance threshold is treated as 90% exhaustion for alerting purposes.
- Alert once per metric per reset period; do not replay the warning on every poll.
- When a previously depleted or constrained limit refreshes to a new allowance period, play a distinct short, cheerful sound.
- Detect refreshes primarily through a changed provider reset period or reset timestamp. If unavailable, detect a large increase in remaining allowance only when supported by consecutive observations, to avoid false alerts.
- Sound alerts can be disabled independently. The settings view includes preview buttons and volume control, and respects the operating system's output device and mute state.

## 4. User Interface

The interface is minimal, dark-mode-first, keyboard accessible, and visually quiet. It follows system scaling and uses the system font. Color is not the only status indicator.

### 4.1 Floating monitor

The primary interface is one compact floating window intended to remain open most of the time. It shows the smallest set of UI that is logically relevant: one small row per **configured** account, and only the metrics that have their prerequisite data.

A provider is configured when the user has completed the Options setup that supplies that account's connection data (for example a stored API key) and the provider remains enabled. Enabled-but-unconfigured providers, disabled providers, and providers with nothing displayable do not appear. Session, weekly, and API-credit bars are drawn only when that metric has a value to show (used, remaining, or capacity) in current, stale, refreshing, error, or authentication-required state. A refreshing, error, or authentication-required metric with no amount yet does not get a row, so bars are not shown and then hidden. Unsupported and unavailable metrics, and authentication-required metrics with no last known value, are omitted rather than shown as empty bars, placeholders, or "?".

When no account is configured, the monitor shows a short instruction to configure an account in Options, and nothing else.

Each visible row has the provider name and a thin labeled progress bar per visible metric. Bars include a concise text or icon label so their meaning and status do not depend on color alone. Labels, names, empty-state copy, and bar captions are measured and laid out so they fit in full; text is never ellipsized or clipped. If used increased or remaining fell since the last successful poll, that provider row is drawn a bit brighter; if usage looks idle, the row is drawn darker.

The floating monitor:

- Uses minimal chrome and consumes as little screen space as practical.
- Can be moved, shown or hidden from the tray menu, and optionally kept above other windows.
- Has a user-resizable width. Dragging the right edge uniformly and smoothly scales the entire monitor: the layout is rendered to an offscreen bitmap and stretched with high-quality filtering, so resize does not reflow or crop. Height follows the scaled content. The chosen width is remembered across launches.
- Remembers its position, visibility, scale/width, and always-on-top preference across launches, while recovering onto a visible display if the saved display is unavailable.
- Shows concise stale, error, and authentication-failure states on configured accounts without expanding into a detailed dashboard. Last known usage remains visible when sign-in later fails.
- Opens the Options window when a provider row is activated, or when the empty-state instruction is activated.

Hovering over a provider row or progress bar displays a tooltip with the most useful details available for that metric, such as `x / y tokens used`, remaining percentage, `$x.xx credit left`, reset time, last successful refresh time, or a short error message. Unknown or unsupported values are never inferred and are not shown on the monitor.

### 4.2 Options window

Selecting **Options** from the tray icon's right-click menu opens the detailed configuration and status window. It has one tab for each provider so accounts can be connected. Controls whose prerequisite data is missing are hidden, not disabled-in-place: the API-credit threshold and bar-full amount appear only for providers with a balance API, and **Disconnect** appears only when a credential is stored. Tab labels and other visible strings are sized so they are fully readable.

Each provider tab contains:

- Detailed session, weekly, and API-credit information when applicable, including used, capacity, remaining amount or percentage, reset time, refresh state, and last successful refresh.
- Clear stale, unavailable, authentication-required, unsupported, and error labels with concise diagnostics.
- A **Log in** or **Connect** button. When the provider's official tools use OAuth or device-code subscription login (Claude, Codex, Grok, Antigravity), HypeLimits runs that flow, stores the tokens in Windows Credential Manager, and reads the same session/weekly plan usage those tools show. The user can instead paste a token or API key, or reuse an official CLI login already on the PC. Kimi Code and DeepSeek use API keys. Opening a website alone does not connect the account.
- On the Google Antigravity tab, a password field for the Google OAuth client secret. It is required for in-app Google sign-in and for refreshing a Google session. The field is hidden on other tabs. Paste a new value to replace a saved secret. Disconnecting the Google account does not remove this secret.
- Provider-specific controls such as enable/disable, refresh, and, when their prerequisites exist, API-credit low-balance threshold, API-credit bar full amount (default $100), and disconnect. The $ progress bar is remaining balance divided by that full amount, clamped at 100%.

Shared application settings cover the refresh interval, sounds, thresholds, launch-at-login, terminal CLI token sync, WSL CLI token use, floating-window visibility, and always-on-top behavior. When WSL CLI tokens are enabled, Options lists each detected WSL distro username with a checkbox to include that home in token read (and in CLI write-back when terminal sync is on). Login and connection flows must clearly indicate success, cancellation, expiration, and authentication errors, and must not imply that opening a website alone connected the account.

After onboarding, the application starts in the tray and restores the floating monitor's saved visibility. It does not show a taskbar or dock entry unless a window is open, subject to platform conventions.

## 5. First Run and Launch at Login

On first run, prompt the user once to choose whether HypeLimits should start automatically when they log in. The prompt must offer **Enable**, **Not now**, and a way to change the choice later in Settings. Declining must not prompt again automatically.

Separately, the first time HypeLimits has no recorded answer, ask whether to keep the tokens in the user's terminal synced with HypeLimits. Persist the yes/no answer. Declining is not re-prompted automatically. Options can change the choice later.

If the user opts in, whenever HypeLimits loads or updates a provider credential it picks the latest still-usable token between HypeLimits storage and that provider's official CLI config (Claude Code, Codex, Grok, Antigravity/Gemini, Kimi) and writes the winner to both. A provider with no CLI config path is skipped. If the user opts out, HypeLimits does not write tokens into CLI configs.

A separate Options checkbox includes official CLI configs from WSL, not only the Windows user profile. Detected WSL usernames appear as individual checkboxes (on by default); only checked users are read, and they are write targets only while terminal token sync is on. Unchecked WSL users are ignored. WSL-only logins, including Kimi Code OAuth under `~/.kimi-code/credentials/`, are enough for HypeLimits to show usage. WSL is not prompted on first run.

Autostart uses platform-native mechanisms and is changed only with explicit user action. The application must clearly report if the operating system rejects the change.

## 6. Provider Integration

Each provider adapter exposes:

- Provider identity and supported capabilities.
- Authentication/configuration validation.
- The provider's official login or account URL and any supported authorized sign-in flow.
- Asynchronous retrieval of limit and balance data.
- Normalized metrics and provider-specific diagnostics.
- Rate-limit and retry metadata where available.

Fetch each metric using the same authorized HTTPS endpoints the provider's own tools use (Claude Code `/api/oauth/usage`, Codex `/backend-api/wham/usage`, Grok CLI billing, Kimi Code `/coding/v1/usages`, Moonshot and DeepSeek balance APIs, xAI Management prepaid balance, Antigravity Cloud Code Assist). Connect with the provider's official OAuth or device-code subscription login when available so session and weekly plan usage is used; a pasted platform API key fetches prepaid credit only. Official CLI logins already on the machine can be reused. Do not scrape web pages, import browser cookies, or bypass access controls. If a connected account's endpoint omits a metric, mark that metric unsupported rather than estimating it.

Credentials and tokens must never be written to logs or to HypeLimits' own settings files. Store HypeLimits secrets in Windows Credential Manager. The Google OAuth client secret is not compiled into the application; users paste it in Options at runtime. When the user has opted into terminal token sync, HypeLimits may update the official CLI credential JSON files those tools already use, preserving unrelated keys. Network traffic must use TLS with certificate verification enabled.

## 7. Architecture

Suggested modules:

- `app`: lifecycle, single-instance enforcement, onboarding, and coordination.
- `providers`: adapter interface and one implementation per provider.
- `model`: normalized limits, balances, reset periods, and aggregate status.
- `polling`: scheduling, backoff, connectivity handling, and refresh orchestration.
- `alerts`: threshold transitions, deduplication, reset detection, and sounds.
- `ui`: tray icon/menu, floating monitor, provider-tabbed Options window, and accessible status presentation. The monitor renders to an offscreen bitmap and stretches it when the user resizes width.
- `platform`: Windows Credential Manager, launch-at-login, and background-class process/thread/memory/power priorities.
- `persistence`: non-secret settings and minimal cached observations.

Networking and provider parsing run off the UI thread. Updates are delivered to the UI through thread-safe signals or immutable snapshots. The application should remain responsive when any provider is slow or unavailable.

## 8. Privacy and Reliability

- Collect only information required to display allowance state.
- Send no telemetry by default.
- Redact authorization headers, tokens, account identifiers, and sensitive response fields from diagnostics.
- Cache only the minimum data needed to show the last known state and deduplicate alerts. Do not log tokens.
- Use atomic settings persistence and tolerate malformed or partially missing cached data.
- Keep functioning when one or more providers fail.
- Make provider polling independently disableable.

## 9. Acceptance Criteria

- The application builds as a modern C++ Windows 11 desktop application without third-party dependencies.
- The tray icon and tooltip reflect the most exhausted available limit and update after refreshes.
- One compact floating monitor shows only configured accounts and only metrics that have prerequisite data, with fully visible unclipped text, a user-resizable width that uniformly scales the contents, remembered placement, visibility, and width, and show/hide from the tray menu.
- Unconfigured providers and metrics without data do not occupy monitor or Options chrome; Options still lists every provider so the user can connect an account.
- Hovering over a provider row or bar shows available usage, remaining balance, reset, refresh, and status details in a tooltip without fabricating unknown values.
- Right-clicking the tray icon and choosing **Options** opens a detailed window with one tab per provider.
- Every provider tab includes a login or connection button that opens the provider's official website and supports the safest authorized connection flow available.
- Supported session, weekly, and topped-up fund data appear per provider without fabricating unavailable values.
- Crossing 90% exhaustion produces exactly one warning sound per metric and reset period.
- A verified allowance refresh produces one happy sound.
- First run asks whether to launch at login, saves the answer, and Settings can change it.
- First run (or first launch after this feature) asks whether to keep terminal CLI tokens synced with HypeLimits, saves the answer without re-prompting after a decline, and Options can change it. When enabled, the latest valid token is applied to both HypeLimits storage and the official CLI config.
- Options can include WSL CLI configs. Detected WSL usernames are listed with per-user sync checkboxes; only selected users are read, and they receive write-back only when terminal token sync is on.
- Secrets are stored using native credential storage and never appear in logs. The Google OAuth client secret is configured in Options and is not present in the distributed binary.
- Provider and network failures are visible, non-blocking, and do not freeze the UI.
- Automated tests cover normalization, icon color interpolation, threshold deduplication, reset detection, stale data, adapter parsing with sanitized fixtures, and which providers and metrics appear on the floating monitor.

## 10. Implementation Status

- Dependency-free Windows 11 application shell implemented with native Win32 APIs.
- Floating monitor, tray menu, provider-tabbed Options window, login links, secure credential storage, refresh scheduling, stale-value caching, launch-at-login, and sound alerts implemented.
- Floating monitor shows only configured accounts and ready metrics, sizes text so it is not clipped, and scales from an offscreen bitmap when the user resizes its width. Usage rows appear only after a metric has a value to display. Authentication failure keeps the last known usage on the monitor instead of clearing the account. Rows that consumed allowance since the last poll are brighter; idle rows are darker.
- Process, UI thread, refresh worker, memory, page, and EcoQoS power priorities are set to background/idle classes.
- Options hides threshold, API-credit bar full amount, and disconnect controls until their prerequisites exist. The $ monitor bar uses the configured full amount, defaulting to $100. The Google Antigravity tab includes a password field for the Google OAuth client secret; it is stored in Credential Manager separately from the account token and is not compiled into the binary.
- Usage retrieval implemented for every initial provider, using the same authorized endpoints as Claude Code, Codex, Grok CLI, Kimi Code, Moonshot, DeepSeek, xAI Management API, and Antigravity/Cloud Code Assist. Connect runs the official OAuth or device-code subscription login for Claude, Codex, Grok, and Antigravity so session/weekly plan usage is used; tokens refresh automatically. Antigravity in-app Google sign-in and Google token refresh require the client secret from Options. Kimi Code CLI OAuth (15-minute access tokens) is refreshed at `auth.kimi.com` using the stored refresh token. Official CLI logins can be reused, or a token/API key can be pasted. Metrics a connected endpoint does not return are marked unsupported.
- Optional bidirectional sync of official CLI credential JSON files: first-run prompt with persisted yes/no, Options checkbox, extra-key-preserving merge, and no CLI writes when opted out. Optional WSL CLI inclusion with a detected-username list and per-user checkboxes (on by default); selected WSL homes are read for tokens and written only when terminal sync is on. Kimi Code CLI credentials are read from `~/.kimi-code/credentials/` and the legacy `~/.kimi/credentials/` paths. Enabling WSL sync reloads connections and refreshes usage.
- Portable core and sanitized provider-parser tests implemented; the application builds and tests with Visual Studio Build Tools.
