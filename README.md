# HypeLimits

HypeLimits is a dependency-free Windows 11 tray application for monitoring AI-provider allowances. It uses the Win32 API and Windows SDK only.

## Build

From a Visual Studio Developer Command Prompt:

```bat
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

The executable is produced as `build/hypelimits.exe`.

HypeLimits fetches session, weekly, and credit allowances from the same authorized endpoints the providers' own tools use. Connect with a subscription sign-in (OAuth or device-code) for Claude, Codex, Grok, Kimi Code, and Antigravity to read plan usage; or paste an API key for prepaid credit; or reuse an official CLI login already on the PC. On first run you can opt in to keep those CLI tokens synced both ways with HypeLimits. **Disconnect** in Options (or unchecking **Show on the floating monitor and refresh this provider**) stops that provider's refresh and CLI sync and hides it from the floating window until you Connect again. After an official login, HypeLimits refreshes access tokens silently. If that fails, it retries CLI and cookie re-auth in the background with no login window. Click the orange row (or Connect) for a manual, visible sign-in. It does not scrape dashboards or invent usage values.

Antigravity in-app Google sign-in and Google token refresh need the Google OAuth client secret. Paste it in **Options → Google Antigravity**. It is stored in Windows Credential Manager and is not compiled into the binary. Use the installed-app client secret that belongs to Gemini CLI's public OAuth client (Google publishes it in the Gemini CLI source). Reusing an official CLI login still needs that secret for HypeLimits to refresh the Google session.

## Multiple accounts

Use **Options → provider → Add account** to save another credential. Right-click the provider row in the floating widget (or click **Choose account**) to switch. The selected credential is written to supported Windows and discovered WSL CLI files, excluding unchecked WSL users. Credentials remain in Windows Credential Manager.

Enable **Automatically rotate accounts when allowance runs out** on each provider tab to switch after polling confirms exhaustion. Depleted accounts are skipped until their reported reset; accounts without a reset time can be retried manually. Rotation stops when no eligible account remains.

DeepSeek has no supported CLI credential-file sync. Running clients may need to reload their credentials or restart before using a newly selected account.
