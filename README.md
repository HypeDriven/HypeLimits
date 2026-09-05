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

HypeLimits fetches session, weekly, and credit allowances from the same authorized endpoints the providers' own tools use. Connect with a subscription sign-in (OAuth or device-code) for Claude, Codex, Grok, and Antigravity to read plan usage; or paste an API key for prepaid credit; or reuse an official CLI login already on the PC. On first run you can opt in to keep those CLI tokens synced both ways with HypeLimits. HypeLimits never imports browser cookies, scrapes dashboards, or invents usage values.

Antigravity in-app Google sign-in and Google token refresh need the Google OAuth client secret. Paste it in **Options → Google Antigravity**. It is stored in Windows Credential Manager and is not compiled into the binary. Use the installed-app client secret that belongs to Gemini CLI's public OAuth client (Google publishes it in the Gemini CLI source). Reusing an official CLI login still needs that secret for HypeLimits to refresh the Google session.
