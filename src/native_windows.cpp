#include "alert_engine.hpp"
#include "auto_reauth.hpp"
#include "browser_cookies.hpp"
#include "model.hpp"
#include "provider_parsing.hpp"
#include "token_sync.hpp"
#include "windows_command_line.hpp"

#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A00000C
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif

#include <winsock2.h>
#include <windows.h>
#include <processthreadsapi.h>
#include <windowsx.h>
#include <commctrl.h>
#include <objbase.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <winhttp.h>
#include <wincred.h>
#include <mmsystem.h>
#include <uxtheme.h>
#include <netioapi.h>
#include <bcrypt.h>

#ifndef PROCESS_POWER_THROTTLING_CURRENT_VERSION
#define PROCESS_POWER_THROTTLING_CURRENT_VERSION 1
#endif
#ifndef PROCESS_POWER_THROTTLING_EXECUTION_SPEED
#define PROCESS_POWER_THROTTLING_EXECUTION_SPEED 0x1
#endif
#ifndef THREAD_POWER_THROTTLING_CURRENT_VERSION
#define THREAD_POWER_THROTTLING_CURRENT_VERSION 1
#endif
#ifndef THREAD_POWER_THROTTLING_EXECUTION_SPEED
#define THREAD_POWER_THROTTLING_EXECUTION_SPEED 0x1
#endif
#ifndef MEMORY_PRIORITY_LOW
#define MEMORY_PRIORITY_LOW 2
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cwchar>
#include <cwctype>
#include <format>
#include <functional>
#include <memory>
#include <map>
#include <mutex>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace hypelimits;

namespace {

constexpr wchar_t kAppName[] = L"HypeLimits";
constexpr wchar_t kRegistryKey[] = L"Software\\HypeLimits";
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kRefreshCompleteMessage = WM_APP + 2;
constexpr UINT kNetworkChangedMessage = WM_APP + 3;
constexpr UINT kAutoReauthMessage = WM_APP + 4;
constexpr UINT_PTR kPollTimer = 1;
constexpr UINT_PTR kFlashTimer = 2;
constexpr UINT_PTR kActivityTimer = 3;
constexpr UINT kActivityTimerMs = 2000;
constexpr ULONGLONG kResetFlashMs = 2000;
constexpr COLORREF kResetRowBackground = RGB(36, 214, 78);
constexpr COLORREF kResetRowText = RGB(255, 255, 255);
constexpr COLORREF kResetRowTrack = RGB(18, 118, 42);
constexpr COLORREF kResetRowFill = RGB(196, 255, 168);
constexpr int kMonitorLogicalMinWidth = 196;
constexpr int kMonitorMinWindowWidth = 140;
constexpr int kMonitorResizeEdge = 8;
constexpr int kMonitorCorner = 14;
constexpr int kMonitorFontPx = 16;
constexpr int kMonitorDefaultWidth = 230;
constexpr int kMonitorClickSlop = 4;
constexpr COLORREF kAuthRowBackground = RGB(118, 58, 14);
constexpr COLORREF kAuthRowText = RGB(255, 196, 96);
constexpr COLORREF kAuthRowTrack = RGB(160, 88, 28);

enum ControlId {
    IdTab = 100,
    IdStatus,
    IdLogin,
    IdEnabled,
    IdRefresh,
    IdInterval,
    IdSounds,
    IdVolume,
    IdAlwaysOnTop,
    IdLaunchAtLogin,
    IdSyncCliTokens,
    IdSyncWslTokens,
    IdPreviewWarning,
    IdPreviewReset,
    IdThreshold,
    IdCreditBarFull,
    IdDisconnect,
    IdGoogleClientSecret,
    IdClose,
    IdAddAccount,
    IdAccounts,
    IdRotateAccounts,
    IdTrayShow = 300,
    IdTrayRefresh,
    IdTrayOptions,
    IdTrayQuit,
    IdWslUserFirst = 500,
};

struct ProviderDefinition {
    std::wstring id;
    std::wstring name;
    std::wstring accountUrl;
    std::wstring guidance;
    std::vector<MetricKind> capabilities;
};

struct MonitorAccount {
    DWORD slot{};
    ProviderSnapshot snapshot;
};

struct Provider {
    ProviderDefinition definition;
    ProviderSnapshot snapshot;
    std::vector<MonitorAccount> monitorAccounts;
    bool connected{false};
};

struct MetricHit {
    RECT rect{};
    std::size_t provider{};
    std::size_t metric{};
    DWORD slot{};
};

std::string utf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring wide(std::string_view value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

DWORD readDword(const wchar_t* name, DWORD fallback) {
    DWORD value = fallback;
    DWORD size = sizeof(value);
    RegGetValueW(HKEY_CURRENT_USER, kRegistryKey, name, RRF_RT_REG_DWORD, nullptr, &value, &size);
    return value;
}

void writeDword(const wchar_t* name, DWORD value) {
    HKEY key{};
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegistryKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
        RegCloseKey(key);
    }
}

std::optional<ULONGLONG> readQword(const wchar_t* name) {
    ULONGLONG value{};
    DWORD size = sizeof(value);
    if (RegGetValueW(HKEY_CURRENT_USER, kRegistryKey, name, RRF_RT_REG_QWORD, nullptr, &value, &size) != ERROR_SUCCESS) return std::nullopt;
    return value;
}

void writeQword(const wchar_t* name, ULONGLONG value) {
    HKEY key{};
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegistryKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(key, name, 0, REG_QWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
        RegCloseKey(key);
    }
}

void deleteSetting(const wchar_t* name) {
    HKEY key{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRegistryKey, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
        RegDeleteValueW(key, name);
        RegCloseKey(key);
    }
}

std::wstring currentExecutablePath() {
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) return {};
    path.resize(length);
    return path;
}

std::wstring unquoteLaunchCommand(std::wstring_view command) {
    if (command.size() >= 2 && command.front() == L'"' && command.back() == L'"') {
        return std::wstring{command.substr(1, command.size() - 2)};
    }
    return std::wstring{command};
}

std::wstring readLaunchAtLoginCommand() {
    DWORD size = 0;
    if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     kAppName, RRF_RT_REG_SZ, nullptr, nullptr, &size) != ERROR_SUCCESS) {
        return {};
    }
    if (size < sizeof(wchar_t)) return {};
    std::wstring value(size / sizeof(wchar_t), L'\0');
    if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     kAppName, RRF_RT_REG_SZ, nullptr, value.data(), &size) != ERROR_SUCCESS) {
        return {};
    }
    if (const auto n = value.find(L'\0'); n != std::wstring::npos) value.resize(n);
    return value;
}

bool sameExecutablePath(std::wstring_view left, std::wstring_view right) {
    if (left.empty() || right.empty()) return false;
    return CompareStringOrdinal(left.data(), static_cast<int>(left.size()),
                                right.data(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}

bool setLaunchAtLogin(bool enabled) {
    HKEY key{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) return false;
    LONG result;
    if (enabled) {
        const std::wstring path = currentExecutablePath();
        if (path.empty()) {
            RegCloseKey(key);
            return false;
        }
        const std::wstring quoted = L"\"" + path + L"\"";
        result = RegSetValueExW(key, kAppName, 0, REG_SZ, reinterpret_cast<const BYTE*>(quoted.c_str()),
                                static_cast<DWORD>((quoted.size() + 1) * sizeof(wchar_t)));
    } else {
        result = RegDeleteValueW(key, kAppName);
        if (result == ERROR_FILE_NOT_FOUND) result = ERROR_SUCCESS;
    }
    RegCloseKey(key);
    if (result == ERROR_SUCCESS) writeDword(L"LaunchAtLogin", enabled);
    return result == ERROR_SUCCESS;
}

void syncLaunchAtLoginPath() {
    if (!readDword(L"LaunchAtLogin", 0)) return;
    const std::wstring exe = currentExecutablePath();
    if (exe.empty()) return;
    const std::wstring registered = unquoteLaunchCommand(readLaunchAtLoginCommand());
    if (sameExecutablePath(registered, exe)) return;
    setLaunchAtLogin(true);
}

// Slot zero retains the original Credential Manager target for seamless migration.
DWORD activeAccount(std::wstring_view id) {
    return readDword((L"Provider." + std::wstring(id) + L".ActiveAccount").c_str(), 0);
}
std::wstring accountKey(std::wstring_view id, DWORD slot) {
    return std::wstring(id) + L"/account-" + std::to_wstring(slot);
}
std::wstring accountSetting(std::wstring_view id) {
    const DWORD slot = activeAccount(id);
    return L"Provider." + std::wstring(id) + (slot ? L".Account." + std::to_wstring(slot) : L"");
}
bool managedAccounts(std::wstring_view id) {
    return readDword((L"Provider." + std::wstring(id) + L".ManagedAccounts").c_str(), 0) != 0;
}

class CredentialStore {
    static constexpr int kMaxChunks = 32;
    static constexpr std::string_view kChunkPrefix{"HLCHUNKS:"};

    static std::wstring targetName(std::wstring_view provider, std::wstring_view suffix = {}) {
        std::wstring target = L"HypeLimits/";
        // Explicit account keys bypass the active-slot lookup.
        const auto marker = provider.find(L"/account-");
        if (marker != std::wstring_view::npos) {
            target.append(provider.substr(0, marker));
            const auto slot = provider.substr(marker + 9);
            if (slot != L"0") target += L"/accounts/" + std::wstring(slot);
        } else {
            target.append(provider.begin(), provider.end());
            const auto slot = activeAccount(provider);
            if (slot) target += L"/accounts/" + std::to_wstring(slot);
        }
        if (!suffix.empty()) {
            target.push_back(L'/');
            target.append(suffix.begin(), suffix.end());
        }
        return target;
    }

    static bool writeBlob(const std::wstring& target, std::string_view bytes) {
        if (bytes.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE) return false;
        std::wstring userName{kAppName};
        CREDENTIALW credential{};
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = const_cast<wchar_t*>(target.c_str());
        credential.CredentialBlobSize = static_cast<DWORD>(bytes.size());
        credential.CredentialBlob = reinterpret_cast<BYTE*>(const_cast<char*>(bytes.data()));
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
        credential.UserName = userName.data();
        return CredWriteW(&credential, 0) != FALSE;
    }

    static std::optional<std::string> readBlob(const std::wstring& target) {
        PCREDENTIALW credential{};
        if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &credential)) return std::nullopt;
        std::string raw(reinterpret_cast<const char*>(credential->CredentialBlob), credential->CredentialBlobSize);
        CredFree(credential);
        if (raw.size() >= 2 && raw.size() % 2 == 0 && static_cast<unsigned char>(raw[1]) == 0) {
            std::wstring wideBlob(reinterpret_cast<const wchar_t*>(raw.data()), raw.size() / sizeof(wchar_t));
            raw = utf8(wideBlob);
            SecureZeroMemory(wideBlob.data(), wideBlob.size() * sizeof(wchar_t));
        }
        return raw;
    }

    static void deleteBlob(const std::wstring& target) {
        CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0);
    }

    static void deleteChunks(std::wstring_view provider) {
        for (int i = 0; i < kMaxChunks; ++i) deleteBlob(targetName(provider, std::to_wstring(i)));
    }

public:
    static bool save(std::wstring_view provider, std::wstring_view secret) {
        return saveUtf8(provider, utf8(secret));
    }

    static bool saveUtf8(std::wstring_view provider, std::string_view secret) {
        const std::wstring main = targetName(provider);
        if (secret.size() <= CRED_MAX_CREDENTIAL_BLOB_SIZE) {
            if (!writeBlob(main, secret)) return false;
            deleteChunks(provider);
            return true;
        }
        const DWORD chunk = CRED_MAX_CREDENTIAL_BLOB_SIZE;
        const int n = static_cast<int>((secret.size() + chunk - 1) / chunk);
        if (n > kMaxChunks) return false;
        for (int i = 0; i < n; ++i) {
            const std::size_t off = static_cast<std::size_t>(i) * chunk;
            const std::size_t len = std::min<std::size_t>(chunk, secret.size() - off);
            if (!writeBlob(targetName(provider, std::to_wstring(i)), secret.substr(off, len))) return false;
        }
        for (int i = n; i < kMaxChunks; ++i) deleteBlob(targetName(provider, std::to_wstring(i)));
        return writeBlob(main, std::format("{}{}", kChunkPrefix, n));
    }

    static std::optional<std::string> loadUtf8(std::wstring_view provider) {
        auto main = readBlob(targetName(provider));
        if (!main) return std::nullopt;
        if (main->starts_with(kChunkPrefix)) {
            int count = 0;
            for (const char ch : main->substr(kChunkPrefix.size())) {
                if (ch < '0' || ch > '9') {
                    count = 0;
                    break;
                }
                count = count * 10 + (ch - '0');
            }
            if (count <= 0 || count > kMaxChunks) {
                SecureZeroMemory(main->data(), main->size());
                return std::nullopt;
            }
            std::string joined;
            for (int i = 0; i < count; ++i) {
                auto part = readBlob(targetName(provider, std::to_wstring(i)));
                if (!part) {
                    SecureZeroMemory(main->data(), main->size());
                    SecureZeroMemory(joined.data(), joined.size());
                    return std::nullopt;
                }
                joined += *part;
                SecureZeroMemory(part->data(), part->size());
            }
            SecureZeroMemory(main->data(), main->size());
            return joined;
        }
        return main;
    }

    static std::optional<std::wstring> load(std::wstring_view provider) {
        auto bytes = loadUtf8(provider);
        if (!bytes) return std::nullopt;
        auto wideSecret = wide(*bytes);
        SecureZeroMemory(bytes->data(), bytes->size());
        return wideSecret;
    }

    static void remove(std::wstring_view provider) {
        deleteChunks(provider);
        deleteBlob(targetName(provider));
    }

    static bool exists(std::wstring_view provider) {
        auto secret = loadUtf8(provider);
        if (!secret) return false;
        const bool present = !secret->empty();
        SecureZeroMemory(secret->data(), secret->size());
        return present;
    }
};

constexpr std::wstring_view kGoogleClientSecretId{L"oauth-google-client-secret"};

std::string loadGoogleClientSecret() {
    auto stored = CredentialStore::loadUtf8(kGoogleClientSecretId);
    if (!stored) return {};
    return std::move(*stored);
}

bool googleClientSecretConfigured() {
    auto secret = loadGoogleClientSecret();
    const bool ok = !secret.empty();
    if (!secret.empty()) SecureZeroMemory(secret.data(), secret.size());
    return ok;
}

std::wstring userProfile() {
    wchar_t home[MAX_PATH]{};
    GetEnvironmentVariableW(L"USERPROFILE", home, static_cast<DWORD>(std::size(home)));
    return home;
}

std::wstring windowsUserName() {
    wchar_t name[256]{};
    DWORD size = static_cast<DWORD>(std::size(name));
    if (GetUserNameW(name, &size) && name[0] != L'\0') return name;
    const auto home = userProfile();
    const auto slash = home.find_last_of(L"\\/");
    return slash == std::wstring::npos ? home : home.substr(slash + 1);
}

bool wideEqualsIgnoreCase(std::wstring_view left, std::wstring_view right) {
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0; i < left.size(); ++i) {
        if (towlower(left[i]) != towlower(right[i])) return false;
    }
    return true;
}

std::wstring trimWide(std::wstring text) {
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ' || text.back() == L'\0')) text.pop_back();
    std::size_t start = 0;
    while (start < text.size() && (text[start] == L' ' || text[start] == L'\t' || text[start] == L'\0')) ++start;
    return text.substr(start);
}

bool skipWslDistroName(std::wstring_view name) {
    return name.empty() || name == L"." || name == L".." || wideEqualsIgnoreCase(name, L"docker-desktop")
        || wideEqualsIgnoreCase(name, L"docker-desktop-data");
}

using DirectoryLookup = UINT (WINAPI*)(LPWSTR, UINT);

std::optional<std::wstring> directoryFromApi(DirectoryLookup lookup) {
    std::wstring directory(MAX_PATH, L'\0');
    for (;;) {
        const UINT capacity = static_cast<UINT>(directory.size());
        const UINT length = lookup(directory.data(), capacity);
        if (length == 0) return std::nullopt;
        if (length < capacity) {
            directory.resize(length);
            return directory;
        }
        directory.resize(static_cast<std::size_t>(length) + 1);
    }
}

std::optional<std::wstring> systemWslExecutable() {
    BOOL wow64 = FALSE;
    const bool useSysnative = IsWow64Process(GetCurrentProcess(), &wow64) && wow64;
    const auto directory = directoryFromApi(useSysnative ? GetWindowsDirectoryW : GetSystemDirectoryW);
    if (!directory) return std::nullopt;
    return *directory + (useSysnative ? L"\\Sysnative\\wsl.exe" : L"\\wsl.exe");
}

std::vector<std::wstring> parseWslDistroList(std::string_view raw) {
    std::wstring text;
    if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFF && static_cast<unsigned char>(raw[1]) == 0xFE) {
        text.assign(reinterpret_cast<const wchar_t*>(raw.data() + 2), (raw.size() - 2) / sizeof(wchar_t));
    } else if (raw.size() >= 2 && raw.size() % 2 == 0 && static_cast<unsigned char>(raw[1]) == 0) {
        text.assign(reinterpret_cast<const wchar_t*>(raw.data()), raw.size() / sizeof(wchar_t));
    } else {
        text = wide(raw);
    }
    std::vector<std::wstring> distros;
    std::wstring line;
    for (wchar_t ch : text) {
        if (ch == L'\n') {
            line = trimWide(std::move(line));
            if (!skipWslDistroName(line)) distros.push_back(std::move(line));
            line.clear();
        } else {
            line.push_back(ch);
        }
    }
    line = trimWide(std::move(line));
    if (!skipWslDistroName(line)) distros.push_back(std::move(line));
    return distros;
}

std::vector<std::wstring> listWslDistros() {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE reader{};
    HANDLE writer{};
    if (!CreatePipe(&reader, &writer, &sa, 0)) return {};
    SetHandleInformation(reader, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si{sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = writer;
    si.hStdError = writer;
    PROCESS_INFORMATION pi{};
    std::string raw;
    if (const auto wslExe = systemWslExecutable()) {
        std::wstring command;
        appendWindowsCommandLineArgument(command, *wslExe);
        command += L" --list --quiet";
        if (CreateProcessW(wslExe->c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(writer);
            writer = nullptr;
            if (WaitForSingleObject(pi.hProcess, 4000) == WAIT_TIMEOUT) TerminateProcess(pi.hProcess, 1);
            char buffer[1024];
            DWORD read = 0;
            while (ReadFile(reader, buffer, sizeof(buffer), &read, nullptr) && read > 0) raw.append(buffer, read);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        } else {
            CloseHandle(writer);
            writer = nullptr;
        }
    } else {
        CloseHandle(writer);
        writer = nullptr;
    }
    CloseHandle(reader);
    auto distros = parseWslDistroList(raw);
    if (!distros.empty()) return distros;

    WIN32_FIND_DATAW find{};
    HANDLE handle = FindFirstFileW(L"\\\\wsl.localhost\\*", &find);
    if (handle == INVALID_HANDLE_VALUE) handle = FindFirstFileW(L"\\\\wsl$\\*", &find);
    if (handle == INVALID_HANDLE_VALUE) return {};
    do {
        std::wstring name = find.cFileName;
        if (!skipWslDistroName(name)) distros.push_back(std::move(name));
    } while (FindNextFileW(handle, &find));
    FindClose(handle);
    return distros;
}

struct WslHome {
    std::wstring distro;
    std::wstring user;
    std::wstring home;
};

std::wstring directoryIfExists(const std::wstring& path) {
    const DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY) == 0) return {};
    return path;
}

std::vector<WslHome> discoverWslHomes() {
    std::vector<WslHome> homes;
    for (const auto& distro : listWslDistros()) {
        std::wstring root = directoryIfExists(L"\\\\wsl.localhost\\" + distro + L"\\home");
        if (root.empty()) root = directoryIfExists(L"\\\\wsl$\\" + distro + L"\\home");
        if (root.empty()) continue;
        WIN32_FIND_DATAW find{};
        HANDLE handle = FindFirstFileW((root + L"\\*").c_str(), &find);
        if (handle == INVALID_HANDLE_VALUE) continue;
        do {
            if ((find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
            if (find.cFileName[0] == L'.') continue;
            homes.push_back(WslHome{distro, find.cFileName, root + L"\\" + find.cFileName});
            if (homes.size() >= 16) break;
        } while (FindNextFileW(handle, &find));
        FindClose(handle);
        if (homes.size() >= 16) break;
    }
    return homes;
}

std::vector<WslHome> cachedWslHomes;

std::wstring joinHomeRelative(const std::wstring& home, std::string_view relative) {
    std::wstring path = home;
    path.push_back(L'\\');
    for (char ch : relative) path.push_back(ch == '/' ? L'\\' : static_cast<wchar_t>(static_cast<unsigned char>(ch)));
    return path;
}

bool wslTokenSyncEnabled() {
    return readDword(L"WslTokenSyncEnabled", 0) != 0;
}

bool wslHomeSyncEnabled(const WslHome& home) {
    const std::wstring key = wide(wslUserSettingKey(utf8(home.distro), utf8(home.user)));
    return readDword(key.c_str(), 1) != 0;
}

std::wstring firstExistingOrFront(const std::vector<std::wstring>& paths) {
    for (const auto& path : paths) {
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return path;
    }
    return paths.empty() ? std::wstring{} : paths.front();
}

bool isWslUncPath(std::wstring_view path) {
    return path.starts_with(L"\\\\wsl.localhost\\") || path.starts_with(L"\\\\wsl$\\");
}

std::optional<std::string> readWslFileViaCat(const std::wstring& unc) {
    std::wstring prefix;
    if (unc.starts_with(L"\\\\wsl.localhost\\")) prefix = L"\\\\wsl.localhost\\";
    else if (unc.starts_with(L"\\\\wsl$\\")) prefix = L"\\\\wsl$\\";
    else return std::nullopt;
    const auto rest = unc.substr(prefix.size());
    const auto slash = rest.find(L'\\');
    if (slash == std::wstring::npos || slash == 0) return std::nullopt;
    const std::wstring distro = rest.substr(0, slash);
    std::wstring linux = rest.substr(slash);
    for (wchar_t& ch : linux) if (ch == L'\\') ch = L'/';
    std::wstring user;
    if (linux.starts_with(L"/home/")) {
        const auto end = linux.find(L'/', 6);
        if (end != std::wstring::npos) user = linux.substr(6, end - 6);
    }
    const auto wslExe = systemWslExecutable();
    if (!wslExe) return std::nullopt;
    std::wstring command = buildWslCatCommandLine(*wslExe, distro, user, linux);

    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE reader{};
    HANDLE writer{};
    if (!CreatePipe(&reader, &writer, &sa, 0)) return std::nullopt;
    SetHandleInformation(reader, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si{sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = writer;
    si.hStdError = writer;
    PROCESS_INFORMATION pi{};
    std::string raw;
    if (CreateProcessW(wslExe->c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(writer);
        writer = nullptr;
        if (WaitForSingleObject(pi.hProcess, 5000) == WAIT_TIMEOUT) TerminateProcess(pi.hProcess, 1);
        char buffer[4096];
        DWORD read = 0;
        while (ReadFile(reader, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
            raw.append(buffer, read);
            if (raw.size() > 1024 * 1024) {
                raw.clear();
                break;
            }
        }
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(reader);
        if (exitCode != 0 || raw.empty()) return std::nullopt;
        return raw;
    }
    if (writer) CloseHandle(writer);
    CloseHandle(reader);
    return std::nullopt;
}

std::optional<std::string> readUtf8File(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (isWslUncPath(path)) return readWslFileViaCat(path);
        return std::nullopt;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 1024 * 1024) {
        CloseHandle(file);
        return std::nullopt;
    }
    std::string body(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    const BOOL ok = ReadFile(file, body.data(), static_cast<DWORD>(body.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok) return std::nullopt;
    body.resize(read);
    return body;
}

struct AuthMaterial {
    std::string token;
    std::string refreshToken;
    std::string accountId;
    std::string teamId;
    std::optional<std::int64_t> expiresAtMs;
    std::optional<std::int64_t> observedAtMs;
    std::string idToken;
    bool antigravityCli{false};
};

std::string jsonEscape(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const unsigned char ch : value) {
        if (ch == '"' || ch == '\\') { out.push_back('\\'); out.push_back(static_cast<char>(ch)); }
        else if (ch == '\n') out += "\\n";
        else out.push_back(static_cast<char>(ch));
    }
    return out;
}

std::string packAuthJson(const AuthMaterial& auth) {
    std::string json = std::format("{{\"access_token\":\"{}\",\"refresh_token\":\"{}\",\"account_id\":\"{}\",\"team_id\":\"{}\"",
                                   jsonEscape(auth.token), jsonEscape(auth.refreshToken), jsonEscape(auth.accountId), jsonEscape(auth.teamId));
    if (auth.expiresAtMs) json += std::format(",\"expires_at\":{}", *auth.expiresAtMs);
    if (auth.observedAtMs) json += std::format(",\"observed_at\":{}", *auth.observedAtMs);
    json += ",\"id_token\":\"" + jsonEscape(auth.idToken) + "\"}";
    return json;
}

AuthMaterial parseAuthJson(const std::string& json) {
    AuthMaterial auth;
    auth.idToken = jsonString(json, "id_token").value_or("");
    auth.token = jsonString(json, "accessToken").value_or(jsonString(json, "access_token").value_or(jsonString(json, "token").value_or(jsonString(json, "api_key").value_or(std::string{}))));
    auth.refreshToken = jsonString(json, "refreshToken").value_or(jsonString(json, "refresh_token").value_or({}));
    auth.accountId = jsonString(json, "account_id").value_or(jsonString(json, "chatgpt_account_id").value_or({}));
    auth.teamId = jsonString(json, "team_id").value_or(jsonString(json, "teamId").value_or({}));
    if (const auto exp = jsonNumber(json, "expires_at")) {
        auto n = static_cast<std::int64_t>(*exp);
        if (n > 0 && n < 10'000'000'000LL) n *= 1000;
        if (n > 0) auth.expiresAtMs = n;
    } else if (const auto expIn = jsonNumber(json, "expires_in")) {
        const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        auth.expiresAtMs = now + static_cast<std::int64_t>(*expIn * 1000.0);
    }
    if (const auto observed = jsonNumber(json, "observed_at")) {
        auto n = static_cast<std::int64_t>(*observed);
        if (n > 0 && n < 10'000'000'000LL) n *= 1000;
        if (n > 0) auth.observedAtMs = n;
    }
    return auth;
}

bool saveAuth(std::wstring_view id, const AuthMaterial& auth) {
    std::string packed = packAuthJson(auth);
    const bool ok = CredentialStore::saveUtf8(id, packed);
    SecureZeroMemory(packed.data(), packed.size());
    return ok;
}

bool cliTokenSyncEnabled() {
    return readDword(L"TokenSyncEnabled", 0) != 0;
}

void appendJsonFiles(std::vector<std::wstring>& paths, const std::wstring& directory) {
    WIN32_FIND_DATAW find{};
    HANDLE handle = FindFirstFileW((directory + L"\\*.json").c_str(), &find);
    if (handle == INVALID_HANDLE_VALUE) return;
    do {
        if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring path = directory + L"\\" + find.cFileName;
        if (std::ranges::find(paths, path) == paths.end()) paths.push_back(std::move(path));
    } while (FindNextFileW(handle, &find));
    FindClose(handle);
}

std::vector<std::wstring> cliCredentialPathsForHome(const std::wstring& home, std::wstring_view id) {
    std::vector<std::wstring> paths;
    for (const auto& relative : cliHomeRelativePaths(utf8(id))) paths.push_back(joinHomeRelative(home, relative));
    if (id == L"moonshot") {
        appendJsonFiles(paths, home + L"\\.kimi-code\\credentials");
        appendJsonFiles(paths, home + L"\\.kimi\\credentials");
    }
    return paths;
}

std::vector<std::wstring> windowsCliCredentialPaths(std::wstring_view id) {
    return cliCredentialPathsForHome(userProfile(), id);
}

std::vector<std::wstring> wslCliReadPaths(std::wstring_view id) {
    std::vector<std::wstring> paths;
    if (!wslTokenSyncEnabled()) return paths;
    for (const auto& home : cachedWslHomes) {
        if (!wslHomeSyncEnabled(home)) continue;
        auto userPaths = cliCredentialPathsForHome(home.home, id);
        paths.insert(paths.end(), userPaths.begin(), userPaths.end());
    }
    return paths;
}

std::vector<std::wstring> allCliReadPaths(std::wstring_view id) {
    auto paths = windowsCliCredentialPaths(id);
    auto wsl = wslCliReadPaths(id);
    paths.insert(paths.end(), wsl.begin(), wsl.end());
    return paths;
}

std::wstring cliSyncPath(std::wstring_view id) {
    return firstExistingOrFront(windowsCliCredentialPaths(id));
}

std::vector<std::wstring> tokenSyncWritePaths(std::wstring_view id) {
    std::vector<std::wstring> paths;
    auto windows = cliSyncPath(id);
    if (!windows.empty()) paths.push_back(std::move(windows));
    if (!cliTokenSyncEnabled() || !wslTokenSyncEnabled()) return paths;
    for (const auto& home : cachedWslHomes) {
        if (!wslHomeSyncEnabled(home)) continue;
        auto path = firstExistingOrFront(cliCredentialPathsForHome(home.home, id));
        if (!path.empty()) paths.push_back(std::move(path));
    }
    return paths;
}

AuthMaterial loadStoredAuth(std::wstring_view id) {
    AuthMaterial auth;
    if (auto stored = CredentialStore::loadUtf8(id)) {
        if (!stored->empty()) {
            if (stored->front() == '{') auth = parseAuthJson(*stored);
            else auth.token = *stored;
        }
        SecureZeroMemory(stored->data(), stored->size());
    }
    return auth;
}

TokenRecord recordFromAuth(const AuthMaterial& auth) {
    return TokenRecord{auth.token, auth.refreshToken, auth.accountId, auth.teamId, auth.expiresAtMs, auth.observedAtMs, auth.idToken};
}

AuthMaterial authFromRecord(const TokenRecord& record) {
    AuthMaterial auth;
    auth.token = record.accessToken;
    auth.refreshToken = record.refreshToken;
    auth.accountId = record.accountId;
    auth.teamId = record.teamId;
    auth.expiresAtMs = record.expiresAtMs;
    auth.observedAtMs = record.observedAtMs;
    auth.idToken = record.idToken;
    return auth;
}

bool writeUtf8FileAtomic(const std::wstring& path, std::string_view body) {
    const auto slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos) SHCreateDirectoryExW(nullptr, path.substr(0, slash).c_str(), nullptr);
    const std::wstring temp = path + L".tmp";
    HANDLE file = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const BOOL ok = WriteFile(file, body.data(), static_cast<DWORD>(body.size()), &written, nullptr);
    CloseHandle(file);
    if (!ok || written != body.size()) {
        DeleteFileW(temp.c_str());
        return false;
    }
    if (MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return true;
    DeleteFileW(temp.c_str());
    return false;
}

bool applyAccountToCli(std::wstring_view id, const AuthMaterial& auth);
bool backgroundSyncAllowed(std::wstring_view id);
bool antigravityCliTokenPath(const std::wstring& path);
AuthMaterial loadCliAuth(std::wstring_view id);
std::optional<std::int64_t> accessTokenExpiryMs(const AuthMaterial& auth);

void syncProviderTokens(std::wstring_view id) {
    if (!backgroundSyncAllowed(id)) return;
    if (managedAccounts(id)) {
        // Explicit selection authorizes ongoing write-back for that account.
        if (readDword((accountSetting(id) + L".SelectionSync").c_str(), 0)) {
            // Only push a stored token that is still valid and newer than the CLI's; never overwrite a fresh CLI
            // login (or a CLI-side refresh) with an older copy, which signs the CLI out.
            auto stored = loadStoredAuth(id);
            const auto cli = loadCliAuth(id);
            const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            const auto storedExpiry = accessTokenExpiryMs(stored);
            const bool storedValid = !stored.token.empty() && (!storedExpiry || *storedExpiry > nowMs);
            const bool cliMissing = cli.token.empty() && cli.refreshToken.empty();
            if (storedValid && (cliMissing || pickLatestValidToken(recordFromAuth(stored), recordFromAuth(cli), nowMs) == TokenPick::Left)) {
                const bool ok = applyAccountToCli(id, stored);
                writeDword((accountSetting(id) + L".SyncFailed").c_str(), ok ? 0 : 1);
            }
            SecureZeroMemory(stored.token.data(), stored.token.size());
            SecureZeroMemory(stored.refreshToken.data(), stored.refreshToken.size());
        }
        return;
    }
    if (!cliTokenSyncEnabled()) return;
    const auto format = cliFormatForProvider(utf8(id));
    if (!format) return;
    const auto paths = tokenSyncWritePaths(id);
    if (paths.empty()) return;
    std::vector<std::string> bodies(paths.size());
    std::vector<TokenRecord> records;
    records.reserve(paths.size() + 1);
    const TokenRecord stored = recordFromAuth(loadStoredAuth(id));
    records.push_back(stored);
    for (std::size_t i = 0; i < paths.size(); ++i) {
        if (auto body = readUtf8File(paths[i])) bodies[i] = std::move(*body);
        records.push_back(parseCliTokenRecord(*format, bodies[i]));
    }
    const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::optional<TokenRecord> agyWinner;
    if (id == L"antigravity") {
        for (std::size_t i = 0; i < paths.size(); ++i) {
            if (!antigravityCliTokenPath(paths[i]) || !tokenRecordUsable(records[i + 1], nowMs)) continue;
            if (!agyWinner || pickLatestValidToken(*agyWinner, records[i + 1], nowMs) == TokenPick::Right) agyWinner = records[i + 1];
        }
    }
    const TokenRecord winner = agyWinner ? *agyWinner : records[pickLatestValidTokenIndex(records, nowMs)];
    bool writeCli = false;
    for (std::size_t i = 0; i < paths.size(); ++i) {
        if (pickLatestValidToken(records[i + 1], winner, nowMs) != TokenPick::Tie
            || GetFileAttributesW(paths[i].c_str()) == INVALID_FILE_ATTRIBUTES) {
            writeCli = true;
            break;
        }
    }
    if (pickLatestValidToken(stored, winner, nowMs) == TokenPick::Tie && !writeCli) {
        for (auto& body : bodies) SecureZeroMemory(body.data(), body.size());
        return;
    }
    saveAuth(id, authFromRecord(winner));
    if (writeCli || pickLatestValidToken(stored, winner, nowMs) != TokenPick::Tie) {
        for (std::size_t i = 0; i < paths.size(); ++i) {
            const std::string merged = mergeCliCredentialJson(*format, bodies[i], winner);
            writeUtf8FileAtomic(paths[i], merged);
        }
    }
    for (auto& body : bodies) SecureZeroMemory(body.data(), body.size());
}

void syncAllProviderTokens() {
    if (!cliTokenSyncEnabled()) return;
    for (const wchar_t* id : {L"anthropic", L"openai", L"xai", L"antigravity", L"moonshot"}) syncProviderTokens(id);
}

bool antigravityCliTokenPath(const std::wstring& path) {
    return path.ends_with(L"antigravity-oauth-token");
}

AuthMaterial loadCliAuth(std::wstring_view id) {
    const auto format = cliFormatForProvider(utf8(id));
    std::vector<TokenRecord> records;
    std::vector<TokenRecord> agyRecords;
    const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    for (const auto& path : allCliReadPaths(id)) {
        auto json = readUtf8File(path);
        if (!json) continue;
        TokenRecord record = format ? parseCliTokenRecord(*format, *json) : recordFromAuth(parseAuthJson(*json));
        SecureZeroMemory(json->data(), json->size());
        if (record.accessToken.empty() && record.refreshToken.empty()) continue;
        if (id == L"antigravity" && antigravityCliTokenPath(path) && tokenRecordUsable(record, nowMs)) {
            agyRecords.push_back(record);
        }
        records.push_back(std::move(record));
    }
    // The Gemini CLI file can outlive its useful login. agy's own token file is the Antigravity session.
    if (!agyRecords.empty()) {
        AuthMaterial auth = authFromRecord(agyRecords[pickLatestValidTokenIndex(agyRecords, nowMs)]);
        auth.antigravityCli = true;
        return auth;
    }
    if (records.empty()) return {};
    return authFromRecord(records[pickLatestValidTokenIndex(records, nowMs)]);
}

bool allowOfficialCli(std::wstring_view id) {
    return readDword((accountSetting(id) + L".UseOfficialCli").c_str(), 1) != 0;
}

bool providerEnabledSetting(std::wstring_view id) {
    return readDword((L"Provider." + std::wstring(id) + L".Enabled").c_str(), 1) != 0;
}

bool backgroundSyncAllowed(std::wstring_view id) {
    return shouldBackgroundSyncProvider(providerEnabledSetting(id), allowOfficialCli(id));
}

AuthMaterial loadAuth(std::wstring_view id) {
    if (!backgroundSyncAllowed(id)) return loadStoredAuth(id);
    if (managedAccounts(id)) {
        auto stored = loadStoredAuth(id);
        if (!cliTokenSyncEnabled()) return stored;
        const auto cli = loadCliAuth(id);
        const bool same = sameCredentialAccount(recordFromAuth(stored), recordFromAuth(cli));
        const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (same && pickLatestValidToken(recordFromAuth(stored), recordFromAuth(cli), now) == TokenPick::Right) {
            if (saveAuth(id, cli)) return cli;
        }
        return stored;
    }
    AuthMaterial cli;
    if (allowOfficialCli(id)) cli = loadCliAuth(id);
    AuthMaterial stored = loadStoredAuth(id);
    const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    const TokenRecord cliRecord = recordFromAuth(cli);
    const TokenRecord storedRecord = recordFromAuth(stored);
    // A Gemini CLI oauth_creds.json expiry can outrank agy even though that login cannot read Antigravity quota.
    if (id == L"antigravity" && cli.antigravityCli && tokenRecordUsable(cliRecord, nowMs)) {
        if (pickLatestValidToken(storedRecord, cliRecord, nowMs) != TokenPick::Tie) saveAuth(id, cli);
        return cli;
    }
    const auto pick = pickLatestValidToken(cliRecord, storedRecord, nowMs);
    if (pick == TokenPick::Right) return stored;
    if (pick == TokenPick::Left) return cli;
    return tokenRecordUsable(storedRecord, nowMs) ? stored : cli;
}

bool hasAuth(std::wstring_view id) {
    auto auth = loadAuth(id);
    const bool ok = !auth.token.empty();
    SecureZeroMemory(auth.token.data(), auth.token.size());
    SecureZeroMemory(auth.refreshToken.data(), auth.refreshToken.size());
    return ok;
}

Metric unsupportedMetric(MetricKind kind) {
    Metric metric;
    metric.kind = kind;
    metric.state = MetricState::Unsupported;
    metric.diagnostic = "This provider does not expose a documented, authorized endpoint for this allowance.";
    return metric;
}

Metric authenticationMetric(MetricKind kind) {
    Metric metric;
    metric.kind = kind;
    metric.state = MetricState::AuthenticationRequired;
    metric.diagnostic = "Connect with the provider's official CLI login or paste its access token or API key.";
    return metric;
}

bool metricFetchable(std::wstring_view id, MetricKind kind) {
    if (id == L"deepseek") return kind == MetricKind::ApiCredit;
    return true;
}

Metric initialMetric(std::wstring_view id, MetricKind kind) {
    if (metricFetchable(id, kind)) return authenticationMetric(kind);
    return unsupportedMetric(kind);
}

struct HttpResponse {
    DWORD status{};
    std::string body;
    std::string error;
    std::wstring url;
    std::wstring location;
};

struct HttpRequest {
    std::wstring host;
    std::wstring path;
    std::wstring method{L"GET"};
    std::string token;
    std::wstring extraHeaders;
    std::string body;
    bool followRedirects{true};
};

HttpResponse httpsRequest(const HttpRequest& spec) {
    HttpResponse result;
    HINTERNET session = WinHttpOpen(L"HypeLimits/0.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { result.error = "Could not initialize Windows networking."; return result; }
    WinHttpSetTimeouts(session, 5000, 5000, 8000, 8000);
    HINTERNET connection = WinHttpConnect(session, spec.host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET request = connection ? WinHttpOpenRequest(connection, spec.method.c_str(), spec.path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr;
    if (request && !spec.followRedirects) {
        DWORD disable = WINHTTP_DISABLE_REDIRECTS;
        WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable));
    }
    std::wstring headers;
    if (!spec.token.empty()) headers += L"Authorization: Bearer " + wide(spec.token) + L"\r\n";
    headers += spec.extraHeaders;
    if (!spec.body.empty() && headers.find(L"Content-Type:") == std::wstring::npos) {
        headers += L"Content-Type: application/json\r\n";
    }
    BOOL sent = request && (headers.empty() || WinHttpAddRequestHeaders(request, headers.c_str(), static_cast<DWORD>(-1),
                                                    WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE))
                        && WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                              spec.body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(spec.body.data()),
                                              static_cast<DWORD>(spec.body.size()), static_cast<DWORD>(spec.body.size()), 0)
                        && WinHttpReceiveResponse(request, nullptr);
    if (sent) {
        DWORD statusSize = sizeof(result.status);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &result.status, &statusSize, WINHTTP_NO_HEADER_INDEX);
        wchar_t location[2048]{};
        DWORD locationSize = sizeof(location);
        if (WinHttpQueryHeaders(request, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX, location, &locationSize,
                                WINHTTP_NO_HEADER_INDEX)) {
            result.location = location;
        }
        DWORD urlSize = 0;
        WinHttpQueryOption(request, WINHTTP_OPTION_URL, nullptr, &urlSize);
        if (urlSize > sizeof(wchar_t)) {
            result.url.assign(urlSize / sizeof(wchar_t), L'\0');
            if (WinHttpQueryOption(request, WINHTTP_OPTION_URL, result.url.data(), &urlSize)) {
                if (!result.url.empty() && result.url.back() == L'\0') result.url.pop_back();
            }
        }
        while (result.body.size() < 1024 * 1024) {
            DWORD available{};
            if (!WinHttpQueryDataAvailable(request, &available) || available == 0) break;
            const auto oldSize = result.body.size();
            result.body.resize(oldSize + std::min<DWORD>(available, static_cast<DWORD>(1024 * 1024 - oldSize)));
            DWORD read{};
            if (!WinHttpReadData(request, result.body.data() + oldSize,
                                 static_cast<DWORD>(result.body.size() - oldSize), &read)) {
                result.body.resize(oldSize); break;
            }
            result.body.resize(oldSize + read);
        }
    } else {
        result.error = "The secure request failed.";
    }
    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    SecureZeroMemory(headers.data(), headers.size() * sizeof(wchar_t));
    return result;
}

HttpResponse httpsGet(std::wstring_view host, std::wstring_view path, std::string_view token, std::wstring extraHeaders = {}) {
    return httpsRequest({std::wstring(host), std::wstring(path), L"GET", std::string(token), std::move(extraHeaders), {}});
}

HttpResponse httpsPost(std::wstring_view host, std::wstring_view path, std::string_view body, std::wstring extraHeaders) {
    HttpRequest spec;
    spec.host = std::wstring(host);
    spec.path = std::wstring(path);
    spec.method = L"POST";
    spec.body = std::string(body);
    spec.extraHeaders = std::move(extraHeaders);
    return httpsRequest(spec);
}

std::string urlEncode(std::string_view value) {
    std::string out;
    for (const unsigned char ch : value) {
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
            out.push_back(static_cast<char>(ch));
        } else {
            out += std::format("%{:02X}", ch);
        }
    }
    return out;
}

std::string base64Url(const unsigned char* data, std::size_t size) {
    static constexpr char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((size + 2) / 3 * 4);
    for (std::size_t i = 0; i < size; i += 3) {
        unsigned int n = data[i] << 16;
        if (i + 1 < size) n |= data[i + 1] << 8;
        if (i + 2 < size) n |= data[i + 2];
        out.push_back(kTable[(n >> 18) & 63]);
        out.push_back(kTable[(n >> 12) & 63]);
        if (i + 1 < size) out.push_back(kTable[(n >> 6) & 63]);
        if (i + 2 < size) out.push_back(kTable[n & 63]);
    }
    return out;
}

std::string randomUrlToken(std::size_t bytes) {
    std::vector<unsigned char> buffer(bytes);
    BCryptGenRandom(nullptr, buffer.data(), static_cast<ULONG>(buffer.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return base64Url(buffer.data(), buffer.size());
}

std::string sha256Url(std::string_view input) {
    BCRYPT_ALG_HANDLE alg{};
    unsigned char digest[32]{};
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
    const NTSTATUS hashed = BCryptHash(alg, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                                       static_cast<ULONG>(input.size()), digest, sizeof(digest));
    BCryptCloseAlgorithmProvider(alg, 0);
    if (hashed != 0) return {};
    return base64Url(digest, sizeof(digest));
}

void applyTokenResponse(AuthMaterial& auth, const std::string& json) {
    if (auto identity = jsonString(json, "id_token")) auth.idToken = *identity;
    if (auto access = jsonString(json, "access_token")) auth.token = *access;
    if (auto refresh = jsonString(json, "refresh_token")) auth.refreshToken = *refresh;
    if (auto account = jsonString(json, "account_id")) auth.accountId = *account;
    if (const auto expIn = jsonNumber(json, "expires_in")) {
        const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        auth.expiresAtMs = now + static_cast<std::int64_t>(*expIn * 1000.0);
    }
    auth.observedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    if (auth.accountId.empty()) {
        const auto jwt = auth.token.find('.');
        if (jwt != std::string::npos) {
            if (auto id = jsonString(auth.token, "chatgpt_account_id")) auth.accountId = *id;
        }
    }
}

std::wstring kimiIdentityHeaders() {
    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD computerSize = static_cast<DWORD>(std::size(computer));
    GetComputerNameW(computer, &computerSize);
    return std::format(
        L"Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n"
        L"X-Msh-Platform: kimi_cli\r\nX-Msh-Version: hypelimits\r\nX-Msh-Device-Name: {}\r\n"
        L"X-Msh-Device-Model: Windows\r\nX-Msh-Os-Version: Windows\r\nX-Msh-Device-Id: hypelimits-{}\r\n",
        computer, computer);
}

std::wstring kimiUsageHeaders() {
    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD computerSize = static_cast<DWORD>(std::size(computer));
    GetComputerNameW(computer, &computerSize);
    return std::format(
        L"Accept: application/json\r\n"
        L"X-Msh-Platform: kimi_cli\r\nX-Msh-Version: hypelimits\r\nX-Msh-Device-Name: {}\r\n"
        L"X-Msh-Device-Model: Windows\r\nX-Msh-Os-Version: Windows\r\nX-Msh-Device-Id: hypelimits-{}\r\n",
        computer, computer);
}

struct AntigravityOAuthClient {
    std::string id;
    std::string secret;
};

bool googleOauthChar(unsigned char ch) {
    return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '-' || ch == '_';
}

// The desktop client id and secret ship inside the agy binary. Keep them out of the repo.
std::vector<AntigravityOAuthClient> clientsFromAgyBinary(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    constexpr std::string_view kSecretMarker = "generateContentGOCSPX-";
    constexpr std::string_view kClientSuffix = ".apps.googleusercontent.com";
    std::string window;
    const auto markerAt = [&](std::size_t i, std::string_view marker) {
        return i + marker.size() <= window.size() && std::string_view(window).substr(i, marker.size()) == marker;
    };
    std::string secret;
    std::vector<std::string> ids;
    char buffer[64 * 1024];
    auto scan = [&](bool final) {
        const std::size_t limit = final || window.size() <= 200 ? window.size() : window.size() - 200;
        for (std::size_t i = 0; i < limit; ++i) {
            if (secret.empty() && i + kSecretMarker.size() + 28 <= window.size() && markerAt(i, kSecretMarker)) {
                const auto start = i + kSecretMarker.size();
                const bool shaped = std::all_of(window.begin() + static_cast<std::ptrdiff_t>(start),
                                                 window.begin() + static_cast<std::ptrdiff_t>(start + 28),
                                                 [](char ch) { return googleOauthChar(static_cast<unsigned char>(ch)); });
                const bool ended = start + 28 == window.size() || !googleOauthChar(static_cast<unsigned char>(window[start + 28]));
                if (shaped && ended) secret = "GOCSPX-" + window.substr(start, 28);
            }
            if (markerAt(i, kClientSuffix)) {
                std::size_t begin = i;
                while (begin > 0 && googleOauthChar(static_cast<unsigned char>(window[begin - 1]))) --begin;
                const auto body = std::string_view(window).substr(begin, i - begin);
                const auto hyphen = body.rfind('-');
                if (hyphen == std::string_view::npos || hyphen < 6) continue;
                std::size_t project = hyphen;
                while (project > 0 && window[begin + project - 1] >= '0' && window[begin + project - 1] <= '9') --project;
                if (hyphen - project < 6 || body.size() < hyphen + 9) continue;
                const auto id = std::string(body.substr(project)) + std::string(kClientSuffix);
                if (std::ranges::find(ids, id) == ids.end()) ids.push_back(id);
            }
        }
        if (limit > 0) window.erase(0, limit);
    };
    DWORD read = 0;
    while (ReadFile(file, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
        window.append(buffer, read);
        scan(false);
    }
    CloseHandle(file);
    scan(true);
    if (secret.empty()) return {};
    std::vector<AntigravityOAuthClient> clients;
    for (const auto& id : ids) clients.push_back({id, secret});
    return clients;
}

std::vector<AntigravityOAuthClient> discoverAntigravityOAuthClients() {
    std::vector<std::wstring> paths;
    const auto homes = cachedWslHomes.empty() ? discoverWslHomes() : cachedWslHomes;
    for (const auto& home : homes) paths.push_back(joinHomeRelative(home.home, ".local/bin/agy"));
    for (const auto& distro : listWslDistros()) {
        paths.push_back(L"\\\\wsl.localhost\\" + distro + L"\\usr\\local\\bin\\agy");
        paths.push_back(L"\\\\wsl$\\" + distro + L"\\usr\\local\\bin\\agy");
    }
    wchar_t localAppData[MAX_PATH]{};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH) > 0) {
        paths.push_back(std::wstring(localAppData) + L"\\agy\\agy.exe");
    }
    std::vector<AntigravityOAuthClient> clients;
    for (const auto& path : paths) {
        auto found = clientsFromAgyBinary(path);
        clients.insert(clients.end(), found.begin(), found.end());
        if (!clients.empty()) break;
    }
    return clients;
}

HttpResponse refreshAntigravityToken(const std::string& refreshToken) {
    static std::optional<AntigravityOAuthClient> chosen;
    const auto clients = chosen ? std::vector<AntigravityOAuthClient>{*chosen} : discoverAntigravityOAuthClients();
    for (const auto& client : clients) {
        const std::string body = "grant_type=refresh_token&refresh_token=" + urlEncode(refreshToken) +
                                 "&client_id=" + urlEncode(client.id) +
                                 "&client_secret=" + urlEncode(client.secret);
        HttpResponse response = httpsPost(L"oauth2.googleapis.com", L"/token", body, L"Content-Type: application/x-www-form-urlencoded\r\n");
        if (response.status == 200 && jsonString(response.body, "access_token")) {
            chosen = client;
            return response;
        }
    }
    return {};
}

bool refreshOAuth(std::wstring_view credentialId, AuthMaterial& auth) {
    if (auth.refreshToken.empty()) return false;
    // A rejected refresh token is stale (rotated elsewhere). Retrying it only invites the provider to revoke the
    // whole token family, which signs the provider's CLI out. Back off instead.
    static std::map<std::wstring, ULONGLONG> blockedUntil;
    static std::mutex blockedMutex;
    const std::wstring blockKey = std::wstring(credentialId) + L"|" + wide(auth.refreshToken.substr(auth.refreshToken.size() > 12 ? auth.refreshToken.size() - 12 : 0));
    {
        std::lock_guard lock(blockedMutex);
        const auto found = blockedUntil.find(blockKey);
        if (found != blockedUntil.end() && found->second > GetTickCount64()) return false;
    }
    const auto slotMarker = credentialId.find(L"/account-");
    const std::wstring providerStorage = slotMarker == std::wstring_view::npos
        ? std::wstring(credentialId) : std::wstring(credentialId.substr(0, slotMarker));
    const std::wstring_view id = providerStorage;
    HttpResponse response;
    if (id == L"anthropic") {
        const std::string body = std::format(
            "{{\"grant_type\":\"refresh_token\",\"refresh_token\":\"{}\",\"client_id\":\"9d1c250a-e61b-44d9-88ed-5944d1962f5e\"}}",
            jsonEscape(auth.refreshToken));
        response = httpsPost(L"platform.claude.com", L"/v1/oauth/token", body, L"Content-Type: application/json\r\n");
    } else if (id == L"openai") {
        const std::string body = "grant_type=refresh_token&refresh_token=" + urlEncode(auth.refreshToken) +
                                 "&client_id=" + urlEncode("app_EMoamEEZ73f0CkXaXp7hrann");
        response = httpsPost(L"auth.openai.com", L"/oauth/token", body, L"Content-Type: application/x-www-form-urlencoded\r\n");
    } else if (id == L"xai") {
        const std::string body = "grant_type=refresh_token&refresh_token=" + urlEncode(auth.refreshToken) +
                                 "&client_id=" + urlEncode("b1a00492-073a-47ea-816f-4c329264a828");
        response = httpsPost(L"auth.x.ai", L"/oauth2/token", body, L"Content-Type: application/x-www-form-urlencoded\r\n");
    } else if (id == L"antigravity") {
        // agy issues refresh tokens for its own desktop client, not the Gemini CLI client.
        response = refreshAntigravityToken(auth.refreshToken);
        if (response.status != 200) return false;
    } else if (id == L"moonshot") {
        const std::string body = "grant_type=refresh_token&refresh_token=" + urlEncode(auth.refreshToken) +
                                 "&client_id=" + urlEncode("17e5f671-d194-4dfb-9706-5516cb48c098");
        response = httpsPost(L"auth.kimi.com", L"/api/oauth/token", body, kimiIdentityHeaders());
    } else {
        return false;
    }
    if (response.status != 200 || !jsonString(response.body, "access_token")) {
        if (response.status >= 400 && response.status < 500 && response.status != 429) {
            std::lock_guard lock(blockedMutex);
            blockedUntil[blockKey] = GetTickCount64() + 6ULL * 60 * 60 * 1000;
        }
        return false;
    }
    applyTokenResponse(auth, response.body);
    saveAuth(credentialId, auth);
    // Only the selected account is written back to the CLI. Other slots stay in Credential Manager.
    if (slotMarker == std::wstring_view::npos) syncProviderTokens(id);
    return true;
}

bool providerHasSubscriptionOAuth(std::wstring_view id) {
    return id == L"anthropic" || id == L"openai" || id == L"xai" || id == L"antigravity" || id == L"moonshot";
}

bool providerHasOfficialReauth(std::wstring_view id) {
    return providerHasSubscriptionOAuth(id);
}

void markOfficialLogin(std::wstring_view id, bool official) {
    writeDword((accountSetting(id) + L".OfficialLogin").c_str(), official ? 1 : 0);
}

bool accountUsedOfficialSignIn(std::wstring_view id) {
    if (readDword((accountSetting(id) + L".OfficialLogin").c_str(), 0) != 0) return true;
    auto auth = loadAuth(id);
    const bool official = !auth.refreshToken.empty();
    SecureZeroMemory(auth.token.data(), auth.token.size());
    SecureZeroMemory(auth.refreshToken.data(), auth.refreshToken.size());
    return official;
}

std::vector<std::string> cookieHostSuffixes(std::wstring_view id) {
    if (id == L"anthropic") return {"claude.ai", "claude.com", "anthropic.com"};
    if (id == L"openai") return {"chatgpt.com", "openai.com", "auth.openai.com"};
    if (id == L"xai") return {"x.ai", "grok.com", "auth.x.ai"};
    if (id == L"antigravity") return {"google.com", "googleapis.com", "googleusercontent.com"};
    if (id == L"moonshot") return {"kimi.ai", "kimi.com", "moonshot.ai", "auth.kimi.com"};
    return {};
}

std::wstring webViewUserDataFolder() {
    PWSTR local{};
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local)) || !local) return {};
    const std::wstring root = std::wstring(local) + L"\\HypeLimits";
    CoTaskMemFree(local);
    CreateDirectoryW(root.c_str(), nullptr);
    const std::wstring path = root + L"\\WebView2";
    CreateDirectoryW(path.c_str(), nullptr);
    return path;
}

std::optional<std::string> codeFromHttp(const HttpResponse& response) {
    std::string haystack = utf8(response.url) + "\n" + utf8(response.location) + "\n" + response.body;
    return extractAuthorizationCode(haystack);
}

std::string claudeAuthorizeQuery(std::string_view challenge, std::string_view state) {
    // Claude.ai rejects states shorter than 32 random bytes with "Invalid request format".
    return std::format(
        "/cai/oauth/authorize?code=true&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e&response_type=code"
        "&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback"
        "&scope=org%3Acreate_api_key%20user%3Aprofile%20user%3Ainference%20user%3Asessions%3Aclaude_code%20user%3Amcp_servers%20user%3Afile_upload"
        "&code_challenge={}&code_challenge_method=S256&state={}",
        challenge, state);
}

bool exchangeClaudeCode(AuthMaterial& auth, std::string_view code, std::string_view verifier, std::string_view state) {
    const std::string body = std::format(
        "{{\"grant_type\":\"authorization_code\",\"code\":\"{}\",\"redirect_uri\":\"https://platform.claude.com/oauth/code/callback\","
        "\"client_id\":\"9d1c250a-e61b-44d9-88ed-5944d1962f5e\",\"code_verifier\":\"{}\",\"state\":\"{}\"}}",
        jsonEscape(std::string{code}), jsonEscape(std::string{verifier}), jsonEscape(std::string{state}));
    const auto response = httpsPost(L"platform.claude.com", L"/v1/oauth/token", body, L"Content-Type: application/json\r\n");
    if (response.status != 200) return false;
    applyTokenResponse(auth, response.body);
    return !auth.token.empty();
}

struct DevicePoll {
    std::wstring host;
    std::wstring path;
    std::string body;
    std::wstring headers{L"Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n"};
    int intervalMs{5000};
    DWORD timeoutMs{15 * 60 * 1000};
    std::function<bool(const HttpResponse&, AuthMaterial&)> complete;
};

bool waitForDeviceApproval(HWND parent, const std::wstring& userCode, const std::wstring& verifyUrl, DevicePoll poll, AuthMaterial& auth) {
    ShellExecuteW(parent, L"open", verifyUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    struct State {
        DevicePoll* poll;
        AuthMaterial* auth;
        DWORD lastPoll{};
        bool done{};
        bool ok{};
    } state{&poll, &auth, 0, false, false};

    const std::wstring content = L"A browser window opened for subscription sign-in (the same usage as the provider's own app).\n\nEnter this code if asked:\n\n" +
                                 userCode + L"\n\nWaiting for approval...";
    TASKDIALOGCONFIG cfg{};
    cfg.cbSize = sizeof(cfg);
    cfg.hwndParent = parent;
    cfg.dwFlags = TDF_CALLBACK_TIMER | TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT;
    cfg.dwCommonButtons = TDCBF_CANCEL_BUTTON;
    cfg.pszWindowTitle = kAppName;
    cfg.pszMainInstruction = L"Sign in with your subscription";
    cfg.pszContent = content.c_str();
    cfg.lpCallbackData = reinterpret_cast<LONG_PTR>(&state);
    cfg.pfCallback = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM, LONG_PTR data) -> HRESULT {
        auto* state = reinterpret_cast<State*>(data);
        if (msg == TDN_TIMER && !state->done) {
            if (wParam - state->lastPoll >= static_cast<WPARAM>(state->poll->intervalMs)) {
                state->lastPoll = static_cast<DWORD>(wParam);
                const auto response = httpsPost(state->poll->host, state->poll->path, state->poll->body, state->poll->headers);
                if (state->poll->complete(response, *state->auth)) {
                    state->ok = true;
                    state->done = true;
                    SendMessageW(hwnd, TDM_CLICK_BUTTON, IDCANCEL, 0);
                } else if (response.body.find("expired") != std::string::npos || response.body.find("access_denied") != std::string::npos) {
                    state->done = true;
                    SendMessageW(hwnd, TDM_CLICK_BUTTON, IDCANCEL, 0);
                } else if (response.body.find("slow_down") != std::string::npos) {
                    state->poll->intervalMs += 5000;
                }
            }
            if (wParam >= state->poll->timeoutMs) {
                state->done = true;
                SendMessageW(hwnd, TDM_CLICK_BUTTON, IDCANCEL, 0);
            }
        }
        if (msg == TDN_BUTTON_CLICKED && wParam == IDCANCEL) state->done = true;
        return S_OK;
    };
    TaskDialogIndirect(&cfg, nullptr, nullptr, nullptr);
    return state.ok && !auth.token.empty();
}

bool waitForDeviceApprovalSilent(HWND parent, const std::wstring& verifyUrl, DevicePoll poll, AuthMaterial& auth,
                                 const std::vector<BrowserCookie>& cookies) {
    poll.timeoutMs = std::min<DWORD>(poll.timeoutMs, 25000);
    std::atomic_bool done{false};
    std::jthread poller([&] {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
        DWORD last = 0;
        const DWORD started = GetTickCount();
        while (!done.load() && GetTickCount() - started < poll.timeoutMs) {
            if (GetTickCount() - last >= static_cast<DWORD>(poll.intervalMs)) {
                last = GetTickCount();
                const auto response = httpsPost(poll.host, poll.path, poll.body, poll.headers);
                if (poll.complete(response, auth)) {
                    done = true;
                    return;
                }
                if (response.body.find("expired") != std::string::npos || response.body.find("access_denied") != std::string::npos) {
                    done = true;
                    return;
                }
                if (response.body.find("slow_down") != std::string::npos) poll.intervalMs += 5000;
            }
            Sleep(200);
        }
    });
    runWebViewOAuth(parent, verifyUrl, webViewUserDataFolder(), cookies, poll.timeoutMs);
    done = true;
    if (poller.joinable()) poller.join();
    return !auth.token.empty();
}

bool runClaudeOAuth(HWND parent, AuthMaterial& auth) {
    const std::string verifier = randomUrlToken(32);
    const std::string state = randomUrlToken(32);
    const std::string challenge = sha256Url(verifier);
    const std::wstring url = wide("https://claude.com" + claudeAuthorizeQuery(challenge, state));
    ShellExecuteW(parent, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    CREDUI_INFOW info{sizeof(info), parent, L"Claude subscription sign-in",
                      L"Finish sign-in in the browser, then paste the authorization code (code#state) into the password field.", nullptr};
    wchar_t user[2] = L"-";
    wchar_t secret[2048]{};
    BOOL save = FALSE;
    if (CredUIPromptForCredentialsW(&info, L"HypeLimits/anthropic-oauth", nullptr, 0, user, 2, secret, static_cast<ULONG>(std::size(secret)),
                                    &save, CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_ALWAYS_SHOW_UI | CREDUI_FLAGS_DO_NOT_PERSIST | CREDUI_FLAGS_EXCLUDE_CERTIFICATES) != NO_ERROR ||
        secret[0] == L'\0') {
        SecureZeroMemory(secret, sizeof(secret));
        return false;
    }
    std::string pasted = utf8(secret);
    SecureZeroMemory(secret, sizeof(secret));
    std::string code = pasted;
    if (const auto pos = pasted.find("code="); pos != std::string::npos) {
        code = pasted.substr(pos + 5);
        const auto end = code.find_first_of("&# ");
        if (end != std::string::npos) code = code.substr(0, end);
    } else if (const auto hash = pasted.find('#'); hash != std::string::npos) {
        code = pasted.substr(0, hash);
    }
    const std::string body = std::format(
        "{{\"grant_type\":\"authorization_code\",\"code\":\"{}\",\"redirect_uri\":\"https://platform.claude.com/oauth/code/callback\","
        "\"client_id\":\"9d1c250a-e61b-44d9-88ed-5944d1962f5e\",\"code_verifier\":\"{}\",\"state\":\"{}\"}}",
        jsonEscape(code), jsonEscape(verifier), jsonEscape(state));
    const auto response = httpsPost(L"platform.claude.com", L"/v1/oauth/token", body, L"Content-Type: application/json\r\n");
    if (response.status != 200) return false;
    applyTokenResponse(auth, response.body);
    return !auth.token.empty();
}

bool runCodexOAuth(HWND parent, AuthMaterial& auth) {
    const auto started = httpsPost(L"auth.openai.com", L"/api/accounts/deviceauth/usercode",
                                   R"({"client_id":"app_EMoamEEZ73f0CkXaXp7hrann"})", L"Content-Type: application/json\r\n");
    const auto deviceId = jsonString(started.body, "device_auth_id");
    const auto userCode = jsonString(started.body, "user_code");
    if (started.status != 200 || !deviceId || !userCode) return false;
    DevicePoll poll;
    poll.host = L"auth.openai.com";
    poll.path = L"/api/accounts/deviceauth/token";
    poll.body = std::format("{{\"device_auth_id\":\"{}\",\"user_code\":\"{}\"}}", jsonEscape(*deviceId), jsonEscape(*userCode));
    poll.headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    poll.complete = [](const HttpResponse& response, AuthMaterial& out) {
        if (response.status != 200) return false;
        const auto code = jsonString(response.body, "authorization_code");
        const auto verifier = jsonString(response.body, "code_verifier");
        if (!code || !verifier) return false;
        const std::string body = "grant_type=authorization_code&code=" + urlEncode(*code) +
                                 "&code_verifier=" + urlEncode(*verifier) +
                                 "&client_id=" + urlEncode("app_EMoamEEZ73f0CkXaXp7hrann") +
                                 "&redirect_uri=" + urlEncode("https://auth.openai.com/deviceauth/callback");
        const auto tokens = httpsPost(L"auth.openai.com", L"/oauth/token", body, L"Content-Type: application/x-www-form-urlencoded\r\n");
        if (tokens.status != 200) return false;
        applyTokenResponse(out, tokens.body);
        return !out.token.empty();
    };
    return waitForDeviceApproval(parent, wide(*userCode), L"https://auth.openai.com/codex/device", poll, auth);
}

bool runGrokOAuth(HWND parent, AuthMaterial& auth) {
    const std::string startBody = "client_id=" + urlEncode("b1a00492-073a-47ea-816f-4c329264a828") +
                                  "&scope=" + urlEncode("openid profile email offline_access grok-cli:access api:access");
    const auto started = httpsPost(L"auth.x.ai", L"/oauth2/device/code", startBody,
                                   L"Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n");
    const auto device = jsonString(started.body, "device_code");
    const auto userCode = jsonString(started.body, "user_code");
    auto verify = jsonString(started.body, "verification_uri_complete");
    if (!verify) verify = jsonString(started.body, "verification_uri");
    if (started.status != 200 || !device || !userCode) return false;
    DevicePoll poll;
    poll.host = L"auth.x.ai";
    poll.path = L"/oauth2/token";
    poll.body = "grant_type=" + urlEncode("urn:ietf:params:oauth:grant-type:device_code") +
                "&device_code=" + urlEncode(*device) +
                "&client_id=" + urlEncode("b1a00492-073a-47ea-816f-4c329264a828");
    if (const auto interval = jsonNumber(started.body, "interval")) poll.intervalMs = std::max(1000, static_cast<int>(*interval * 1000.0));
    poll.complete = [](const HttpResponse& response, AuthMaterial& out) {
        if (response.status != 200 || !jsonString(response.body, "access_token")) return false;
        applyTokenResponse(out, response.body);
        return true;
    };
    return waitForDeviceApproval(parent, wide(*userCode), wide(verify.value_or("https://auth.x.ai/oauth2/device")), poll, auth);
}

bool runGoogleOAuth(HWND parent, AuthMaterial& auth) {
    auto secret = loadGoogleClientSecret();
    if (secret.empty()) return false;
    const std::string startBody = "client_id=" + urlEncode("681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com") +
                                  "&scope=" + urlEncode("https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile");
    const auto started = httpsPost(L"oauth2.googleapis.com", L"/device/code", startBody,
                                   L"Content-Type: application/x-www-form-urlencoded\r\n");
    const auto device = jsonString(started.body, "device_code");
    const auto userCode = jsonString(started.body, "user_code");
    auto verify = jsonString(started.body, "verification_url");
    if (!verify) verify = jsonString(started.body, "verification_uri");
    if (started.status != 200 || !device || !userCode) {
        SecureZeroMemory(secret.data(), secret.size());
        return false;
    }
    DevicePoll poll;
    poll.host = L"oauth2.googleapis.com";
    poll.path = L"/token";
    poll.body = "grant_type=" + urlEncode("urn:ietf:params:oauth:grant-type:device_code") +
                "&device_code=" + urlEncode(*device) +
                "&client_id=" + urlEncode("681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com") +
                "&client_secret=" + urlEncode(secret);
    SecureZeroMemory(secret.data(), secret.size());
    if (const auto interval = jsonNumber(started.body, "interval")) poll.intervalMs = std::max(1000, static_cast<int>(*interval * 1000.0));
    poll.complete = [](const HttpResponse& response, AuthMaterial& out) {
        if (response.status != 200 || !jsonString(response.body, "access_token")) return false;
        applyTokenResponse(out, response.body);
        return true;
    };
    return waitForDeviceApproval(parent, wide(*userCode), wide(verify.value_or("https://www.google.com/device")), poll, auth);
}

bool startKimiDevice(DevicePoll& poll, std::wstring& userCode, std::wstring& verifyUrl) {
    constexpr char kClient[] = "17e5f671-d194-4dfb-9706-5516cb48c098";
    const std::string startBody = "client_id=" + urlEncode(kClient);
    const auto started = httpsPost(L"auth.kimi.com", L"/api/oauth/device_authorization", startBody, kimiIdentityHeaders());
    const auto device = jsonString(started.body, "device_code");
    const auto code = jsonString(started.body, "user_code");
    auto verify = jsonString(started.body, "verification_uri_complete");
    if (!verify) verify = jsonString(started.body, "verification_uri");
    if (started.status != 200 || !device || !code) return false;
    userCode = wide(*code);
    verifyUrl = wide(verify.value_or("https://www.kimi.com/code/authorize_device"));
    poll.host = L"auth.kimi.com";
    poll.path = L"/api/oauth/token";
    poll.body = "grant_type=" + urlEncode("urn:ietf:params:oauth:grant-type:device_code") +
                "&device_code=" + urlEncode(*device) + "&client_id=" + urlEncode(kClient);
    poll.headers = kimiIdentityHeaders();
    if (const auto interval = jsonNumber(started.body, "interval")) poll.intervalMs = std::max(1000, static_cast<int>(*interval * 1000.0));
    poll.complete = [](const HttpResponse& response, AuthMaterial& out) {
        if (response.status != 200 || !jsonString(response.body, "access_token")) return false;
        applyTokenResponse(out, response.body);
        return true;
    };
    return true;
}

bool runKimiOAuth(HWND parent, AuthMaterial& auth) {
    DevicePoll poll;
    std::wstring userCode;
    std::wstring verifyUrl;
    if (!startKimiDevice(poll, userCode, verifyUrl)) return false;
    return waitForDeviceApproval(parent, userCode, verifyUrl, poll, auth);
}

bool runSubscriptionOAuth(HWND parent, std::wstring_view id, AuthMaterial& auth) {
    if (id == L"anthropic") return runClaudeOAuth(parent, auth);
    if (id == L"openai") return runCodexOAuth(parent, auth);
    if (id == L"xai") return runGrokOAuth(parent, auth);
    if (id == L"antigravity") return runGoogleOAuth(parent, auth);
    if (id == L"moonshot") return runKimiOAuth(parent, auth);
    return false;
}

bool tryClaudeAuthorizeHttp(AuthMaterial& auth, const std::vector<BrowserCookie>& cookies, std::string_view verifier,
                            std::string_view state, std::string_view challenge) {
    const std::wstring path = wide(claudeAuthorizeQuery(challenge, state));
    std::wstring cookie;
    for (const char* host : {"claude.com", "claude.ai", "anthropic.com"}) {
        const auto part = wide(cookieHeaderForHost(cookies, host));
        if (part.empty()) continue;
        if (!cookie.empty()) cookie += L"; ";
        cookie += part;
    }
    HttpRequest spec;
    spec.host = L"claude.com";
    spec.path = path;
    spec.followRedirects = false;
    if (!cookie.empty()) spec.extraHeaders = L"Cookie: " + cookie + L"\r\nAccept: text/html,application/json\r\n";
    auto response = httpsRequest(spec);
    SecureZeroMemory(cookie.data(), cookie.size() * sizeof(wchar_t));
    if (auto code = codeFromHttp(response)) return exchangeClaudeCode(auth, *code, verifier, state);
    for (int hop = 0; hop < 6 && !response.location.empty(); ++hop) {
        std::wstring loc = response.location;
        std::wstring host = spec.host;
        std::wstring nextPath = loc;
        if (loc.starts_with(L"https://")) {
            loc.erase(0, 8);
            const auto slash = loc.find(L'/');
            host = slash == std::wstring::npos ? loc : loc.substr(0, slash);
            nextPath = slash == std::wstring::npos ? L"/" : loc.substr(slash);
        }
        spec.host = host;
        spec.path = nextPath;
        spec.extraHeaders = L"Cookie: " + wide(cookieHeaderForHost(cookies, utf8(host))) + L"\r\nAccept: text/html\r\n";
        response = httpsRequest(spec);
        if (auto code = codeFromHttp(response)) return exchangeClaudeCode(auth, *code, verifier, state);
    }
    return false;
}

bool autoRunOfficialSignIn(HWND parent, std::wstring_view id, AuthMaterial& auth, const std::vector<BrowserCookie>& cookies) {
    if (id == L"anthropic") {
        const std::string verifier = randomUrlToken(32);
        const std::string state = randomUrlToken(32);
        const std::string challenge = sha256Url(verifier);
        if (tryClaudeAuthorizeHttp(auth, cookies, verifier, state, challenge)) return true;
        const std::wstring url = wide("https://claude.com" + claudeAuthorizeQuery(challenge, state));
        const auto captured = runWebViewOAuth(parent, url, webViewUserDataFolder(), cookies, 25000);
        const std::string haystack = utf8(captured.url) + "\n" + utf8(captured.pageText);
        if (const auto code = extractAuthorizationCode(haystack)) return exchangeClaudeCode(auth, *code, verifier, state);
        return false;
    }
    if (id == L"openai") {
        const auto started = httpsPost(L"auth.openai.com", L"/api/accounts/deviceauth/usercode",
                                       R"({"client_id":"app_EMoamEEZ73f0CkXaXp7hrann"})", L"Content-Type: application/json\r\n");
        const auto deviceId = jsonString(started.body, "device_auth_id");
        const auto userCode = jsonString(started.body, "user_code");
        if (started.status != 200 || !deviceId || !userCode) return false;
        DevicePoll poll;
        poll.host = L"auth.openai.com";
        poll.path = L"/api/accounts/deviceauth/token";
        poll.body = std::format("{{\"device_auth_id\":\"{}\",\"user_code\":\"{}\"}}", jsonEscape(*deviceId), jsonEscape(*userCode));
        poll.headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
        poll.complete = [](const HttpResponse& response, AuthMaterial& out) {
            if (response.status != 200) return false;
            const auto code = jsonString(response.body, "authorization_code");
            const auto verifier = jsonString(response.body, "code_verifier");
            if (!code || !verifier) return false;
            const std::string body = "grant_type=authorization_code&code=" + urlEncode(*code) +
                                     "&code_verifier=" + urlEncode(*verifier) +
                                     "&client_id=" + urlEncode("app_EMoamEEZ73f0CkXaXp7hrann") +
                                     "&redirect_uri=" + urlEncode("https://auth.openai.com/deviceauth/callback");
            const auto tokens = httpsPost(L"auth.openai.com", L"/oauth/token", body, L"Content-Type: application/x-www-form-urlencoded\r\n");
            if (tokens.status != 200) return false;
            applyTokenResponse(out, tokens.body);
            return !out.token.empty();
        };
        return waitForDeviceApprovalSilent(parent, L"https://auth.openai.com/codex/device", poll, auth, cookies);
    }
    if (id == L"xai") {
        const std::string startBody = "client_id=" + urlEncode("b1a00492-073a-47ea-816f-4c329264a828") +
                                      "&scope=" + urlEncode("openid profile email offline_access grok-cli:access api:access");
        const auto started = httpsPost(L"auth.x.ai", L"/oauth2/device/code", startBody,
                                       L"Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n");
        const auto device = jsonString(started.body, "device_code");
        const auto userCode = jsonString(started.body, "user_code");
        auto verify = jsonString(started.body, "verification_uri_complete");
        if (!verify) verify = jsonString(started.body, "verification_uri");
        if (started.status != 200 || !device || !userCode) return false;
        DevicePoll poll;
        poll.host = L"auth.x.ai";
        poll.path = L"/oauth2/token";
        poll.body = "grant_type=" + urlEncode("urn:ietf:params:oauth:grant-type:device_code") +
                    "&device_code=" + urlEncode(*device) +
                    "&client_id=" + urlEncode("b1a00492-073a-47ea-816f-4c329264a828");
        if (const auto interval = jsonNumber(started.body, "interval")) poll.intervalMs = std::max(1000, static_cast<int>(*interval * 1000.0));
        poll.complete = [](const HttpResponse& response, AuthMaterial& out) {
            if (response.status != 200 || !jsonString(response.body, "access_token")) return false;
            applyTokenResponse(out, response.body);
            return true;
        };
        return waitForDeviceApprovalSilent(parent, wide(verify.value_or("https://auth.x.ai/oauth2/device")), poll, auth, cookies);
    }
    if (id == L"antigravity") {
        auto secret = loadGoogleClientSecret();
        if (secret.empty()) return false;
        const std::string startBody = "client_id=" + urlEncode("681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com") +
                                      "&scope=" + urlEncode("https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile");
        const auto started = httpsPost(L"oauth2.googleapis.com", L"/device/code", startBody,
                                       L"Content-Type: application/x-www-form-urlencoded\r\n");
        const auto device = jsonString(started.body, "device_code");
        const auto userCode = jsonString(started.body, "user_code");
        auto verify = jsonString(started.body, "verification_url");
        if (!verify) verify = jsonString(started.body, "verification_uri");
        if (started.status != 200 || !device || !userCode) {
            SecureZeroMemory(secret.data(), secret.size());
            return false;
        }
        DevicePoll poll;
        poll.host = L"oauth2.googleapis.com";
        poll.path = L"/token";
        poll.body = "grant_type=" + urlEncode("urn:ietf:params:oauth:grant-type:device_code") +
                    "&device_code=" + urlEncode(*device) +
                    "&client_id=" + urlEncode("681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com") +
                    "&client_secret=" + urlEncode(secret);
        SecureZeroMemory(secret.data(), secret.size());
        if (const auto interval = jsonNumber(started.body, "interval")) poll.intervalMs = std::max(1000, static_cast<int>(*interval * 1000.0));
        poll.complete = [](const HttpResponse& response, AuthMaterial& out) {
            if (response.status != 200 || !jsonString(response.body, "access_token")) return false;
            applyTokenResponse(out, response.body);
            return true;
        };
        return waitForDeviceApprovalSilent(parent, wide(verify.value_or("https://www.google.com/device")), poll, auth, cookies);
    }
    if (id == L"moonshot") {
        if (!auth.refreshToken.empty() && refreshOAuth(id, auth)) return true;
        DevicePoll poll;
        std::wstring userCode;
        std::wstring verifyUrl;
        if (!startKimiDevice(poll, userCode, verifyUrl)) return false;
        return waitForDeviceApprovalSilent(parent, verifyUrl, poll, auth, cookies);
    }
    return false;
}

Metric* metricSlot(ProviderSnapshot& snapshot, MetricKind kind) {
    auto found = std::ranges::find_if(snapshot.metrics, [&](const Metric& metric) { return metric.kind == kind; });
    if (found != snapshot.metrics.end()) return &*found;
    snapshot.metrics.push_back(Metric{kind});
    return &snapshot.metrics.back();
}

void applyWindow(ProviderSnapshot& snapshot, MetricKind kind, const UsageWindow& window, TimePoint now) {
    Metric* metric = metricSlot(snapshot, kind);
    const Metric previous = *metric;
    metric->kind = kind;
    metric->state = MetricState::Current;
    metric->announceAuthentication = false;
    metric->used = window.used;
    metric->capacity = window.capacity;
    metric->remaining = std::max(0.0, window.capacity - window.used);
    metric->unit = window.unit;
    metric->resetAt = window.resetAt;
    metric->observedAt = now;
    metric->diagnostic.clear();
    metric->drawingDown = usageDrewDownSince(previous, *metric);
    if (metric->drawingDown) metric->lastDrawdownAt = now;
}

void applyCredit(ProviderSnapshot& snapshot, const BalanceValue& credit, TimePoint now, std::optional<double> threshold,
                 double barFull) {
    Metric* metric = metricSlot(snapshot, MetricKind::ApiCredit);
    const Metric previous = *metric;
    metric->kind = MetricKind::ApiCredit;
    metric->state = MetricState::Current;
    metric->announceAuthentication = false;
    metric->remaining = credit.amount;
    metric->used = credit.used;
    metric->capacity = credit.capacity;
    metric->currency = credit.currency;
    metric->observedAt = now;
    metric->lowBalanceThreshold = threshold;
    metric->barFullAmount = barFull > 0.0 ? barFull : 100.0;
    metric->diagnostic.clear();
    metric->drawingDown = usageDrewDownSince(previous, *metric);
    if (metric->drawingDown) metric->lastDrawdownAt = now;
}

void applyUsage(ProviderSnapshot& snapshot, const ProviderUsage& usage, TimePoint now, std::optional<double> threshold,
                double barFull) {
    if (usage.session) applyWindow(snapshot, MetricKind::Session, *usage.session, now);
    if (usage.weekly) applyWindow(snapshot, MetricKind::Weekly, *usage.weekly, now);
    if (usage.credit) applyCredit(snapshot, *usage.credit, now, threshold, barFull);
    snapshot.lastSuccessfulRefresh = now;
}

bool metricHasLastValue(const Metric& metric) {
    return metric.used.has_value() || metric.remaining.has_value() || (metric.capacity && *metric.capacity > 0.0);
}

void markAuthenticationFailed(Metric& metric, std::string diagnostic) {
    if (!metricHasLastValue(metric)) {
        const auto kind = metric.kind;
        metric = authenticationMetric(kind);
    } else {
        metric.state = MetricState::AuthenticationRequired;
    }
    metric.announceAuthentication = true;
    if (!diagnostic.empty()) metric.diagnostic = std::move(diagnostic);
}

void failMetric(Metric& metric, DWORD status, const std::string& error) {
    if (status == 401 || status == 403) {
        markAuthenticationFailed(metric, "The saved credential was rejected. Connect again from Options.");
        return;
    }
    metric.state = metricHasLastValue(metric) ? MetricState::Stale : MetricState::Error;
    metric.diagnostic = error.empty() ? "The provider returned HTTP " + std::to_string(status) + "." : error;
}

void finishRefresh(ProviderSnapshot& snapshot, bool gotData, bool authenticationRejected, DWORD lastStatus, const std::string& lastError) {
    for (auto& metric : snapshot.metrics) {
        if (metric.state != MetricState::Refreshing) continue;
        if (authenticationRejected) {
            markAuthenticationFailed(metric, "The saved credential was rejected. Connect again from Options.");
        } else if (gotData) {
            metric.state = MetricState::Unsupported;
            metric.announceAuthentication = false;
            metric.diagnostic = "This provider did not return this allowance for the connected account.";
        } else {
            failMetric(metric, lastStatus, lastError);
        }
    }
}

bool mergeHttpUsage(ProviderSnapshot& snapshot, const HttpResponse& response, const std::optional<ProviderUsage>& parsed,
                    TimePoint now, std::optional<double> threshold, double barFull, DWORD& lastStatus, std::string& lastError,
                    bool& authenticationRejected) {
    lastStatus = response.status;
    lastError = response.error;
    if (response.status == 401 || response.status == 403) authenticationRejected = true;
    if (response.status == 200 && parsed) {
        applyUsage(snapshot, *parsed, now, threshold, barFull);
        return true;
    }
    return false;
}

// Expiry from the explicit field, else the access token's own JWT "exp" claim. Unknown means "do not refresh":
// refresh tokens rotate, so a blind refresh would invalidate the copy the provider's CLI is holding.
std::optional<std::int64_t> accessTokenExpiryMs(const AuthMaterial& auth) {
    if (auth.expiresAtMs) return auth.expiresAtMs;
    const auto first = auth.token.find('.');
    if (first == std::string::npos) return std::nullopt;
    const auto second = auth.token.find('.', first + 1);
    if (second == std::string::npos) return std::nullopt;
    std::string payload;
    unsigned int bits = 0;
    int count = 0;
    for (std::size_t i = first + 1; i < second; ++i) {
        const char ch = auth.token[i];
        int value = -1;
        if (ch >= 'A' && ch <= 'Z') value = ch - 'A';
        else if (ch >= 'a' && ch <= 'z') value = ch - 'a' + 26;
        else if (ch >= '0' && ch <= '9') value = ch - '0' + 52;
        else if (ch == '-' || ch == '+') value = 62;
        else if (ch == '_' || ch == '/') value = 63;
        if (value < 0) continue;
        bits = (bits << 6) | static_cast<unsigned int>(value);
        count += 6;
        if (count >= 8) {
            count -= 8;
            payload.push_back(static_cast<char>((bits >> count) & 0xFF));
        }
    }
    if (const auto exp = jsonNumber(payload, "exp")) return static_cast<std::int64_t>(*exp * 1000.0);
    return std::nullopt;
}

bool accessTokenNeedsRefresh(const AuthMaterial& auth) {
    if (auth.refreshToken.empty()) return false;
    const auto expiry = accessTokenExpiryMs(auth);
    if (!expiry) return false;
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    return *expiry <= now;
}

// The CLI may have refreshed since this credential was loaded. Adopt its unexpired token instead of rotating
// the shared refresh token a second time.
bool adoptNewerCliToken(std::wstring_view id, AuthMaterial& auth) {
    if (!allowOfficialCli(id)) return false;
    // For managed accounts the CLI file holds the selected account's live token only after an explicit selection.
    if (managedAccounts(id) && !readDword((accountSetting(id) + L".SelectionSync").c_str(), 0)) return false;
    AuthMaterial cli = loadCliAuth(id);
    const bool usable = !cli.token.empty() && (cli.token != auth.token || cli.refreshToken != auth.refreshToken)
        && !accessTokenNeedsRefresh(cli) && (cli.expiresAtMs || accessTokenExpiryMs(cli));
    if (usable) {
        auth = cli;
        saveAuth(id, auth);
    }
    SecureZeroMemory(cli.token.data(), cli.token.size());
    SecureZeroMemory(cli.refreshToken.data(), cli.refreshToken.size());
    return usable;
}

void queryProviderUsage(std::wstring_view id, const AuthMaterial& auth, ProviderSnapshot& snapshot,
                       TimePoint now, std::optional<double> threshold, double barFull,
                       DWORD& lastStatus, std::string& lastError, bool& gotData, bool& authenticationRejected) {
    lastStatus = 0;
    lastError.clear();
    gotData = false;
    authenticationRejected = false;
    if (id == L"anthropic") {
        auto response = httpsGet(L"api.anthropic.com", L"/api/oauth/usage", auth.token,
                                 L"anthropic-beta: oauth-2025-04-20\r\nanthropic-version: 2023-06-01\r\nx-app: cli\r\n");
        gotData = mergeHttpUsage(snapshot, response, parseClaudeUsage(response.body), now, threshold, barFull, lastStatus, lastError, authenticationRejected);
    } else if (id == L"openai") {
        std::wstring extra = L"Accept: application/json\r\n";
        if (!auth.accountId.empty()) extra += L"ChatGPT-Account-Id: " + wide(auth.accountId) + L"\r\n";
        auto response = httpsGet(L"chatgpt.com", L"/backend-api/wham/usage", auth.token, extra);
        gotData = mergeHttpUsage(snapshot, response, parseCodexUsage(response.body), now, threshold, barFull, lastStatus, lastError, authenticationRejected);
    } else if (id == L"moonshot") {
        auto coding = httpsGet(L"api.kimi.com", L"/coding/v1/usages", auth.token, kimiUsageHeaders());
        gotData = mergeHttpUsage(snapshot, coding, parseKimiCodingUsage(coding.body), now, threshold, barFull, lastStatus, lastError, authenticationRejected);
        auto balance = httpsGet(L"api.moonshot.ai", L"/v1/users/me/balance", auth.token);
        if (mergeHttpUsage(snapshot, balance, parseMoonshotBalance(balance.body) ? ProviderUsage{std::nullopt, std::nullopt, parseMoonshotBalance(balance.body)} : std::optional<ProviderUsage>{},
                           now, threshold, barFull, lastStatus, lastError, authenticationRejected)) {
            gotData = true;
        } else if (!gotData) {
            lastStatus = balance.status ? balance.status : lastStatus;
            lastError = balance.error.empty() ? lastError : balance.error;
        }
    } else if (id == L"deepseek") {
        // DeepSeek publishes an API key, not an OAuth refresh token.
        auto response = httpsGet(L"api.deepseek.com", L"/user/balance", auth.token);
        const auto parsed = parseDeepSeekBalance(response.body);
        gotData = mergeHttpUsage(snapshot, response, parsed ? ProviderUsage{std::nullopt, std::nullopt, parsed} : std::optional<ProviderUsage>{},
                                 now, threshold, barFull, lastStatus, lastError, authenticationRejected);
    } else if (id == L"xai") {
        auto billing = httpsGet(L"cli-chat-proxy.grok.com", L"/v1/billing?format=credits", auth.token,
                                L"X-XAI-Token-Auth: xai-grok-cli\r\nAccept: application/json\r\n");
        gotData = mergeHttpUsage(snapshot, billing, parseGrokBilling(billing.body), now, threshold, barFull, lastStatus, lastError, authenticationRejected);
        const std::wstring team = wide(auth.teamId.empty() ? "default" : auth.teamId);
        auto prepaid = httpsGet(L"management-api.x.ai", L"/v1/billing/teams/" + team + L"/prepaid/balance", auth.token);
        if (mergeHttpUsage(snapshot, prepaid, parseXaiPrepaidBalance(prepaid.body) ? ProviderUsage{std::nullopt, std::nullopt, parseXaiPrepaidBalance(prepaid.body)} : std::optional<ProviderUsage>{},
                           now, threshold, barFull, lastStatus, lastError, authenticationRejected)) {
            gotData = true;
        }
    } else if (id == L"antigravity") {
        const std::string body = R"({"metadata":{"ideType":"ANTIGRAVITY","platform":"PLATFORM_UNSPECIFIED","pluginType":"GEMINI"}})";
        const std::wstring headers = L"User-Agent: antigravity/1.107.0\r\nContent-Type: application/json\r\n";
        std::wstring host = L"daily-cloudcode-pa.googleapis.com";
        auto assist = httpsRequest({host, L"/v1internal:loadCodeAssist", L"POST", auth.token, headers, body});
        if (assist.status != 200 || !jsonString(assist.body, "cloudaicompanionProject")) {
            host = L"cloudcode-pa.googleapis.com";
            auto prod = httpsRequest({host, L"/v1internal:loadCodeAssist", L"POST", auth.token, headers, body});
            if (prod.status == 200) assist = std::move(prod);
        }
        gotData = mergeHttpUsage(snapshot, assist, parseAntigravityAssist(assist.body), now, threshold, barFull, lastStatus, lastError, authenticationRejected);
        std::string project = jsonString(assist.body, "cloudaicompanionProject").value_or({});
        if (!project.empty()) {
            const std::string modelsBody = std::format("{{\"project\":\"{}\"}}", jsonEscape(project));
            auto models = httpsRequest({host, L"/v1internal:fetchAvailableModels", L"POST", auth.token, headers, modelsBody});
            if (mergeHttpUsage(snapshot, models, parseAntigravityModels(models.body), now, threshold, barFull, lastStatus, lastError, authenticationRejected)) gotData = true;
        }
    }
}

void fetchProviderUsage(std::wstring_view credentialId, AuthMaterial& auth, ProviderSnapshot& snapshot,
                        TimePoint now, std::optional<double> threshold, double barFull) {
    const auto slotMarker = credentialId.find(L"/account-");
    const std::wstring providerStorage = slotMarker == std::wstring_view::npos
        ? std::wstring(credentialId) : std::wstring(credentialId.substr(0, slotMarker));
    const std::wstring_view id = providerStorage;
    bool refreshed = false;
    if (accessTokenNeedsRefresh(auth) && slotMarker == std::wstring_view::npos && adoptNewerCliToken(id, auth)) {
        // The CLI already holds a fresh token; no refresh needed.
    } else if (accessTokenNeedsRefresh(auth)) {
        refreshed = refreshOAuth(credentialId, auth);
    }
    DWORD lastStatus = 0;
    std::string lastError;
    bool gotData = false;
    bool authenticationRejected = false;
    queryProviderUsage(id, auth, snapshot, now, threshold, barFull, lastStatus, lastError, gotData, authenticationRejected);
    if (authenticationRejected && !refreshed && slotMarker == std::wstring_view::npos && adoptNewerCliToken(id, auth)) {
        for (auto& metric : snapshot.metrics) {
            if (metricFetchable(id, metric.kind) && metric.state != MetricState::Current) metric.state = MetricState::Refreshing;
        }
        queryProviderUsage(id, auth, snapshot, now, threshold, barFull, lastStatus, lastError, gotData, authenticationRejected);
    }
    if (authenticationRejected && !refreshed && refreshOAuth(credentialId, auth)) {
        for (auto& metric : snapshot.metrics) {
            if (metricFetchable(id, metric.kind) && metric.state != MetricState::Current) metric.state = MetricState::Refreshing;
        }
        queryProviderUsage(id, auth, snapshot, now, threshold, barFull, lastStatus, lastError, gotData, authenticationRejected);
    }
    if (authenticationRejected && slotMarker == std::wstring_view::npos && !managedAccounts(id)) {
        // The CLI file and the stored copy can diverge; one may hold a token the provider has since invalidated.
        // Try the other source before declaring the login rejected.
        std::vector<AuthMaterial> alternates;
        alternates.push_back(loadStoredAuth(id));
        if (allowOfficialCli(id)) alternates.push_back(loadCliAuth(id));
        for (auto& alt : alternates) {
            const bool differs = alt.token != auth.token || alt.refreshToken != auth.refreshToken;
            if (!differs || (alt.token.empty() && alt.refreshToken.empty())) continue;
            if (alt.token.empty() || accessTokenNeedsRefresh(alt)) continue; // never rotate a refresh token speculatively
            for (auto& metric : snapshot.metrics) {
                if (metricFetchable(id, metric.kind) && metric.state != MetricState::Current) metric.state = MetricState::Refreshing;
            }
            queryProviderUsage(id, alt, snapshot, now, threshold, barFull, lastStatus, lastError, gotData, authenticationRejected);
            if (!authenticationRejected) {
                saveAuth(credentialId, alt);
                auth = alt;
            }
            SecureZeroMemory(alt.token.data(), alt.token.size());
            SecureZeroMemory(alt.refreshToken.data(), alt.refreshToken.size());
            if (!authenticationRejected) break;
        }
    }
    finishRefresh(snapshot, gotData, authenticationRejected, lastStatus, lastError);
}

std::wstring kindName(MetricKind kind) {
    return wide(metricKindName(kind));
}

std::wstring stateName(MetricState state) {
    return wide(metricStateName(state));
}

std::wstring formatTime(const std::optional<TimePoint>& value) {
    if (!value) return L"Unknown";
    const std::time_t raw = std::chrono::system_clock::to_time_t(*value);
    std::tm local{};
    localtime_s(&local, &raw);
    wchar_t output[80]{};
    wcsftime(output, std::size(output), L"%x %X", &local);
    return output;
}

COLORREF lerpColor(COLORREF from, COLORREF to, double activity) {
    activity = std::clamp(activity, 0.0, 1.0);
    auto channel = [&](int shift) {
        const int start = (from >> shift) & 0xFF;
        const int end = (to >> shift) & 0xFF;
        return static_cast<int>(std::lround(start + (end - start) * activity));
    };
    return RGB(channel(0), channel(8), channel(16));
}

COLORREF remainingColor(double remaining, double activity = 0.0) {
    const auto color = applyUsageActivity(statusColor(remaining), activity);
    return RGB(color.red, color.green, color.blue);
}

std::wstring tooltipText(const Provider& provider, const Metric& metric, DWORD slot) {
    std::wstring text = provider.definition.name + L" — Account " + std::to_wstring(slot + 1) + L" — " + kindName(metric.kind) + L"\r\n";
    if (metric.used && metric.capacity) {
        text += std::format(L"{:.0f} / {:.0f} {} used\r\n", *metric.used, *metric.capacity, wide(metric.unit));
    }
    if (const auto fraction = metric.remainingFraction()) {
        text += std::format(L"{:.0f}% remaining\r\n", *fraction * 100.0);
    } else if (metric.remaining) {
        text += std::format(L"{}{:.2f} remaining\r\n", wide(metric.currency), *metric.remaining);
    }
    if (metric.resetAt) text += L"Resets: " + formatTime(metric.resetAt) + L"\r\n";
    if (provider.snapshot.lastSuccessfulRefresh) text += L"Last refreshed: " + formatTime(provider.snapshot.lastSuccessfulRefresh) + L"\r\n";
    text += L"Status: " + stateName(metric.state);
    if (!metric.diagnostic.empty()) text += L"\r\n" + wide(metric.diagnostic);
    if (metric.state == MetricState::AuthenticationRequired) text += L"\r\nClick to reconnect.";
    return text;
}

class App {
public:
    bool initialize(HINSTANCE instance);
    int run();
    void showOptionsWindow() { showOptions(); }
    void notifyNetworkChanged() { if (trayWindow_) PostMessageW(trayWindow_, kNetworkChangedMessage, 0, 0); }

private:
    static LRESULT CALLBACK floatingProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK optionsProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK trayProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT onFloating(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT onOptions(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT onTray(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

    void createProviders();
    void seedMonitorAccounts(Provider& provider);
    void createOptionsControls();
    void discoverAndBuildWslControls(bool forceDiscover);
    void syncWslControlVisibility();
    void layoutOptions(int width, int height);
    void updateAll();
    void updateOptions();
    void paintFloating();
    void layoutMonitor();
    void renderMonitorBitmap();
    void destroyMonitorBitmap();
    void syncFloatingWindowSize();
    void applyLowSystemPriorities();
    static void applyWorkerPriorities();
    [[nodiscard]] double monitorScale() const;
    [[nodiscard]] POINT toLogical(POINT client) const;
    enum class ResizeEdge { None, Right, Bottom, Corner };
    [[nodiscard]] ResizeEdge resizeEdgeAt(POINT client) const;
    void refresh(bool queueIfBusy = false);
    void scheduleNextPoll(bool failed);
    void connectProvider();
    void addAccount();
    void showAccountMenu(std::size_t index, POINT screen);
    bool selectAccount(std::size_t index, DWORD slot, bool interactive = true);
    bool rotateAccounts();
    void reloadCliConnections();
    bool attemptAutoReauth(std::size_t index);
    void queueAutoReauth();
    void processAutoReauth();
    void showOptions(std::optional<std::size_t> provider = std::nullopt);
    void toggleMonitor();
    void showTrayMenu();
    void installTrayIcon();
    void updateTrayIcon();
    HICON createGaugeIcon(std::optional<double> remaining);
    void activateTooltip(POINT clientPoint);
    void playWarning();
    void playReset();
    void playTone(bool reset);
    void startRowFlash(const std::string& providerId);
    void tickRowFlashes();
    void persistGoogleClientSecretField();
    void syncGoogleSecretControls();
    [[nodiscard]] HWND dialogParent() const;
    [[nodiscard]] const MetricHit* hitAt(POINT client) const;
    [[nodiscard]] const ProviderSnapshot& hitSnapshotFor(const MetricHit& hit) const;
    [[nodiscard]] bool authenticationFailedAt(POINT client) const;
    void handleMonitorClick(POINT client);

    HINSTANCE instance_{};
    HWND trayWindow_{};
    HWND floatingWindow_{};
    HWND optionsWindow_{};
    HWND tooltip_{};
    HWND tab_{};
    HWND status_{};
    HWND login_{};
    HWND addAccount_{};
    HWND accounts_{};
    HWND rotateAccounts_{};
    HWND enabled_{};
    HWND refresh_{};
    HWND interval_{};
    HWND intervalLabel_{};
    HWND sounds_{};
    HWND volume_{};
    HWND volumeLabel_{};
    HWND alwaysOnTop_{};
    HWND launchAtLogin_{};
    HWND syncCliTokens_{};
    HWND syncWslTokens_{};
    HWND wslUsersLabel_{};
    HWND wslEmpty_{};
    std::vector<HWND> wslUserChecks_{};
    HWND previewWarning_{};
    HWND previewReset_{};
    HWND threshold_{};
    HWND thresholdLabel_{};
    HWND creditBarFull_{};
    HWND creditBarFullLabel_{};
    HWND disconnect_{};
    HWND googleSecretLabel_{};
    HWND googleSecret_{};
    HWND close_{};
    HFONT font_{};
    HICON trayIcon_{};
    HBRUSH darkBrush_{};
    HBRUSH editBrush_{};
    HANDLE networkNotification_{};
    UINT taskbarCreatedMessage_{};
    std::vector<Provider> providers_;
    std::vector<MetricHit> hits_;
    std::wstring activeTooltip_;
    std::size_t selectedProvider_{0};
    bool dragging_{false};
    bool resizing_{false};
    POINT dragStart_{};
    POINT windowStart_{};
    POINT resizeCursorStart_{};
    int resizeStartWidth_{};
    ResizeEdge resizeEdge_{ResizeEdge::None};
    HBITMAP monitorBitmap_{};
    void* monitorBits_{};
    int monitorBmpW_{};
    int monitorBmpH_{};
    int logicalWidth_{kMonitorDefaultWidth};
    int logicalHeight_{48};
    AlertEngine alerts_;
    std::vector<ULONGLONG> rowFlashUntil_;
    std::vector<unsigned char> soundBuffer_;
    std::jthread refreshThread_;
    std::atomic_bool refreshing_{false};
    bool refreshQueued_{false};
    ULONGLONG lastRefreshTick_{0};
    unsigned int failureStreak_{0};
    std::vector<char> autoReauthTried_;
    std::vector<std::size_t> autoReauthQueue_;
    bool autoReauthBusy_{false};
    bool signInInProgress_{false};
};

VOID CALLBACK networkChangedCallback(PVOID context, PMIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE) {
    static_cast<App*>(context)->notifyNetworkChanged();
}

App* appFrom(HWND hwnd) {
    return reinterpret_cast<App*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

bool ownStyleVisible(HWND hwnd) {
    return hwnd && (GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_VISIBLE);
}

LRESULT CALLBACK App::floatingProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
    }
    if (auto* self = appFrom(hwnd)) return self->onFloating(hwnd, message, wParam, lParam);
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK App::optionsProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
    }
    if (auto* self = appFrom(hwnd)) return self->onOptions(hwnd, message, wParam, lParam);
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK App::trayProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
    }
    if (auto* self = appFrom(hwnd)) return self->onTray(hwnd, message, wParam, lParam);
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

std::wstring accountSettingFor(std::wstring_view id, DWORD slot) {
    return L"Provider." + std::wstring(id) + (slot ? L".Account." + std::to_wstring(slot) : L"");
}

std::vector<DWORD> listAccountSlots(std::wstring_view id) {
    std::vector<DWORD> slots;
    if (managedAccounts(id)) {
        const DWORD count = std::min<DWORD>(readDword((L"Provider." + std::wstring(id) + L".AccountCount").c_str(), 1), 100);
        for (DWORD slot = 0; slot < count; ++slot) {
            auto auth = loadStoredAuth(accountKey(id, slot));
            const bool exists = !auth.token.empty() || !auth.refreshToken.empty();
            SecureZeroMemory(auth.token.data(), auth.token.size());
            SecureZeroMemory(auth.refreshToken.data(), auth.refreshToken.size());
            if (exists) slots.push_back(slot);
        }
    }
    if (slots.empty()) slots.push_back(activeAccount(id));
    return slots;
}

void restoreAccountSnapshot(ProviderSnapshot& snapshot, std::wstring_view id, DWORD slot) {
    const std::wstring base = accountSettingFor(id, slot);
    bool restored = false;
    for (auto& metric : snapshot.metrics) {
        const std::wstring prefix = base + L"." + std::to_wstring(static_cast<int>(metric.kind));
        const auto used = readQword((prefix + L".UsedMicros").c_str());
        const auto capacity = readQword((prefix + L".CapacityMicros").c_str());
        const auto remaining = readQword((prefix + L".RemainingMicros").c_str());
        const auto observed = readQword((prefix + L".ObservedUnix").c_str());
        const auto reset = readQword((prefix + L".ResetUnix").c_str());
        if (!observed || (!used && !capacity && !remaining)) continue;
        metric.state = MetricState::Stale;
        if (used) metric.used = *used / 1000000.0;
        if (capacity) metric.capacity = *capacity / 1000000.0;
        if (remaining) metric.remaining = *remaining / 1000000.0;
        metric.observedAt = TimePoint{std::chrono::seconds{*observed}};
        if (reset) metric.resetAt = TimePoint{std::chrono::seconds{*reset}};
        if (const auto drawdown = readQword((prefix + L".DrawdownUnix").c_str())) {
            metric.lastDrawdownAt = TimePoint{std::chrono::seconds{*drawdown}};
        }
        metric.currency = readDword((prefix + L".Currency").c_str(), 1) == 2 ? "CNY " : "$";
        metric.unit = metric.kind == MetricKind::ApiCredit ? metric.currency : "%";
        metric.diagnostic = "Showing the last successful value while a refresh is pending.";
        restored = true;
    }
    if (restored) {
        const auto first = std::ranges::find_if(snapshot.metrics, [](const Metric& metric) { return metric.observedAt.has_value(); });
        if (first != snapshot.metrics.end()) snapshot.lastSuccessfulRefresh = first->observedAt;
    }
}

void App::seedMonitorAccounts(Provider& provider) {
    const auto slots = listAccountSlots(provider.definition.id);
    const DWORD active = activeAccount(provider.definition.id);
    std::vector<MonitorAccount> rows;
    rows.reserve(slots.size());
    for (const DWORD slot : slots) {
        MonitorAccount row;
        row.slot = slot;
        if (slot == active) {
            row.snapshot = provider.snapshot;
        } else {
            row.snapshot = provider.snapshot;
            row.snapshot.id = utf8(accountKey(provider.definition.id, slot));
            for (std::size_t i = 0; i < row.snapshot.metrics.size() && i < provider.definition.capabilities.size(); ++i) {
                row.snapshot.metrics[i] = initialMetric(provider.definition.id, provider.definition.capabilities[i]);
            }
            restoreAccountSnapshot(row.snapshot, provider.definition.id, slot);
        }
        rows.push_back(std::move(row));
    }
    provider.monitorAccounts = std::move(rows);
}

std::vector<MonitorAccount> monitorRowsFor(const Provider& provider) {
    if (!provider.monitorAccounts.empty()) return provider.monitorAccounts;
    return {{activeAccount(provider.definition.id), provider.snapshot}};
}

std::wstring monitorRowLabel(const Provider& provider, const MonitorAccount& account, const ProviderSnapshot& snapshot) {
    std::wstring label = provider.definition.name;
    if (provider.monitorAccounts.size() > 1) label += L" " + std::to_wstring(account.slot + 1);
    if (providerAuthenticationFailed(snapshot)) label += L"  ·  Sign in";
    return label;
}

void App::createProviders() {
    std::vector<ProviderDefinition> definitions = {
        {L"anthropic", L"Anthropic Claude", L"https://claude.ai/settings/usage",
         L"Connect with Claude Code's login or an OAuth access token. HypeLimits uses the same /api/oauth/usage endpoint as Claude Code /usage.",
         {MetricKind::Session, MetricKind::Weekly, MetricKind::ApiCredit}},
        {L"openai", L"OpenAI Codex", L"https://chatgpt.com/codex",
         L"Connect with the Codex CLI login or a ChatGPT access token. HypeLimits uses Codex's /backend-api/wham/usage endpoint.",
         {MetricKind::Session, MetricKind::Weekly, MetricKind::ApiCredit}},
        {L"moonshot", L"Moonshot Kimi", L"https://www.kimi.com/code",
         L"Connect with Kimi Code's subscription login (the same device-code flow as the official CLI, at kimi.ai / kimi.com) or paste a Kimi Code / Moonshot API key. Session and weekly usage come from /coding/v1/usages; a platform key fetches prepaid API credit.",
         {MetricKind::Session, MetricKind::Weekly, MetricKind::ApiCredit}},
        {L"deepseek", L"DeepSeek", L"https://platform.deepseek.com/",
         L"A DeepSeek API key fetches prepaid balance from /user/balance. DeepSeek does not publish session or weekly allowances.",
         {MetricKind::ApiCredit}},
        {L"xai", L"xAI Grok", L"https://console.x.ai/",
         L"A Grok CLI login fetches SuperGrok usage from cli-chat-proxy billing. A Management API key fetches prepaid API credit.",
         {MetricKind::Session, MetricKind::Weekly, MetricKind::ApiCredit}},
        {L"antigravity", L"Google Antigravity", L"https://antigravity.google/",
         L"Connect with the Antigravity or Gemini CLI Google login. Paste the Google OAuth client secret on this tab before in-app Google sign-in; it is stored in Windows Credential Manager. HypeLimits uses Cloud Code Assist loadCodeAssist and fetchAvailableModels.",
         {MetricKind::Session, MetricKind::Weekly, MetricKind::ApiCredit}},
    };
    for (auto& definition : definitions) {
        Provider provider;
        provider.definition = std::move(definition);
        provider.snapshot.id = utf8(activeAccount(provider.definition.id) ? accountKey(provider.definition.id, activeAccount(provider.definition.id)) : provider.definition.id);
        provider.snapshot.displayName = utf8(provider.definition.name);
        provider.snapshot.enabled = readDword((L"Provider." + provider.definition.id + L".Enabled").c_str(), 1) != 0;
        provider.connected = hasAuth(provider.definition.id);
        for (const auto capability : provider.definition.capabilities) provider.snapshot.metrics.push_back(initialMetric(provider.definition.id, capability));
        for (auto& metric : provider.snapshot.metrics) {
            if (metric.kind != MetricKind::ApiCredit) continue;
            metric.lowBalanceThreshold = readDword((L"Provider." + provider.definition.id + L".ThresholdCents").c_str(), 1000) / 100.0;
            metric.barFullAmount = readDword((L"Provider." + provider.definition.id + L".CreditBarFullCents").c_str(), 10000) / 100.0;
        }
        if (provider.connected) {
            bool restored = false;
            for (auto& metric : provider.snapshot.metrics) {
                const std::wstring prefix = accountSetting(provider.definition.id) + L"." + std::to_wstring(static_cast<int>(metric.kind));
                const auto used = readQword((prefix + L".UsedMicros").c_str());
                const auto capacity = readQword((prefix + L".CapacityMicros").c_str());
                const auto remaining = readQword((prefix + L".RemainingMicros").c_str());
                const auto observed = readQword((prefix + L".ObservedUnix").c_str());
                const auto reset = readQword((prefix + L".ResetUnix").c_str());
                if (!observed || (!used && !capacity && !remaining)) {
                    if (metricFetchable(provider.definition.id, metric.kind)) metric.state = MetricState::Refreshing;
                    continue;
                }
                metric.state = MetricState::Stale;
                if (used) metric.used = *used / 1000000.0;
                if (capacity) metric.capacity = *capacity / 1000000.0;
                if (remaining) metric.remaining = *remaining / 1000000.0;
                metric.observedAt = TimePoint{std::chrono::seconds{*observed}};
                if (reset) metric.resetAt = TimePoint{std::chrono::seconds{*reset}};
                if (const auto drawdown = readQword((prefix + L".DrawdownUnix").c_str())) {
                    metric.lastDrawdownAt = TimePoint{std::chrono::seconds{*drawdown}};
                }
                metric.currency = readDword((prefix + L".Currency").c_str(), 1) == 2 ? "CNY " : "$";
                metric.unit = metric.kind == MetricKind::ApiCredit ? metric.currency : "%";
                if (metric.kind == MetricKind::ApiCredit) {
                    metric.lowBalanceThreshold = readDword((L"Provider." + provider.definition.id + L".ThresholdCents").c_str(), 1000) / 100.0;
                    metric.barFullAmount = readDword((L"Provider." + provider.definition.id + L".CreditBarFullCents").c_str(), 10000) / 100.0;
                }
                metric.diagnostic = "Showing the last successful value while a refresh is pending.";
                restored = true;
            }
            if (restored) {
                const auto first = std::ranges::find_if(provider.snapshot.metrics, [](const Metric& metric) { return metric.observedAt.has_value(); });
                if (first != provider.snapshot.metrics.end()) provider.snapshot.lastSuccessfulRefresh = first->observedAt;
            }
        }
        for (const auto& metric : provider.snapshot.metrics) {
            const std::wstring warningName = L"Alert." + wide(provider.snapshot.id) + L"." + std::to_wstring(static_cast<int>(metric.kind)) + L".Warned";
            if (readDword(warningName.c_str(), 0)) alerts_.restoreWarning(provider.snapshot.id, metric.kind, metric.resetAt.value_or(TimePoint{}));
        }
        seedMonitorAccounts(provider);
        providers_.push_back(std::move(provider));
    }
    autoReauthTried_.assign(providers_.size(), 0);
}

bool App::initialize(HINSTANCE instance) {
    instance_ = instance;
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    applyLowSystemPriorities();
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES | ICC_TAB_CLASSES | ICC_BAR_CLASSES};
    InitCommonControlsEx(&controls);
    createProviders();
    darkBrush_ = CreateSolidBrush(RGB(31, 33, 39));
    editBrush_ = CreateSolidBrush(RGB(45, 48, 56));

    const WNDCLASSEXW floatingClass{sizeof(WNDCLASSEXW), CS_DBLCLKS, floatingProc, 0, 0, instance_, nullptr,
        LoadCursorW(nullptr, IDC_ARROW), nullptr, nullptr, L"HypeLimitsFloating", nullptr};
    const WNDCLASSEXW optionsClass{sizeof(WNDCLASSEXW), CS_DBLCLKS, optionsProc, 0, 0, instance_, nullptr,
        LoadCursorW(nullptr, IDC_ARROW), darkBrush_, nullptr, L"HypeLimitsOptions", nullptr};
    const WNDCLASSEXW trayClass{sizeof(WNDCLASSEXW), 0, trayProc, 0, 0, instance_, nullptr,
        nullptr, nullptr, nullptr, L"HypeLimitsTray", nullptr};
    if (!RegisterClassExW(&floatingClass) || !RegisterClassExW(&optionsClass) || !RegisterClassExW(&trayClass)) return false;

    trayWindow_ = CreateWindowExW(0, trayClass.lpszClassName, kAppName, 0, 0, 0, 0, 0,
                                  HWND_MESSAGE, nullptr, instance_, this);
    taskbarCreatedMessage_ = RegisterWindowMessageW(L"TaskbarCreated");
    NotifyIpInterfaceChange(AF_UNSPEC, networkChangedCallback, this, FALSE, &networkNotification_);
    const int x = static_cast<int>(readDword(L"MonitorX", 30));
    const int y = static_cast<int>(readDword(L"MonitorY", 30));
    const int width = std::max(static_cast<int>(readDword(L"MonitorWidth", kMonitorDefaultWidth)), kMonitorMinWindowWidth);
    floatingWindow_ = CreateWindowExW(WS_EX_TOOLWINDOW | (readDword(L"AlwaysOnTop", 1) ? WS_EX_TOPMOST : 0),
        floatingClass.lpszClassName, kAppName, WS_POPUP, x, y, width, 80, nullptr, nullptr, instance_, this);
    optionsWindow_ = CreateWindowExW(WS_EX_APPWINDOW, optionsClass.lpszClassName, L"HypeLimits Options",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 720, 820, nullptr, nullptr, instance_, this);
    if (!trayWindow_ || !floatingWindow_ || !optionsWindow_) return false;

    BOOL dark = TRUE;
    DwmSetWindowAttribute(optionsWindow_, 20, &dark, sizeof(dark));
    createOptionsControls();
    RECT optionsClient{};
    GetClientRect(optionsWindow_, &optionsClient);
    layoutOptions(optionsClient.right, optionsClient.bottom);
    installTrayIcon();

    if (!readDword(L"FirstRunComplete", 0)) {
        const int answer = MessageBoxW(optionsWindow_, L"Would you like HypeLimits to start automatically when you log in?\n\nYou can change this later in Options.",
                                       L"Start HypeLimits at login?", MB_ICONQUESTION | MB_YESNO);
        if (answer == IDYES && !setLaunchAtLogin(true)) {
            MessageBoxW(optionsWindow_, L"Windows rejected the launch-at-login change.", kAppName, MB_ICONWARNING);
        }
        writeDword(L"FirstRunComplete", 1);
    }
    syncLaunchAtLoginPath();
    if (!readDword(L"TokenSyncAsked", 0)) {
        const int answer = MessageBoxW(optionsWindow_,
            L"Keep the tokens in your terminal synced with HypeLimits?\n\n"
            L"If you choose Yes, HypeLimits will use the latest valid sign-in from either this app or the official CLI configs (Claude Code, Codex, Grok, Antigravity/Gemini, Kimi) and write that token to both, so you sign in less often.\n\n"
            L"You can change this later in Options. Secrets stay out of HypeLimits logs.",
            L"Sync terminal tokens with HypeLimits?", MB_ICONQUESTION | MB_YESNO);
        writeDword(L"TokenSyncEnabled", answer == IDYES ? 1 : 0);
        writeDword(L"TokenSyncAsked", 1);
        if (syncCliTokens_) Button_SetCheck(syncCliTokens_, answer == IDYES ? BST_CHECKED : BST_UNCHECKED);
    }
    syncAllProviderTokens();
    for (auto& provider : providers_) provider.connected = hasAuth(provider.definition.id);

    updateAll();
    scheduleNextPoll(false);
    refresh();

    RECT monitorRect{};
    GetWindowRect(floatingWindow_, &monitorRect);
    if (!MonitorFromRect(&monitorRect, MONITOR_DEFAULTTONULL)) SetWindowPos(floatingWindow_, nullptr, 30, 30, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    if (readDword(L"MonitorVisible", 1)) ShowWindow(floatingWindow_, SW_SHOWNOACTIVATE);
    return true;
}

int App::run() {
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}

void App::createOptionsControls() {
    font_ = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                        DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    auto make = [&](const wchar_t* cls, const wchar_t* text, DWORD style, int id) {
        HWND control = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10,
                                       optionsWindow_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance_, nullptr);
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
        SetWindowTheme(control, L"DarkMode_Explorer", nullptr);
        return control;
    };
    tab_ = make(WC_TABCONTROLW, L"", WS_TABSTOP | WS_CLIPSIBLINGS | TCS_OWNERDRAWFIXED | TCS_MULTILINE, IdTab);
    int widestTab = 72;
    {
        HDC dc = GetDC(tab_);
        const auto oldFont = SelectObject(dc, font_);
        for (std::size_t index = 0; index < providers_.size(); ++index) {
            TCITEMW item{TCIF_TEXT};
            item.pszText = providers_[index].definition.name.data();
            TabCtrl_InsertItem(tab_, static_cast<int>(index), &item);
            SIZE size{};
            GetTextExtentPoint32W(dc, providers_[index].definition.name.c_str(),
                                  static_cast<int>(providers_[index].definition.name.size()), &size);
            widestTab = std::max(widestTab, static_cast<int>(size.cx) + 20);
        }
        SelectObject(dc, oldFont);
        ReleaseDC(tab_, dc);
    }
    SendMessageW(tab_, TCM_SETMINTABWIDTH, 0, widestTab);
    status_ = make(L"EDIT", L"", WS_BORDER | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, IdStatus);
    login_ = make(L"BUTTON", L"Log in / Connect", BS_PUSHBUTTON | WS_TABSTOP, IdLogin);
    addAccount_ = make(L"BUTTON", L"Add account", BS_PUSHBUTTON | WS_TABSTOP, IdAddAccount);
    accounts_ = make(L"BUTTON", L"Choose account", BS_PUSHBUTTON | WS_TABSTOP, IdAccounts);
    rotateAccounts_ = make(L"BUTTON", L"Automatically rotate accounts when allowance runs out", BS_AUTOCHECKBOX | WS_TABSTOP, IdRotateAccounts);
    enabled_ = make(L"BUTTON", L"Show on the floating monitor and refresh this provider", BS_AUTOCHECKBOX | WS_TABSTOP, IdEnabled);
    refresh_ = make(L"BUTTON", L"Refresh provider status", BS_PUSHBUTTON | WS_TABSTOP, IdRefresh);
    disconnect_ = make(L"BUTTON", L"Disconnect", BS_PUSHBUTTON | WS_TABSTOP, IdDisconnect);
    intervalLabel_ = make(L"STATIC", L"Refresh interval (minutes)", SS_LEFT, 0);
    interval_ = make(L"EDIT", L"5", WS_BORDER | ES_NUMBER | WS_TABSTOP, IdInterval);
    sounds_ = make(L"BUTTON", L"Enable alert sounds", BS_AUTOCHECKBOX | WS_TABSTOP, IdSounds);
    volume_ = make(TRACKBAR_CLASSW, L"", TBS_AUTOTICKS | WS_TABSTOP, IdVolume);
    volumeLabel_ = make(L"STATIC", L"Alert volume", SS_LEFT, 0);
    SendMessageW(volume_, TBM_SETRANGE, TRUE, MAKELPARAM(0, 100));
    alwaysOnTop_ = make(L"BUTTON", L"Keep monitor above other windows", BS_AUTOCHECKBOX | WS_TABSTOP, IdAlwaysOnTop);
    launchAtLogin_ = make(L"BUTTON", L"Start HypeLimits when I log in", BS_AUTOCHECKBOX | WS_TABSTOP, IdLaunchAtLogin);
    syncCliTokens_ = make(L"BUTTON", L"Keep terminal CLI tokens synced with HypeLimits", BS_AUTOCHECKBOX | WS_TABSTOP, IdSyncCliTokens);
    syncWslTokens_ = make(L"BUTTON", L"Also use WSL CLI tokens", BS_AUTOCHECKBOX | WS_TABSTOP, IdSyncWslTokens);
    wslUsersLabel_ = make(L"STATIC", L"WSL users", SS_LEFT, 0);
    wslEmpty_ = make(L"STATIC", L"No WSL users found", SS_LEFT, 0);
    previewWarning_ = make(L"BUTTON", L"Preview warning", BS_PUSHBUTTON | WS_TABSTOP, IdPreviewWarning);
    previewReset_ = make(L"BUTTON", L"Preview reset", BS_PUSHBUTTON | WS_TABSTOP, IdPreviewReset);
    thresholdLabel_ = make(L"STATIC", L"API credit low-balance threshold ($)", SS_LEFT, 0);
    threshold_ = make(L"EDIT", L"10.00", WS_BORDER | WS_TABSTOP, IdThreshold);
    creditBarFullLabel_ = make(L"STATIC", L"API credit bar full ($)", SS_LEFT, 0);
    creditBarFull_ = make(L"EDIT", L"100.00", WS_BORDER | WS_TABSTOP, IdCreditBarFull);
    googleSecretLabel_ = make(L"STATIC", L"Google OAuth client secret", SS_LEFT, 0);
    googleSecret_ = make(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD | WS_TABSTOP, IdGoogleClientSecret);
    ShowWindow(googleSecretLabel_, SW_HIDE);
    ShowWindow(googleSecret_, SW_HIDE);
    close_ = make(L"BUTTON", L"Close", BS_DEFPUSHBUTTON | WS_TABSTOP, IdClose);
    SetWindowTextW(interval_, std::to_wstring(readDword(L"PollingMinutes", 5)).c_str());
    Button_SetCheck(sounds_, readDword(L"SoundsEnabled", 1) ? BST_CHECKED : BST_UNCHECKED);
    SendMessageW(volume_, TBM_SETPOS, TRUE, readDword(L"SoundVolume", 60));
    Button_SetCheck(alwaysOnTop_, readDword(L"AlwaysOnTop", 1) ? BST_CHECKED : BST_UNCHECKED);
    Button_SetCheck(launchAtLogin_, readDword(L"LaunchAtLogin", 0) ? BST_CHECKED : BST_UNCHECKED);
    Button_SetCheck(syncCliTokens_, readDword(L"TokenSyncEnabled", 0) ? BST_CHECKED : BST_UNCHECKED);
    Button_SetCheck(syncWslTokens_, readDword(L"WslTokenSyncEnabled", 0) ? BST_CHECKED : BST_UNCHECKED);
    discoverAndBuildWslControls(false);
}

void App::discoverAndBuildWslControls(bool forceDiscover) {
    if (forceDiscover || wslTokenSyncEnabled()) cachedWslHomes = discoverWslHomes();
    for (HWND hwnd : wslUserChecks_) {
        if (hwnd) DestroyWindow(hwnd);
    }
    wslUserChecks_.clear();
    for (std::size_t i = 0; i < cachedWslHomes.size(); ++i) {
        const auto& home = cachedWslHomes[i];
        const std::wstring label = L"Sync " + home.user + L" on " + home.distro;
        HWND check = CreateWindowExW(0, L"BUTTON", label.c_str(),
            WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP, 0, 0, 10, 10, optionsWindow_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(IdWslUserFirst + static_cast<int>(i))), instance_, nullptr);
        SendMessageW(check, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
        SetWindowTheme(check, L"DarkMode_Explorer", nullptr);
        Button_SetCheck(check, wslHomeSyncEnabled(home) ? BST_CHECKED : BST_UNCHECKED);
        wslUserChecks_.push_back(check);
    }
    syncWslControlVisibility();
}

void App::syncWslControlVisibility() {
    const bool enabled = syncWslTokens_ && Button_GetCheck(syncWslTokens_) == BST_CHECKED;
    ShowWindow(wslUsersLabel_, enabled ? SW_SHOW : SW_HIDE);
    ShowWindow(wslEmpty_, enabled && wslUserChecks_.empty() ? SW_SHOW : SW_HIDE);
    for (HWND hwnd : wslUserChecks_) ShowWindow(hwnd, enabled ? SW_SHOW : SW_HIDE);
}

void App::syncGoogleSecretControls() {
    const bool show = selectedProvider_ < providers_.size()
        && providers_[selectedProvider_].definition.id == L"antigravity";
    ShowWindow(googleSecretLabel_, show ? SW_SHOW : SW_HIDE);
    ShowWindow(googleSecret_, show ? SW_SHOW : SW_HIDE);
    if (!show) return;
    SetWindowTextW(googleSecretLabel_, googleClientSecretConfigured()
        ? L"Google OAuth client secret (saved — paste a new value to replace)"
        : L"Google OAuth client secret (required for Google sign-in and token refresh)");
}

void App::persistGoogleClientSecretField() {
    if (!googleSecret_) return;
    wchar_t value[512]{};
    GetWindowTextW(googleSecret_, value, static_cast<int>(std::size(value)));
    std::wstring text = value;
    SecureZeroMemory(value, sizeof(value));
    while (!text.empty() && iswspace(text.front())) text.erase(text.begin());
    while (!text.empty() && iswspace(text.back())) text.pop_back();
    if (text.empty()) return;
    if (!CredentialStore::save(kGoogleClientSecretId, text)) {
        SecureZeroMemory(text.data(), text.size() * sizeof(wchar_t));
        MessageBoxW(optionsWindow_, L"Windows Credential Manager rejected the Google OAuth client secret.", kAppName, MB_ICONERROR);
        return;
    }
    SecureZeroMemory(text.data(), text.size() * sizeof(wchar_t));
    SetWindowTextW(googleSecret_, L"");
    syncGoogleSecretControls();
}

void App::layoutOptions(int width, int height) {
    const int margin = 16;
    const int innerLeft = margin + 12;
    const int innerWidth = std::max(120, width - innerLeft - margin);
    auto tabHeight = [&] {
        return 10 + std::max(1, TabCtrl_GetRowCount(tab_)) * 28;
    };
    int tabH = tabHeight();
    MoveWindow(tab_, margin, margin, width - margin * 2, tabH, TRUE);
    tabH = tabHeight();
    MoveWindow(tab_, margin, margin, width - margin * 2, tabH, TRUE);
    int y = margin + tabH + 12;
    int extraBottom = 0;
    if (ownStyleVisible(syncWslTokens_)) extraBottom += 28;
    if (ownStyleVisible(wslUsersLabel_)) extraBottom += 22;
    if (ownStyleVisible(wslEmpty_)) extraBottom += 22;
    extraBottom += 24 * static_cast<int>(std::count_if(wslUserChecks_.begin(), wslUserChecks_.end(), ownStyleVisible));
    if (ownStyleVisible(creditBarFull_)) extraBottom += 34;
    if (ownStyleVisible(googleSecret_)) extraBottom += 56;
    const int statusH = std::max(90, height - y - 374 - extraBottom);
    MoveWindow(status_, innerLeft, y, innerWidth, statusH, TRUE);
    y += statusH + 10;

    int x = innerLeft;
    auto placeButton = [&](HWND hwnd, int buttonWidth, int buttonHeight) {
        if (!ownStyleVisible(hwnd)) return;
        if (x > innerLeft && x + buttonWidth > width - margin) {
            x = innerLeft;
            y += buttonHeight + 8;
        }
        MoveWindow(hwnd, x, y, buttonWidth, buttonHeight, TRUE);
        x += buttonWidth + 8;
    };
    placeButton(login_, 145, 32);
    placeButton(refresh_, 185, 32);
    placeButton(disconnect_, 105, 32);
    y += 40;

    x = innerLeft;
    placeButton(addAccount_, 130, 32);
    placeButton(accounts_, 150, 32);
    y += 40;
    MoveWindow(rotateAccounts_, innerLeft, y, innerWidth, 28, TRUE);
    y += 32;
    MoveWindow(enabled_, innerLeft, y, innerWidth, 28, TRUE);
    y += 32;
    if (ownStyleVisible(googleSecret_)) {
        MoveWindow(googleSecretLabel_, innerLeft, y, innerWidth, 22, TRUE);
        y += 24;
        MoveWindow(googleSecret_, innerLeft, y, innerWidth, 26, TRUE);
        y += 34;
    }
    if (ownStyleVisible(threshold_)) {
        const int fieldWidth = 88;
        MoveWindow(thresholdLabel_, innerLeft, y, std::max(80, innerWidth - fieldWidth - 8), 26, TRUE);
        MoveWindow(threshold_, innerLeft + innerWidth - fieldWidth, y, fieldWidth, 26, TRUE);
        y += 34;
    }
    if (ownStyleVisible(creditBarFull_)) {
        const int fieldWidth = 88;
        MoveWindow(creditBarFullLabel_, innerLeft, y, std::max(80, innerWidth - fieldWidth - 8), 26, TRUE);
        MoveWindow(creditBarFull_, innerLeft + innerWidth - fieldWidth, y, fieldWidth, 26, TRUE);
        y += 34;
    }
    MoveWindow(intervalLabel_, innerLeft, y, std::max(80, innerWidth - 80), 26, TRUE);
    MoveWindow(interval_, innerLeft + innerWidth - 72, y, 72, 26, TRUE);
    y += 34;
    MoveWindow(sounds_, innerLeft, y, innerWidth, 26, TRUE);
    y += 30;
    const int previewTotal = 115 + 8 + 108;
    MoveWindow(volumeLabel_, innerLeft, y, 110, 26, TRUE);
    MoveWindow(volume_, innerLeft + 115, y - 4, std::max(80, innerWidth - 115 - previewTotal - 8), 32, TRUE);
    MoveWindow(previewWarning_, width - margin - previewTotal, y - 2, 115, 30, TRUE);
    MoveWindow(previewReset_, width - margin - 108, y - 2, 108, 30, TRUE);
    y += 36;
    MoveWindow(alwaysOnTop_, innerLeft, y, innerWidth, 26, TRUE);
    y += 28;
    MoveWindow(launchAtLogin_, innerLeft, y, innerWidth, 26, TRUE);
    y += 28;
    MoveWindow(syncCliTokens_, innerLeft, y, innerWidth, 26, TRUE);
    y += 28;
    if (ownStyleVisible(syncWslTokens_)) {
        MoveWindow(syncWslTokens_, innerLeft, y, innerWidth, 26, TRUE);
        y += 28;
    }
    if (ownStyleVisible(wslUsersLabel_)) {
        MoveWindow(wslUsersLabel_, innerLeft, y, innerWidth, 22, TRUE);
        y += 22;
    }
    for (HWND hwnd : wslUserChecks_) {
        if (!ownStyleVisible(hwnd)) continue;
        MoveWindow(hwnd, innerLeft + 12, y, std::max(80, innerWidth - 12), 22, TRUE);
        y += 24;
    }
    if (ownStyleVisible(wslEmpty_)) {
        MoveWindow(wslEmpty_, innerLeft + 12, y, innerWidth - 12, 22, TRUE);
    }
    MoveWindow(close_, width - margin - 88, height - 46, 88, 30, TRUE);
}

void App::updateOptions() {
    if (selectedProvider_ >= providers_.size()) return;
    const auto& provider = providers_[selectedProvider_];
    const bool canEdit = !refreshing_ && !signInInProgress_ && !autoReauthBusy_;
    for (HWND control : {login_, addAccount_, accounts_, disconnect_}) EnableWindow(control, canEdit);
    Button_SetCheck(rotateAccounts_, readDword((L"Provider." + provider.definition.id + L".RotateAccounts").c_str(), 0) ? BST_CHECKED : BST_UNCHECKED);
    std::wstring text = L"Selected credential: Account " + std::to_wstring(activeAccount(provider.definition.id) + 1) + L"\r\n";
    for (const auto& metric : provider.snapshot.metrics) {
        text += kindName(metric.kind) + L": " + stateName(metric.state) + L"\r\n";
        if (metric.used) text += std::format(L"  Used: {:.0f} {}\r\n", *metric.used, wide(metric.unit));
        if (metric.capacity) text += std::format(L"  Capacity: {:.0f} {}\r\n", *metric.capacity, wide(metric.unit));
        if (metric.remaining) text += std::format(L"  Remaining: {}{:.2f}\r\n", wide(metric.currency), *metric.remaining);
        text += L"  Reset: " + formatTime(metric.resetAt) + L"\r\n";
        if (!metric.diagnostic.empty()) text += L"  " + wide(metric.diagnostic) + L"\r\n";
    }
    text += L"\r\n" + provider.definition.guidance + L"\r\nLast successful refresh: " + formatTime(provider.snapshot.lastSuccessfulRefresh);
    if (readDword((accountSetting(provider.definition.id) + L".SyncFailed").c_str(), 0))
        text += L"\r\nCredential sync failed. Select the account again to retry Windows/WSL sync.";
    if (!cliFormatForProvider(utf8(provider.definition.id)))
        text += L"\r\nThis provider has no supported local CLI credential file; account selection applies to HypeLimits.";
    SetWindowTextW(status_, text.c_str());
    Button_SetCheck(enabled_, provider.snapshot.enabled ? BST_CHECKED : BST_UNCHECKED);
    const std::wstring thresholdName = L"Provider." + provider.definition.id + L".ThresholdCents";
    SetWindowTextW(threshold_, std::format(L"{}.{:02}", readDword(thresholdName.c_str(), 1000) / 100,
                                           readDword(thresholdName.c_str(), 1000) % 100).c_str());
    const std::wstring barFullName = L"Provider." + provider.definition.id + L".CreditBarFullCents";
    SetWindowTextW(creditBarFull_, std::format(L"{}.{:02}", readDword(barFullName.c_str(), 10000) / 100,
                                               readDword(barFullName.c_str(), 10000) % 100).c_str());
    const bool hasCredit = std::ranges::any_of(provider.definition.capabilities,
                                               [](MetricKind kind) { return kind == MetricKind::ApiCredit; });
    ShowWindow(threshold_, hasCredit ? SW_SHOW : SW_HIDE);
    ShowWindow(thresholdLabel_, hasCredit ? SW_SHOW : SW_HIDE);
    ShowWindow(creditBarFull_, hasCredit ? SW_SHOW : SW_HIDE);
    ShowWindow(creditBarFullLabel_, hasCredit ? SW_SHOW : SW_HIDE);
    ShowWindow(disconnect_, provider.connected ? SW_SHOW : SW_HIDE);
    syncGoogleSecretControls();
    syncWslControlVisibility();
    RECT client{};
    GetClientRect(optionsWindow_, &client);
    layoutOptions(client.right, client.bottom);
}

void App::applyLowSystemPriorities() {
    SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
    SetProcessPriorityBoost(GetCurrentProcess(), TRUE);

    MEMORY_PRIORITY_INFORMATION memory{};
    memory.MemoryPriority = MEMORY_PRIORITY_LOW;
    SetProcessInformation(GetCurrentProcess(), ProcessMemoryPriority, &memory, sizeof(memory));

    PROCESS_POWER_THROTTLING_STATE power{};
    power.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
    power.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    power.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling, &power, sizeof(power));

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
}

void App::applyWorkerPriorities() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
    SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);

    THREAD_POWER_THROTTLING_STATE power{};
    power.Version = THREAD_POWER_THROTTLING_CURRENT_VERSION;
    power.ControlMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED;
    power.StateMask = THREAD_POWER_THROTTLING_EXECUTION_SPEED;
    SetThreadInformation(GetCurrentThread(), ThreadPowerThrottling, &power, sizeof(power));
}

double App::monitorScale() const {
    RECT client{};
    GetClientRect(floatingWindow_, &client);
    return static_cast<double>(std::max(1, static_cast<int>(client.right))) / static_cast<double>(std::max(1, logicalWidth_));
}

POINT App::toLogical(POINT client) const {
    const double scale = monitorScale();
    return {static_cast<int>(std::lround(client.x / scale)), static_cast<int>(std::lround(client.y / scale))};
}

App::ResizeEdge App::resizeEdgeAt(POINT client) const {
    RECT bounds{};
    GetClientRect(floatingWindow_, &bounds);
    const bool right = client.x >= bounds.right - kMonitorResizeEdge;
    const bool bottom = client.y >= bounds.bottom - kMonitorResizeEdge;
    if (right && bottom) return ResizeEdge::Corner;
    if (right) return ResizeEdge::Right;
    if (bottom) return ResizeEdge::Bottom;
    return ResizeEdge::None;
}

void App::destroyMonitorBitmap() {
    if (monitorBitmap_) {
        DeleteObject(monitorBitmap_);
        monitorBitmap_ = nullptr;
        monitorBits_ = nullptr;
        monitorBmpW_ = 0;
        monitorBmpH_ = 0;
    }
}

void App::layoutMonitor() {
    hits_.clear();
    HDC dc = GetDC(floatingWindow_);
    if (!dc) {
        logicalWidth_ = kMonitorLogicalMinWidth;
        logicalHeight_ = 48;
        return;
    }
    const auto oldFont = SelectObject(dc, font_);
    int maxText = 0;
    bool any = false;
    for (const auto& provider : providers_) {
        const auto rows = monitorRowsFor(provider);
        for (const auto& account : rows) {
            if (!monitorIncludesProvider(account.snapshot)) continue;
            any = true;
            const std::wstring label = monitorRowLabel(provider, account, account.snapshot);
            SIZE size{};
            GetTextExtentPoint32W(dc, label.c_str(), static_cast<int>(label.size()), &size);
            maxText = std::max(maxText, static_cast<int>(size.cx));
        }
    }

    constexpr wchar_t kEmpty[] = L"Configure an account in Options";
    SIZE emptySize{};
    GetTextExtentPoint32W(dc, kEmpty, static_cast<int>(wcslen(kEmpty)), &emptySize);
    if (!any) maxText = std::max(maxText, static_cast<int>(emptySize.cx));

    logicalWidth_ = std::max(kMonitorLogicalMinWidth, std::max(maxText + 20, 162));

    int y = 8;
    if (!any) {
        RECT wrap{10, 12, logicalWidth_ - 10, 12};
        DrawTextW(dc, kEmpty, -1, &wrap, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
        logicalHeight_ = std::max(48, static_cast<int>(wrap.bottom) + 12);
    } else {
        for (std::size_t providerIndex = 0; providerIndex < providers_.size(); ++providerIndex) {
            const auto& provider = providers_[providerIndex];
            const auto rows = monitorRowsFor(provider);
            for (const auto& account : rows) {
            if (!monitorIncludesProvider(account.snapshot)) continue;
            const int nameTop = y;
            std::optional<std::size_t> firstMetric;
            y += 20;
            const bool authFailed = providerAuthenticationFailed(account.snapshot);
            bool drewBar = false;
            for (std::size_t metricIndex = 0; metricIndex < account.snapshot.metrics.size(); ++metricIndex) {
                const auto& metric = account.snapshot.metrics[metricIndex];
                if (!metric.visibleOnMonitor() || !metric.remainingFraction()) continue;
                if (!firstMetric) firstMetric = metricIndex;
                hits_.push_back({RECT{8, y - 5, logicalWidth_ - 8, y + 11}, providerIndex, metricIndex, account.slot});
                y += 13;
                drewBar = true;
            }
            if (authFailed && !drewBar) {
                for (std::size_t metricIndex = 0; metricIndex < account.snapshot.metrics.size(); ++metricIndex) {
                    if (!account.snapshot.metrics[metricIndex].visibleOnMonitor()) continue;
                    firstMetric = metricIndex;
                    hits_.push_back({RECT{8, y - 2, logicalWidth_ - 8, y + 16}, providerIndex, metricIndex, account.slot});
                    y += 16;
                    break;
                }
            }
            y += 6;
            if (firstMetric) hits_.push_back({RECT{0, nameTop, logicalWidth_, y}, providerIndex, *firstMetric, account.slot});
            }
        }
        logicalHeight_ = std::max(48, y + 3);
    }
    SelectObject(dc, oldFont);
    ReleaseDC(floatingWindow_, dc);
}

void App::syncFloatingWindowSize() {
    layoutMonitor();
    RECT window{};
    GetWindowRect(floatingWindow_, &window);
    RECT client{};
    GetClientRect(floatingWindow_, &client);
    int width = client.right - client.left;
    if (width <= 0) width = window.right - window.left;
    width = std::max(width, kMonitorMinWindowWidth);
    const int height = std::max(1, static_cast<int>(std::lround(
        static_cast<double>(logicalHeight_) * static_cast<double>(width) / static_cast<double>(logicalWidth_))));
    if (window.right - window.left != width || window.bottom - window.top != height) {
        SetWindowPos(floatingWindow_, nullptr, 0, 0, width, height, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
    const int corner = std::max(4, static_cast<int>(std::lround(kMonitorCorner * monitorScale())));
    SetWindowRgn(floatingWindow_, CreateRoundRectRgn(0, 0, width, height, corner, corner), TRUE);
}

void App::renderMonitorBitmap() {
    layoutMonitor();
    destroyMonitorBitmap();

    RECT client{};
    GetClientRect(floatingWindow_, &client);
    const int renderScale = std::max(2, (std::max(1, static_cast<int>(client.right)) + logicalWidth_ - 1) / logicalWidth_);
    const int bmpW = logicalWidth_ * renderScale;
    const int bmpH = logicalHeight_ * renderScale;

    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = bmpW;
    info.bmiHeader.biHeight = -bmpH;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;

    HDC windowDc = GetDC(floatingWindow_);
    monitorBitmap_ = CreateDIBSection(windowDc, &info, DIB_RGB_COLORS, &monitorBits_, nullptr, 0);
    HDC mem = CreateCompatibleDC(windowDc);
    const auto oldBmp = SelectObject(mem, monitorBitmap_);
    HFONT drawFont = CreateFontW(-kMonitorFontPx * renderScale, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                 DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    const auto oldFont = SelectObject(mem, drawFont);

    RECT full{0, 0, bmpW, bmpH};
    HBRUSH background = CreateSolidBrush(RGB(31, 33, 39));
    FillRect(mem, &full, background);
    DeleteObject(background);
    SetBkMode(mem, TRANSPARENT);
    SetTextColor(mem, RGB(232, 233, 236));

    const int s = renderScale;
    auto scaled = [s](RECT rect) {
        return RECT{rect.left * s, rect.top * s, rect.right * s, rect.bottom * s};
    };

    int y = 8;
    bool any = false;
    const ULONGLONG nowTick = GetTickCount64();
    for (std::size_t providerIndex = 0; providerIndex < providers_.size(); ++providerIndex) {
        const auto& provider = providers_[providerIndex];
        const auto rows = monitorRowsFor(provider);
        const bool flashing = providerIndex < rowFlashUntil_.size() && rowFlashUntil_[providerIndex] > nowTick;
        for (const auto& account : rows) {
        if (!monitorIncludesProvider(account.snapshot)) continue;
        any = true;
        const bool authFailed = !flashing && providerAuthenticationFailed(account.snapshot);
        const auto now = std::chrono::system_clock::now();
        double activity = 0.0;
        for (const auto& metric : account.snapshot.metrics) {
            if (!metric.visibleOnMonitor()) continue;
            activity = std::max(activity, usageActivityBrightness(metric.lastDrawdownAt, now));
        }
        int rowBottom = y + 20;
        int visibleBars = 0;
        for (const auto& metric : account.snapshot.metrics) {
            if (metric.visibleOnMonitor() && metric.remainingFraction()) ++visibleBars;
        }
        rowBottom += visibleBars > 0 ? visibleBars * 13 : (authFailed ? 16 : 0);
        rowBottom += 6;
        if (flashing) {
            RECT row = scaled({0, y - 1, logicalWidth_, rowBottom - 1});
            HBRUSH tint = CreateSolidBrush(kResetRowBackground);
            FillRect(mem, &row, tint);
            DeleteObject(tint);
            SetTextColor(mem, kResetRowText);
        } else if (authFailed) {
            RECT row = scaled({0, y - 1, logicalWidth_, rowBottom - 1});
            HBRUSH tint = CreateSolidBrush(kAuthRowBackground);
            FillRect(mem, &row, tint);
            DeleteObject(tint);
            SetTextColor(mem, kAuthRowText);
        } else {
            SetTextColor(mem, lerpColor(RGB(148, 152, 160), RGB(248, 250, 252), activity));
        }
        const std::wstring rowLabel = monitorRowLabel(provider, account, account.snapshot);
        RECT nameRect = scaled({10, y, logicalWidth_ - 10, y + 20});
        DrawTextW(mem, rowLabel.c_str(), -1, &nameRect, DT_SINGLELINE | DT_NOPREFIX | DT_NOCLIP);
        y += 20;
        bool drewBar = false;
        for (const auto& metric : account.snapshot.metrics) {
            if (!metric.visibleOnMonitor() || !metric.remainingFraction()) continue;
            drewBar = true;
            const wchar_t* label = metric.kind == MetricKind::Session ? L"S" : metric.kind == MetricKind::Weekly ? L"W" : L"$";
            RECT labelRect = scaled({12, y - 3, 28, y + 12});
            DrawTextW(mem, label, -1, &labelRect, DT_SINGLELINE | DT_NOPREFIX | DT_NOCLIP);
            RECT bar = scaled({30, y, logicalWidth_ - 12, y + 6});
            HBRUSH track = CreateSolidBrush(flashing ? kResetRowTrack : (authFailed ? kAuthRowTrack : lerpColor(RGB(46, 48, 56), RGB(78, 82, 94), activity)));
            FillRect(mem, &bar, track);
            DeleteObject(track);
            if (const auto fraction = metric.remainingFraction()) {
                RECT fill = bar;
                fill.right = fill.left + static_cast<LONG>((fill.right - fill.left) * *fraction);
                HBRUSH color = CreateSolidBrush(flashing ? kResetRowFill : (authFailed ? kAuthRowText : remainingColor(*fraction, activity)));
                FillRect(mem, &fill, color);
                DeleteObject(color);
            }
            y += 13;
        }
        if (authFailed && !drewBar) {
            RECT loginRect = scaled({12, y - 2, logicalWidth_ - 10, y + 16});
            DrawTextW(mem, L"Login required", -1, &loginRect, DT_SINGLELINE | DT_NOPREFIX | DT_NOCLIP);
            y += 16;
        }
        y += 6;
        }
    }
    if (!any) {
        RECT empty = scaled({10, 12, logicalWidth_ - 10, logicalHeight_ - 8});
        DrawTextW(mem, L"Configure an account in Options", -1, &empty, DT_WORDBREAK | DT_NOPREFIX | DT_NOCLIP);
    }
    bool fading = false;
    for (const auto& provider : providers_) {
        for (const auto& account : monitorRowsFor(provider)) {
            if (!monitorIncludesProvider(account.snapshot)) continue;
            for (const auto& metric : account.snapshot.metrics) {
                if (metric.visibleOnMonitor() && usageActivityBrightness(metric.lastDrawdownAt, std::chrono::system_clock::now()) > 0.0) fading = true;
            }
        }
    }
    if (fading) SetTimer(floatingWindow_, kActivityTimer, kActivityTimerMs, nullptr);
    else KillTimer(floatingWindow_, kActivityTimer);

    SelectObject(mem, oldFont);
    DeleteObject(drawFont);
    SelectObject(mem, oldBmp);
    DeleteDC(mem);
    ReleaseDC(floatingWindow_, windowDc);
    monitorBmpW_ = bmpW;
    monitorBmpH_ = bmpH;
}

void App::paintFloating() {
    PAINTSTRUCT paint{};
    HDC dc = BeginPaint(floatingWindow_, &paint);
    RECT client{};
    GetClientRect(floatingWindow_, &client);
    if (!monitorBitmap_) renderMonitorBitmap();
    if (monitorBitmap_ && client.right > 0 && client.bottom > 0) {
        HDC mem = CreateCompatibleDC(dc);
        const auto oldBmp = SelectObject(mem, monitorBitmap_);
        SetStretchBltMode(dc, HALFTONE);
        SetBrushOrgEx(dc, 0, 0, nullptr);
        StretchBlt(dc, 0, 0, client.right, client.bottom, mem, 0, 0, monitorBmpW_, monitorBmpH_, SRCCOPY);
        SelectObject(mem, oldBmp);
        DeleteDC(mem);
    }
    EndPaint(floatingWindow_, &paint);
}

void App::activateTooltip(POINT clientPoint) {
    const auto* found = hitAt(clientPoint);
    if (!found) {
        SendMessageW(tooltip_, TTM_TRACKACTIVATE, FALSE, 0);
        return;
    }
    const auto& hitSnapshot = hitSnapshotFor(*found);
    activeTooltip_ = tooltipText(providers_[found->provider], hitSnapshot.metrics[std::min(found->metric, hitSnapshot.metrics.size() - 1)], found->slot);
    TOOLINFOW info{sizeof(info)};
    info.hwnd = floatingWindow_;
    info.uId = 1;
    info.lpszText = activeTooltip_.data();
    SendMessageW(tooltip_, TTM_UPDATETIPTEXTW, 0, reinterpret_cast<LPARAM>(&info));
    POINT screen = clientPoint;
    ClientToScreen(floatingWindow_, &screen);
    SendMessageW(tooltip_, TTM_TRACKPOSITION, 0, MAKELPARAM(screen.x + 14, screen.y + 18));
    SendMessageW(tooltip_, TTM_TRACKACTIVATE, TRUE, reinterpret_cast<LPARAM>(&info));
}

struct RefreshResult {
    std::size_t index{};
    DWORD slot{};
    bool active{false};
    std::wstring credentialId;
    AuthMaterial auth;
    DWORD thresholdCents{};
    DWORD barFullCents{};
    ProviderSnapshot snapshot;
};

void App::refresh(bool queueIfBusy) {
    if (signInInProgress_) return;
    if (refreshing_.exchange(true)) {
        // A reconnect during an in-flight refresh would otherwise keep the old rejected-credential result on screen.
        if (queueIfBusy) refreshQueued_ = true;
        return;
    }
    lastRefreshTick_ = GetTickCount64();
    for (auto& provider : providers_) {
        if (!provider.snapshot.enabled || !provider.connected) continue;
        for (auto& metric : provider.snapshot.metrics) {
            if (metricFetchable(provider.definition.id, metric.kind)) metric.state = MetricState::Refreshing;
        }
        for (auto& account : provider.monitorAccounts) {
            for (auto& metric : account.snapshot.metrics) {
                if (metricFetchable(provider.definition.id, metric.kind)) metric.state = MetricState::Refreshing;
            }
        }
    }
    updateAll();

    std::vector<RefreshResult> requests;
    for (std::size_t index = 0; index < providers_.size(); ++index) {
        auto& provider = providers_[index];
        if (!provider.snapshot.enabled) continue;
        if (provider.monitorAccounts.empty()) seedMonitorAccounts(provider);
        const DWORD active = activeAccount(provider.definition.id);
        const std::wstring prefix = L"Provider." + provider.definition.id;
        const DWORD threshold = readDword((prefix + L".ThresholdCents").c_str(), 1000);
        const DWORD barFull = readDword((prefix + L".CreditBarFullCents").c_str(), 10000);
        for (auto& account : provider.monitorAccounts) {
            const bool isActive = account.slot == active;
            AuthMaterial auth = isActive ? loadAuth(provider.definition.id) : loadStoredAuth(accountKey(provider.definition.id, account.slot));
            if (auth.token.empty()) {
                for (auto& metric : account.snapshot.metrics) {
                    if (metricFetchable(provider.definition.id, metric.kind)) {
                        markAuthenticationFailed(metric, "The saved credential was rejected. Connect again from Options.");
                    }
                }
                if (isActive) provider.snapshot = account.snapshot;
                continue;
            }
            for (auto& metric : account.snapshot.metrics) {
                if (metricFetchable(provider.definition.id, metric.kind)) metric.state = MetricState::Refreshing;
            }
            if (isActive) provider.snapshot = account.snapshot;
            requests.push_back({index, account.slot, isActive,
                isActive ? provider.definition.id : accountKey(provider.definition.id, account.slot),
                std::move(auth), threshold, barFull, account.snapshot});
        }
    }
    refreshThread_ = std::jthread([this, requests = std::move(requests)]() mutable {
        applyWorkerPriorities();
        const auto now = std::chrono::system_clock::now();
        for (auto& request : requests) {
            fetchProviderUsage(request.credentialId, request.auth, request.snapshot, now, request.thresholdCents / 100.0,
                               request.barFullCents / 100.0);
            SecureZeroMemory(request.auth.token.data(), request.auth.token.size());
            SecureZeroMemory(request.auth.refreshToken.data(), request.auth.refreshToken.size());
        }
        auto* completed = new std::vector<RefreshResult>(std::move(requests));
        if (!PostMessageW(trayWindow_, kRefreshCompleteMessage, 0, reinterpret_cast<LPARAM>(completed))) delete completed;
    });
}

void App::scheduleNextPoll(bool failed) {
    failureStreak_ = failed ? std::min(failureStreak_ + 1, 5U) : 0U;
    const ULONGLONG base = static_cast<ULONGLONG>(std::clamp<DWORD>(readDword(L"PollingMinutes", 5), 1, 1440)) * 60000ULL;
    const ULONGLONG multiplier = 1ULL << failureStreak_;
    const ULONGLONG jitter = GetTickCount64() % 5001ULL;
    SetTimer(trayWindow_, kPollTimer, static_cast<UINT>(std::min<ULONGLONG>(base * multiplier + jitter, 0xFFFFFFFEULL)), nullptr);
}

void App::reloadCliConnections() {
    if (refreshing_ || signInInProgress_ || autoReauthBusy_) return;
    if (cliTokenSyncEnabled()) syncAllProviderTokens();
    for (auto& provider : providers_) provider.connected = hasAuth(provider.definition.id);
    updateAll();
    refresh();
}

bool App::attemptAutoReauth(std::size_t index) {
    if (index >= providers_.size()) return false;
    if (signInInProgress_ || managedAccounts(providers_[index].definition.id)) return false;
    auto& provider = providers_[index];
    const auto id = provider.definition.id;
    if (!shouldAutoReauthenticate(providerHasOfficialReauth(id), accountUsedOfficialSignIn(id), false)) return false;

    if (allowOfficialCli(id)) {
        syncProviderTokens(id);
        AuthMaterial cli = loadAuth(id);
        if (!cli.refreshToken.empty() && refreshOAuth(id, cli) && !cli.token.empty()) {
            provider.connected = true;
            SecureZeroMemory(cli.token.data(), cli.token.size());
            SecureZeroMemory(cli.refreshToken.data(), cli.refreshToken.size());
            return true;
        }
        SecureZeroMemory(cli.token.data(), cli.token.size());
        SecureZeroMemory(cli.refreshToken.data(), cli.refreshToken.size());
    }

    auto cookies = loadInstalledBrowserCookies(cookieHostSuffixes(id));
    AuthMaterial auth = loadAuth(id);
    const bool ok = autoRunOfficialSignIn(dialogParent(), id, auth, cookies);
    secureClearCookies(cookies);
    if (ok && !auth.token.empty() && saveAuth(id, auth)) {
        markOfficialLogin(id, true);
        provider.connected = true;
        syncProviderTokens(id);
        SecureZeroMemory(auth.token.data(), auth.token.size());
        SecureZeroMemory(auth.refreshToken.data(), auth.refreshToken.size());
        return true;
    }
    SecureZeroMemory(auth.token.data(), auth.token.size());
    SecureZeroMemory(auth.refreshToken.data(), auth.refreshToken.size());
    return false;
}

void App::queueAutoReauth() {
    if (signInInProgress_ || autoReauthBusy_ || refreshing_) return;
    if (autoReauthTried_.size() < providers_.size()) autoReauthTried_.resize(providers_.size(), 0);
    for (std::size_t index = 0; index < providers_.size(); ++index) {
        const auto& provider = providers_[index];
        if (!provider.snapshot.enabled || !provider.connected) continue;
        if (!providerAuthenticationFailed(provider.snapshot)) continue;
        if (!shouldAutoReauthenticate(providerHasOfficialReauth(provider.definition.id),
                                      accountUsedOfficialSignIn(provider.definition.id),
                                      autoReauthTried_[index] != 0)) {
            continue;
        }
        autoReauthTried_[index] = 1;
        autoReauthQueue_.push_back(index);
    }
    if (!autoReauthBusy_ && !autoReauthQueue_.empty()) PostMessageW(trayWindow_, kAutoReauthMessage, 0, 0);
}

void App::processAutoReauth() {
    if (autoReauthBusy_ || signInInProgress_ || refreshing_ || autoReauthQueue_.empty()) return;
    autoReauthBusy_ = true;
    const std::size_t index = autoReauthQueue_.front();
    autoReauthQueue_.erase(autoReauthQueue_.begin());
    const bool ok = attemptAutoReauth(index);
    autoReauthBusy_ = false;
    if (ok) {
        // Keep the tried flag: it clears only once a refresh returns current data. Clearing it here loops forever
        // when re-auth "succeeds" with a token the usage endpoint still rejects.
        refresh();
        return;
    }
    if (!autoReauthQueue_.empty()) PostMessageW(trayWindow_, kAutoReauthMessage, 0, 0);
}

HWND App::dialogParent() const {
    if (ownStyleVisible(optionsWindow_)) return optionsWindow_;
    if (ownStyleVisible(floatingWindow_)) return floatingWindow_;
    return trayWindow_;
}

const MetricHit* App::hitAt(POINT client) const {
    const POINT logical = toLogical(client);
    const auto found = std::find_if(hits_.begin(), hits_.end(), [&](const MetricHit& hit) { return PtInRect(&hit.rect, logical); });
    return found == hits_.end() ? nullptr : &*found;
}

const ProviderSnapshot& App::hitSnapshotFor(const MetricHit& hit) const {
    const auto& provider = providers_[hit.provider];
    const auto row = std::ranges::find_if(provider.monitorAccounts, [&](const MonitorAccount& account) { return account.slot == hit.slot; });
    return row != provider.monitorAccounts.end() ? row->snapshot : provider.snapshot;
}

bool App::authenticationFailedAt(POINT client) const {
    const auto* hit = hitAt(client);
    return hit && providerAuthenticationFailed(hitSnapshotFor(*hit));
}

void App::handleMonitorClick(POINT client) {
    if (autoReauthBusy_ || signInInProgress_) return;
    const auto* hit = hitAt(client);
    if (!hit || !providerAuthenticationFailed(hitSnapshotFor(*hit))) return;
    selectedProvider_ = hit->provider;
    // A rejected non-selected account must be selected first so the sign-in replaces that account's credential.
    if (hit->slot != activeAccount(providers_[hit->provider].definition.id) && !selectAccount(hit->provider, hit->slot, true)) return;
    connectProvider();
}

// An explicit selection overrides newest-token arbitration. Roll back files on failure.
bool applyAccountToCli(std::wstring_view id, const AuthMaterial& auth) {
    const auto format = cliFormatForProvider(utf8(id));
    if (!format) return true; // No official CLI credential file is known for this provider.
    std::vector<std::wstring> paths;
    auto includeHome = [&](const std::wstring& home) {
        auto candidates = cliCredentialPathsForHome(home, id);
        bool found = false;
        for (const auto& path : candidates) {
            if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
            paths.push_back(path);
            found = true;
        }
        if (!found && !candidates.empty()) paths.push_back(candidates.front());
    };
    includeHome(userProfile());
    for (const auto& home : discoverWslHomes()) {
        if (wslHomeSyncEnabled(home)) includeHome(home.home);
    }
    std::vector<std::optional<std::string>> backups;
    for (const auto& path : paths) {
        auto body = readUtf8File(path);
        if (!body && GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return false;
        backups.push_back(std::move(body));
    }
    bool ok = true;
    for (std::size_t i = 0; i < paths.size(); ++i) {
        const auto merged = mergeCliCredentialJson(*format, backups[i].value_or(""), recordFromAuth(auth));
        if (writeUtf8FileAtomic(paths[i], merged)) continue;
        ok = false;
        for (std::size_t j = 0; j < i; ++j) {
            if (backups[j]) writeUtf8FileAtomic(paths[j], *backups[j]);
            else DeleteFileW(paths[j].c_str());
        }
        break;
    }
    for (auto& body : backups) if (body) SecureZeroMemory(body->data(), body->size());
    return ok;
}

bool App::selectAccount(std::size_t index, DWORD slot, bool interactive) {
    if (refreshing_ || signInInProgress_ || autoReauthBusy_) return false;
    auto& provider = providers_[index];
    const auto& id = provider.definition.id;
    auto auth = loadStoredAuth(accountKey(id, slot));
    if (auth.token.empty() && auth.refreshToken.empty()) return false;
    const bool synced = applyAccountToCli(id, auth);
    SecureZeroMemory(auth.token.data(), auth.token.size());
    SecureZeroMemory(auth.refreshToken.data(), auth.refreshToken.size());
    if (!synced) {
        writeDword((accountSetting(id) + L".SyncFailed").c_str(), 1);
        if (interactive) MessageBoxW(dialogParent(), L"Could not sync the credential to every Windows and selected WSL CLI file. Check file access and WSL availability. The selected account was not changed; earlier writes were rolled back where possible.", kAppName, MB_ICONERROR);
        return false;
    }
    writeDword((L"Provider." + id + L".ManagedAccounts").c_str(), 1);
    writeDword((L"Provider." + id + L".ActiveAccount").c_str(), slot);
    writeDword((accountSetting(id) + L".SelectionSync").c_str(), 1);
    writeDword((accountSetting(id) + L".SyncFailed").c_str(), 0);
    provider.connected = true;
    provider.snapshot.lastSuccessfulRefresh.reset();
    for (auto& metric : provider.snapshot.metrics) metric = initialMetric(id, metric.kind);
    provider.snapshot.id = utf8(slot ? accountKey(id, slot) : id);
    seedMonitorAccounts(provider);
    if (index < autoReauthTried_.size()) autoReauthTried_[index] = 0;
    updateAll();
    return true;
}

void App::showAccountMenu(std::size_t index, POINT screen) {
    const auto& id = providers_[index].definition.id;
    HMENU menu = CreatePopupMenu();
    const DWORD count = std::min<DWORD>(readDword((L"Provider." + id + L".AccountCount").c_str(), 1), 100);
    const bool busy = refreshing_ || signInInProgress_ || autoReauthBusy_;
    for (DWORD slot = 0; slot < count; ++slot) {
        auto auth = loadStoredAuth(accountKey(id, slot));
        const bool exists = !auth.token.empty() || !auth.refreshToken.empty();
        SecureZeroMemory(auth.token.data(), auth.token.size());
        SecureZeroMemory(auth.refreshToken.data(), auth.refreshToken.size());
        if (!exists) continue;
        auto label = L"Account " + std::to_wstring(slot + 1);
        AppendMenuW(menu, MF_STRING | (slot == activeAccount(id) ? MF_CHECKED : 0) | (busy ? MF_GRAYED : 0), 1000 + slot, label.c_str());
    }
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING | (busy ? MF_GRAYED : 0), 2000, L"Add account...");
    const UINT chosen = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screen.x, screen.y, 0, dialogParent(), nullptr);
    DestroyMenu(menu);
    if (chosen == 2000) { selectedProvider_ = index; addAccount(); }
    else if (chosen >= 1000 && chosen < 1100 && selectAccount(index, chosen - 1000)) refresh();
}

void App::addAccount() {
    if (refreshing_ || signInInProgress_ || autoReauthBusy_) return;
    const auto index = selectedProvider_;
    const auto id = providers_[index].definition.id;
    const DWORD previous = activeAccount(id);
    const bool wasManaged = managedAccounts(id);
    // Preserve a legacy CLI-only login before entering managed-account mode.
    auto old = loadAuth(id);
    if (!old.token.empty() && !saveAuth(id, old)) return;
    SecureZeroMemory(old.token.data(), old.token.size());
    SecureZeroMemory(old.refreshToken.data(), old.refreshToken.size());
    const DWORD slot = readDword((L"Provider." + id + L".AccountCount").c_str(), 1);
    if (slot >= 100) { MessageBoxW(dialogParent(), L"Up to 100 account slots are supported per provider.", kAppName, MB_ICONINFORMATION); return; }
    writeDword((L"Provider." + id + L".ManagedAccounts").c_str(), 1);
    writeDword((L"Provider." + id + L".ActiveAccount").c_str(), slot);
    connectProvider();
    writeDword((L"Provider." + id + L".ActiveAccount").c_str(), previous);
    auto added = loadStoredAuth(accountKey(id, slot));
    const bool saved = !added.token.empty();
    SecureZeroMemory(added.token.data(), added.token.size());
    SecureZeroMemory(added.refreshToken.data(), added.refreshToken.size());
    if (saved) {
        writeDword((L"Provider." + id + L".AccountCount").c_str(), slot + 1);
        selectAccount(index, slot);
    } else {
        writeDword((L"Provider." + id + L".ManagedAccounts").c_str(), wasManaged ? 1 : 0);
    }
    providers_[index].connected = hasAuth(id);
    seedMonitorAccounts(providers_[index]);
    updateAll();
    refresh();
}

bool App::rotateAccounts() {
    const auto now = std::chrono::system_clock::now();
    bool changed = false;
    for (std::size_t index = 0; index < providers_.size(); ++index) {
        auto& provider = providers_[index];
        const auto& id = provider.definition.id;
        if (!provider.snapshot.enabled || !provider.connected ||
            !readDword((L"Provider." + id + L".RotateAccounts").c_str(), 0)) continue;
        const auto blockedUntil = exhaustedUntil(provider.snapshot, now);
        if (!blockedUntil) {
            const bool recovered = std::ranges::any_of(provider.snapshot.metrics, [](const Metric& metric) {
                return metric.state == MetricState::Current && metric.observedAt.has_value();
            }) && std::ranges::all_of(provider.snapshot.metrics, [](const Metric& metric) {
                return metric.state == MetricState::Unsupported ||
                    (metric.state == MetricState::Current && ((metric.remaining && *metric.remaining > 0) ||
                    (metric.capacity && metric.used && *metric.capacity > *metric.used)));
            });
            if (recovered) deleteSetting((accountSetting(id) + L".ExhaustedUntil").c_str());
            continue;
        }
        const DWORD active = activeAccount(id);
        writeQword((accountSetting(id) + L".ExhaustedUntil").c_str(),
            static_cast<ULONGLONG>(std::chrono::duration_cast<std::chrono::seconds>(blockedUntil->time_since_epoch()).count()));
        const DWORD count = std::min<DWORD>(readDword((L"Provider." + id + L".AccountCount").c_str(), 1), 100);
        for (DWORD step = 1; step < count; ++step) {
            const DWORD candidate = (active + step) % count;
            const auto prefix = L"Provider." + id + (candidate ? L".Account." + std::to_wstring(candidate) : L"");
            const auto until = readQword((prefix + L".ExhaustedUntil").c_str()).value_or(0);
            if (until > static_cast<ULONGLONG>(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count())) continue;
            auto auth = loadStoredAuth(accountKey(id, candidate));
            const bool exists = !auth.token.empty() || !auth.refreshToken.empty();
            SecureZeroMemory(auth.token.data(), auth.token.size());
            SecureZeroMemory(auth.refreshToken.data(), auth.refreshToken.size());
            if (!exists) continue;
            if (selectAccount(index, candidate, false)) changed = true;
            break;
        }
    }
    return changed;
}

void App::connectProvider() {
    if (signInInProgress_ || autoReauthBusy_ || refreshing_) return;
    struct SignInGuard {
        bool& flag;
        explicit SignInGuard(bool& value) : flag(value) { flag = true; }
        ~SignInGuard() { flag = false; }
    } guard{signInInProgress_};
    persistGoogleClientSecretField();
    auto& provider = providers_[selectedProvider_];
    const bool cliReady = !loadCliAuth(provider.definition.id).token.empty();
    const bool canOAuth = providerHasSubscriptionOAuth(provider.definition.id);
    HWND parent = dialogParent();

    TASKDIALOG_BUTTON buttons[3]{};
    int buttonCount = 0;
    constexpr int kSignIn = 100;
    constexpr int kPaste = 101;
    constexpr int kUseCli = 102;
    if (canOAuth) {
        buttons[buttonCount].nButtonID = kSignIn;
        buttons[buttonCount].pszButtonText = L"Sign in with subscription\nUses the same session and weekly usage as the provider's own app";
        ++buttonCount;
    }
    buttons[buttonCount].nButtonID = kPaste;
    buttons[buttonCount].pszButtonText = canOAuth
        ? L"Paste a token or API key\nPrepaid API credit, or a token copied from the official CLI"
        : L"Paste API key\nThis provider uses a platform API key for balance";
    ++buttonCount;
    if (cliReady) {
        buttons[buttonCount].nButtonID = kUseCli;
        buttons[buttonCount].pszButtonText = L"Use the official CLI login already on this PC";
        ++buttonCount;
    }

    const std::wstring heading = L"Connect " + provider.definition.name;
    TASKDIALOGCONFIG cfg{};
    cfg.cbSize = sizeof(cfg);
    cfg.hwndParent = parent;
    cfg.dwFlags = TDF_USE_COMMAND_LINKS | TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT;
    cfg.dwCommonButtons = TDCBF_CANCEL_BUTTON;
    cfg.pszWindowTitle = kAppName;
    cfg.pszMainInstruction = heading.c_str();
    cfg.pszContent = L"Subscription sign-in fetches plan session/weekly allowances. A platform API key fetches prepaid credit only. When adding an account, choose the intended account on the provider's sign-in page.";
    cfg.cButtons = static_cast<UINT>(buttonCount);
    cfg.pButtons = buttons;
    cfg.nDefaultButton = buttons[0].nButtonID;
    int chosen = IDCANCEL;
    TaskDialogIndirect(&cfg, &chosen, nullptr, nullptr);

    if (chosen == kUseCli) {
        if (!saveAuth(provider.definition.id, loadCliAuth(provider.definition.id))) return;
        writeDword((accountSetting(provider.definition.id) + L".UseOfficialCli").c_str(), 1);
        provider.snapshot.enabled = true;
        writeDword((L"Provider." + provider.definition.id + L".Enabled").c_str(), 1);
        markOfficialLogin(provider.definition.id, true);
        if (selectedProvider_ < autoReauthTried_.size()) autoReauthTried_[selectedProvider_] = 0;
        provider.connected = true;
        syncProviderTokens(provider.definition.id);
        PostMessageW(trayWindow_, WM_COMMAND, IdTrayRefresh, 0);
        return;
    }
    if (chosen == kSignIn) {
        if (provider.definition.id == L"antigravity" && !googleClientSecretConfigured()) {
            showOptions(selectedProvider_);
            MessageBoxW(optionsWindow_,
                L"Paste the Google OAuth client secret on this tab first. It is stored in Windows Credential Manager and is required for in-app Google sign-in and token refresh.",
                kAppName, MB_ICONWARNING);
            return;
        }
        AuthMaterial auth;
        if (!runSubscriptionOAuth(parent, provider.definition.id, auth) || auth.token.empty()) {
            MessageBoxW(parent, L"Subscription sign-in did not complete. You can try again or paste a token.", kAppName, MB_ICONWARNING);
            return;
        }
        if (!saveAuth(provider.definition.id, auth)) {
            MessageBoxW(parent, L"Windows Credential Manager rejected the credential.", kAppName, MB_ICONERROR);
            return;
        }
        writeDword((accountSetting(provider.definition.id) + L".UseOfficialCli").c_str(), 1);
        provider.snapshot.enabled = true;
        writeDword((L"Provider." + provider.definition.id + L".Enabled").c_str(), 1);
        markOfficialLogin(provider.definition.id, true);
        if (selectedProvider_ < autoReauthTried_.size()) autoReauthTried_[selectedProvider_] = 0;
        provider.connected = true;
        syncProviderTokens(provider.definition.id);
        PostMessageW(trayWindow_, WM_COMMAND, IdTrayRefresh, 0);
        return;
    }
    if (chosen != kPaste) return;

    ShellExecuteW(parent, L"open", provider.definition.accountUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    CREDUI_INFOW info{sizeof(info), parent, L"Connect provider", L"Paste the provider access token or API key into the password field. It will be stored in Windows Credential Manager.", nullptr};
    wchar_t user[2] = L"-";
    wchar_t secret[1024]{};
    BOOL save = FALSE;
    const DWORD result = CredUIPromptForCredentialsW(&info, (L"HypeLimits/" + provider.definition.id).c_str(),
        nullptr, 0, user, static_cast<ULONG>(std::size(user)), secret, static_cast<ULONG>(std::size(secret)), &save,
        CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_ALWAYS_SHOW_UI | CREDUI_FLAGS_DO_NOT_PERSIST | CREDUI_FLAGS_EXCLUDE_CERTIFICATES);
    if (result == NO_ERROR && secret[0] != L'\0') {
        if (!CredentialStore::save(provider.definition.id, secret)) {
            MessageBoxW(parent, L"Windows Credential Manager rejected the credential.", kAppName, MB_ICONERROR);
        } else {
            writeDword((accountSetting(provider.definition.id) + L".UseOfficialCli").c_str(), 1);
            provider.snapshot.enabled = true;
            writeDword((L"Provider." + provider.definition.id + L".Enabled").c_str(), 1);
            const auto pasted = parseAuthJson(utf8(secret));
            markOfficialLogin(provider.definition.id, !pasted.refreshToken.empty());
            if (selectedProvider_ < autoReauthTried_.size()) autoReauthTried_[selectedProvider_] = 0;
            provider.connected = true;
            syncProviderTokens(provider.definition.id);
        }
        SecureZeroMemory(secret, sizeof(secret));
        PostMessageW(trayWindow_, WM_COMMAND, IdTrayRefresh, 0);
    } else {
        SecureZeroMemory(secret, sizeof(secret));
    }
}

void App::updateAll() {
    destroyMonitorBitmap();
    syncFloatingWindowSize();
    InvalidateRect(floatingWindow_, nullptr, FALSE);
    updateOptions();
    updateTrayIcon();
    for (const auto& provider : providers_) {
        for (const auto& event : alerts_.observe(provider.snapshot)) {
            const std::wstring warningName = L"Alert." + wide(event.providerId) + L"." + std::to_wstring(static_cast<int>(event.metricKind)) + L".Warned";
            if (event.kind == AlertKind::Warning) {
                writeDword(warningName.c_str(), 1);
                playWarning();
            } else {
                deleteSetting(warningName.c_str());
                playReset();
                startRowFlash(event.providerId);
            }
        }
    }
}

HICON App::createGaugeIcon(std::optional<double> remaining) {
    constexpr int size = 32;
    BITMAPV5HEADER header{};
    header.bV5Size = sizeof(header);
    header.bV5Width = size;
    header.bV5Height = -size;
    header.bV5Planes = 1;
    header.bV5BitCount = 32;
    header.bV5Compression = BI_BITFIELDS;
    header.bV5RedMask = 0x00FF0000;
    header.bV5GreenMask = 0x0000FF00;
    header.bV5BlueMask = 0x000000FF;
    header.bV5AlphaMask = 0xFF000000;
    void* raw{};
    HDC dc = GetDC(nullptr);
    HBITMAP colorBitmap = CreateDIBSection(dc, reinterpret_cast<BITMAPINFO*>(&header), DIB_RGB_COLORS, &raw, nullptr, 0);
    ReleaseDC(nullptr, dc);
    auto* pixels = static_cast<DWORD*>(raw);
    const COLORREF color = remaining ? remainingColor(*remaining) : RGB(140, 145, 154);
    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            const double dx = x - 15.5;
            const double dy = y - 15.5;
            const double radius = std::sqrt(dx * dx + dy * dy);
            double angle = std::atan2(dy, dx);
            const bool gap = angle > 0.65 && angle < 2.49;
            if (radius >= 9.0 && radius <= 13.0 && !gap) {
                pixels[y * size + x] = 0xFF000000 | (GetRValue(color) << 16) | (GetGValue(color) << 8) | GetBValue(color);
            } else if (radius < 2.8) {
                pixels[y * size + x] = 0xFF000000 | (GetRValue(color) << 16) | (GetGValue(color) << 8) | GetBValue(color);
            } else {
                pixels[y * size + x] = 0;
            }
        }
    }
    HBITMAP mask = CreateBitmap(size, size, 1, 1, nullptr);
    ICONINFO info{TRUE, 0, 0, mask, colorBitmap};
    HICON icon = CreateIconIndirect(&info);
    DeleteObject(mask);
    DeleteObject(colorBitmap);
    return icon;
}

void App::installTrayIcon() {
    if (trayIcon_) DestroyIcon(trayIcon_);
    trayIcon_ = createGaugeIcon(std::nullopt);
    NOTIFYICONDATAW data{sizeof(data)};
    data.hWnd = trayWindow_;
    data.uID = 1;
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    data.uCallbackMessage = kTrayMessage;
    data.hIcon = trayIcon_;
    wcscpy_s(data.szTip, L"HypeLimits — status unknown or disconnected");
    Shell_NotifyIconW(NIM_ADD, &data);
    data.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &data);
}

void App::updateTrayIcon() {
    std::vector<ProviderSnapshot> snapshots;
    for (const auto& provider : providers_) snapshots.push_back(provider.snapshot);
    const auto aggregate = aggregateStatus(snapshots);
    HICON newIcon = createGaugeIcon(aggregate.remainingFraction);
    NOTIFYICONDATAW data{sizeof(data)};
    data.hWnd = trayWindow_;
    data.uID = 1;
    data.uFlags = NIF_ICON | NIF_TIP;
    data.hIcon = newIcon;
    std::wstring signIn;
    for (const auto& provider : providers_) {
        if (!provider.snapshot.enabled || !providerAuthenticationFailed(provider.snapshot)) continue;
        if (!signIn.empty()) signIn += L", ";
        signIn += provider.definition.name;
    }
    std::wstring tooltip = L"HypeLimits — status unknown or disconnected";
    if (!signIn.empty()) tooltip = L"Sign in required: " + signIn;
    if (aggregate.remainingFraction) {
        const auto found = std::find_if(providers_.begin(), providers_.end(), [&](const Provider& p) { return p.snapshot.id == aggregate.providerId; });
        if (found != providers_.end()) {
            const std::wstring usage = std::format(L"{} — {:.0f}% {} remaining", found->definition.name,
                *aggregate.remainingFraction * 100.0, kindName(aggregate.kind));
            tooltip = signIn.empty() ? usage : tooltip + L" · " + usage;
        }
    }
    wcsncpy_s(data.szTip, tooltip.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &data);
    if (trayIcon_) DestroyIcon(trayIcon_);
    trayIcon_ = newIcon;
}

void App::showOptions(std::optional<std::size_t> provider) {
    if (provider && *provider < providers_.size()) selectedProvider_ = *provider;
    TabCtrl_SetCurSel(tab_, static_cast<int>(selectedProvider_));
    discoverAndBuildWslControls(true);
    updateOptions();
    ShowWindow(optionsWindow_, SW_SHOW);
    RECT client{};
    GetClientRect(optionsWindow_, &client);
    layoutOptions(client.right, client.bottom);
    SetForegroundWindow(optionsWindow_);
}

void App::toggleMonitor() {
    const bool visible = IsWindowVisible(floatingWindow_) != FALSE;
    ShowWindow(floatingWindow_, visible ? SW_HIDE : SW_SHOWNOACTIVATE);
    writeDword(L"MonitorVisible", !visible);
}

void App::showTrayMenu() {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, IdTrayShow, IsWindowVisible(floatingWindow_) ? L"Hide Monitor" : L"Show Monitor");
    AppendMenuW(menu, MF_STRING, IdTrayRefresh, L"Refresh now");
    AppendMenuW(menu, MF_STRING, IdTrayOptions, L"Options...");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IdTrayQuit, L"Quit");
    POINT cursor{};
    GetCursorPos(&cursor);
    SetForegroundWindow(trayWindow_);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN, cursor.x, cursor.y, 0, trayWindow_, nullptr);
    DestroyMenu(menu);
}

void App::playTone(bool reset) {
    if (!readDword(L"SoundsEnabled", 1)) return;
    const int volume = std::clamp<int>(readDword(L"SoundVolume", 60), 0, 100);
    if (volume == 0) return;
    constexpr int sampleRate = 22050;
    const int durationMs = reset ? 300 : 190;
    const int samples = sampleRate * durationMs / 1000;
    const DWORD dataBytes = samples * sizeof(short);
    soundBuffer_.assign(44 + dataBytes, 0);
    auto put16 = [&](std::size_t offset, WORD value) { memcpy(soundBuffer_.data() + offset, &value, sizeof(value)); };
    auto put32 = [&](std::size_t offset, DWORD value) { memcpy(soundBuffer_.data() + offset, &value, sizeof(value)); };
    memcpy(soundBuffer_.data(), "RIFF", 4); put32(4, 36 + dataBytes); memcpy(soundBuffer_.data() + 8, "WAVEfmt ", 8);
    put32(16, 16); put16(20, 1); put16(22, 1); put32(24, sampleRate); put32(28, sampleRate * 2);
    put16(32, 2); put16(34, 16); memcpy(soundBuffer_.data() + 36, "data", 4); put32(40, dataBytes);
    auto* output = reinterpret_cast<short*>(soundBuffer_.data() + 44);
    for (int index = 0; index < samples; ++index) {
        const double seconds = static_cast<double>(index) / sampleRate;
        double frequency = reset && index > sampleRate * 0.15 ? 880.0 : (reset ? 660.0 : 430.0);
        const bool silence = reset && index > sampleRate * 0.11 && index < sampleRate * 0.15;
        const double envelope = std::min(1.0, index / 220.0) * std::min(1.0, (samples - index) / 440.0);
        output[index] = silence ? 0 : static_cast<short>(std::sin(6.283185307 * frequency * seconds) * 9000 * volume / 100.0 * envelope);
    }
    PlaySoundW(reinterpret_cast<LPCWSTR>(soundBuffer_.data()), nullptr, SND_MEMORY | SND_ASYNC | SND_NODEFAULT);
}

void App::playWarning() {
    playTone(false);
}

void App::playReset() {
    playTone(true);
}

void App::startRowFlash(const std::string& providerId) {
    if (rowFlashUntil_.size() < providers_.size()) rowFlashUntil_.resize(providers_.size());
    for (std::size_t index = 0; index < providers_.size(); ++index) {
        if (providers_[index].snapshot.id != providerId) continue;
        rowFlashUntil_[index] = GetTickCount64() + kResetFlashMs;
        destroyMonitorBitmap();
        InvalidateRect(floatingWindow_, nullptr, FALSE);
        tickRowFlashes();
        return;
    }
}

void App::tickRowFlashes() {
    const ULONGLONG now = GetTickCount64();
    bool any = false;
    bool expired = false;
    ULONGLONG next = 0;
    for (auto& until : rowFlashUntil_) {
        if (until == 0) continue;
        if (until <= now) {
            until = 0;
            expired = true;
            continue;
        }
        any = true;
        if (next == 0 || until < next) next = until;
    }
    if (expired) {
        destroyMonitorBitmap();
        InvalidateRect(floatingWindow_, nullptr, FALSE);
    }
    if (any) {
        SetTimer(trayWindow_, kFlashTimer, static_cast<UINT>(std::max<ULONGLONG>(next - now, 16)), nullptr);
    } else {
        KillTimer(trayWindow_, kFlashTimer);
    }
}

LRESULT App::onFloating(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE: {
        tooltip_ = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                   CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, hwnd, nullptr, instance_, nullptr);
        TOOLINFOW info{sizeof(info)};
        info.uFlags = TTF_TRACK | TTF_ABSOLUTE;
        info.hwnd = hwnd;
        info.uId = 1;
        info.lpszText = const_cast<wchar_t*>(L"");
        SendMessageW(tooltip_, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&info));
        SendMessageW(tooltip_, TTM_SETMAXTIPWIDTH, 0, 420);
        return 0;
    }
    case WM_ERASEBKGND: return 1;
    case WM_TIMER:
        if (wParam == kActivityTimer) {
            destroyMonitorBitmap();
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    case WM_PAINT: paintFloating(); return 0;
    case WM_SIZE:
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    case WM_SETCURSOR:
        if (LOWORD(lParam) == HTCLIENT) {
            POINT cursor{};
            GetCursorPos(&cursor);
            ScreenToClient(hwnd, &cursor);
            switch (resizeEdgeAt(cursor)) {
            case ResizeEdge::Right: SetCursor(LoadCursorW(nullptr, IDC_SIZEWE)); return TRUE;
            case ResizeEdge::Bottom: SetCursor(LoadCursorW(nullptr, IDC_SIZENS)); return TRUE;
            case ResizeEdge::Corner: SetCursor(LoadCursorW(nullptr, IDC_SIZENWSE)); return TRUE;
            case ResizeEdge::None: break;
            }
            if (authenticationFailedAt(cursor)) {
                SetCursor(LoadCursorW(nullptr, IDC_HAND));
                return TRUE;
            }
        }
        break;
    case WM_LBUTTONDOWN: {
        POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        GetCursorPos(&dragStart_);
        RECT rect{};
        GetWindowRect(hwnd, &rect);
        if (const auto edge = resizeEdgeAt(point); edge != ResizeEdge::None) {
            resizing_ = true;
            resizeEdge_ = edge;
            resizeCursorStart_ = dragStart_;
            resizeStartWidth_ = rect.right - rect.left;
        } else {
            dragging_ = true;
            windowStart_ = {rect.left, rect.top};
        }
        SetCapture(hwnd);
        return 0;
    }
    case WM_MOUSEMOVE: {
        POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        POINT cursor{};
        GetCursorPos(&cursor);
        const int dragDx = std::abs(static_cast<int>(cursor.x - dragStart_.x));
        const int dragDy = std::abs(static_cast<int>(cursor.y - dragStart_.y));
        const bool pastSlop = dragDx > kMonitorClickSlop || dragDy > kMonitorClickSlop;
        if (resizing_ && (wParam & MK_LBUTTON) && pastSlop) {
            // The widget keeps its aspect ratio, so vertical drags are mapped back onto width.
            const double aspect = static_cast<double>(logicalWidth_) / static_cast<double>(logicalHeight_);
            const int dx = static_cast<int>(cursor.x - resizeCursorStart_.x);
            const int dy = static_cast<int>(std::lround((cursor.y - resizeCursorStart_.y) * aspect));
            int delta = dx;
            if (resizeEdge_ == ResizeEdge::Bottom) delta = dy;
            else if (resizeEdge_ == ResizeEdge::Corner) delta = std::abs(dx) >= std::abs(dy) ? dx : dy;
            const int width = std::max(resizeStartWidth_ + delta, kMonitorMinWindowWidth);
            const int height = std::max(1, static_cast<int>(std::lround(
                static_cast<double>(logicalHeight_) * width / static_cast<double>(logicalWidth_))));
            SetWindowPos(hwnd, nullptr, 0, 0, width, height, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
            const int corner = std::max(4, static_cast<int>(std::lround(kMonitorCorner * monitorScale())));
            SetWindowRgn(hwnd, CreateRoundRectRgn(0, 0, width, height, corner, corner), TRUE);
        } else if (dragging_ && (wParam & MK_LBUTTON) && pastSlop) {
            SetWindowPos(hwnd, nullptr, windowStart_.x + cursor.x - dragStart_.x, windowStart_.y + cursor.y - dragStart_.y,
                         0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        } else if (!(wParam & MK_LBUTTON)) {
            activateTooltip(point);
            TRACKMOUSEEVENT track{sizeof(track), TME_LEAVE, hwnd, 0};
            TrackMouseEvent(&track);
        }
        return 0;
    }
    case WM_MOUSELEAVE: SendMessageW(tooltip_, TTM_TRACKACTIVATE, FALSE, 0); return 0;
    case WM_LBUTTONUP: {
        POINT cursor{};
        GetCursorPos(&cursor);
        const bool moved = std::abs(static_cast<int>(cursor.x - dragStart_.x)) > kMonitorClickSlop
            || std::abs(static_cast<int>(cursor.y - dragStart_.y)) > kMonitorClickSlop;
        const bool wasResizing = resizing_;
        const bool click = !moved;
        dragging_ = false;
        resizing_ = false;
        ReleaseCapture();
        RECT rect{};
        GetWindowRect(hwnd, &rect);
        writeDword(L"MonitorX", rect.left);
        writeDword(L"MonitorY", rect.top);
        writeDword(L"MonitorWidth", static_cast<DWORD>(rect.right - rect.left));
        if (wasResizing && moved) {
            destroyMonitorBitmap();
            syncFloatingWindowSize();
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        if (click && !wasResizing) {
            POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
            handleMonitorClick(point);
        }
        return 0;
    }
    case WM_CAPTURECHANGED:
        dragging_ = false;
        resizing_ = false;
        return 0;
    case WM_LBUTTONDBLCLK: {
        POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        if (authenticationFailedAt(point)) return 0;
        const auto* found = hitAt(point);
        if (found) showOptions(found->provider);
        else showOptions();
        return 0;
    }
    case WM_RBUTTONUP: {
        POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        const auto* found = hitAt(point);
        if (!found) { showTrayMenu(); return 0; }
        const auto index = found->provider;
        ClientToScreen(hwnd, &point);
        showAccountMenu(index, point);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT App::onOptions(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE: return 0;
    case WM_SIZE: layoutOptions(LOWORD(lParam), HIWORD(lParam)); return 0;
    case WM_CLOSE:
        persistGoogleClientSecretField();
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    case WM_NOTIFY:
        if (reinterpret_cast<NMHDR*>(lParam)->idFrom == IdTab && reinterpret_cast<NMHDR*>(lParam)->code == TCN_SELCHANGE) {
            persistGoogleClientSecretField();
            selectedProvider_ = static_cast<std::size_t>(TabCtrl_GetCurSel(tab_));
            updateOptions();
        }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IdAddAccount: addAccount(); return 0;
        case IdAccounts: {
            POINT point{}; GetCursorPos(&point);
            showAccountMenu(selectedProvider_, point); return 0;
        }
        case IdRotateAccounts:
            writeDword((L"Provider." + providers_[selectedProvider_].definition.id + L".RotateAccounts").c_str(), Button_GetCheck(rotateAccounts_) == BST_CHECKED);
            return 0;
        case IdLogin:
            connectProvider(); return 0;
        case IdEnabled: {
            auto& provider = providers_[selectedProvider_];
            provider.snapshot.enabled = Button_GetCheck(enabled_) == BST_CHECKED;
            writeDword((L"Provider." + provider.definition.id + L".Enabled").c_str(), provider.snapshot.enabled);
            if (provider.snapshot.enabled && provider.connected) refresh();
            updateAll();
            return 0;
        }
        case IdRefresh: refresh(true); return 0;
        case IdDisconnect:
            if (refreshing_ || signInInProgress_ || autoReauthBusy_) return 0;
            CredentialStore::remove(providers_[selectedProvider_].definition.id);
            writeDword((accountSetting(providers_[selectedProvider_].definition.id) + L".UseOfficialCli").c_str(), 0);
            providers_[selectedProvider_].snapshot.enabled = false;
            writeDword((L"Provider." + providers_[selectedProvider_].definition.id + L".Enabled").c_str(), 0);
            markOfficialLogin(providers_[selectedProvider_].definition.id, false);
            if (selectedProvider_ < autoReauthTried_.size()) autoReauthTried_[selectedProvider_] = 0;
            providers_[selectedProvider_].connected = false;
            {
                const std::wstring prefix = accountSetting(providers_[selectedProvider_].definition.id);
                deleteSetting((prefix + L".SelectionSync").c_str());
                deleteSetting((prefix + L".ExhaustedUntil").c_str());
                for (const auto& metric : providers_[selectedProvider_].snapshot.metrics) {
                    for (const auto* field : {L"UsedMicros", L"CapacityMicros", L"RemainingMicros", L"ObservedUnix", L"ResetUnix", L"Currency", L"DrawdownUnix"})
                        deleteSetting((prefix + L"." + std::to_wstring(static_cast<int>(metric.kind)) + L"." + field).c_str());
                }
                deleteSetting((prefix + L".BalanceMicros").c_str());
                deleteSetting((prefix + L".ObservedUnix").c_str());
                deleteSetting((prefix + L".Currency").c_str());
            }
            for (auto& metric : providers_[selectedProvider_].snapshot.metrics) metric = initialMetric(providers_[selectedProvider_].definition.id, metric.kind);
            updateAll();
            return 0;
        case IdSounds: writeDword(L"SoundsEnabled", Button_GetCheck(sounds_) == BST_CHECKED); return 0;
        case IdAlwaysOnTop: {
            const bool top = Button_GetCheck(alwaysOnTop_) == BST_CHECKED;
            writeDword(L"AlwaysOnTop", top);
            SetWindowPos(floatingWindow_, top ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            return 0;
        }
        case IdLaunchAtLogin: {
            const bool enabled = Button_GetCheck(launchAtLogin_) == BST_CHECKED;
            if (!setLaunchAtLogin(enabled)) {
                Button_SetCheck(launchAtLogin_, enabled ? BST_UNCHECKED : BST_CHECKED);
                MessageBoxW(hwnd, L"Windows rejected the launch-at-login change.", kAppName, MB_ICONWARNING);
            }
            return 0;
        }
        case IdSyncCliTokens: {
            const bool enabled = Button_GetCheck(syncCliTokens_) == BST_CHECKED;
            writeDword(L"TokenSyncAsked", 1);
            writeDword(L"TokenSyncEnabled", enabled ? 1 : 0);
            if (enabled) reloadCliConnections();
            return 0;
        }
        case IdSyncWslTokens: {
            const bool enabled = Button_GetCheck(syncWslTokens_) == BST_CHECKED;
            writeDword(L"WslTokenSyncEnabled", enabled ? 1 : 0);
            if (enabled) discoverAndBuildWslControls(true);
            else syncWslControlVisibility();
            {
                RECT client{};
                GetClientRect(hwnd, &client);
                layoutOptions(client.right, client.bottom);
            }
            reloadCliConnections();
            return 0;
        }
        case IdPreviewWarning: playWarning(); return 0;
        case IdPreviewReset: playReset(); return 0;
        case IdClose:
            persistGoogleClientSecretField();
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        case IdGoogleClientSecret:
            if (HIWORD(wParam) == EN_KILLFOCUS) persistGoogleClientSecretField();
            return 0;
        case IdInterval:
            if (HIWORD(wParam) == EN_KILLFOCUS) {
                wchar_t value[16]{}; GetWindowTextW(interval_, value, static_cast<int>(std::size(value)));
                const DWORD minutes = std::clamp<DWORD>(wcstoul(value, nullptr, 10), 1, 1440);
                writeDword(L"PollingMinutes", minutes);
                scheduleNextPoll(false);
                SetWindowTextW(interval_, std::to_wstring(minutes).c_str());
            }
            return 0;
        case IdThreshold:
            if (HIWORD(wParam) == EN_KILLFOCUS) {
                wchar_t value[32]{}; GetWindowTextW(threshold_, value, static_cast<int>(std::size(value)));
                const double dollars = std::clamp(wcstod(value, nullptr), 0.0, 1000000.0);
                const std::wstring name = L"Provider." + providers_[selectedProvider_].definition.id + L".ThresholdCents";
                writeDword(name.c_str(), static_cast<DWORD>(std::lround(dollars * 100.0)));
                for (auto& metric : providers_[selectedProvider_].snapshot.metrics) {
                    if (metric.kind == MetricKind::ApiCredit) metric.lowBalanceThreshold = dollars;
                }
            }
            return 0;
        case IdCreditBarFull:
            if (HIWORD(wParam) == EN_KILLFOCUS) {
                wchar_t value[32]{}; GetWindowTextW(creditBarFull_, value, static_cast<int>(std::size(value)));
                const double dollars = std::clamp(wcstod(value, nullptr), 0.01, 1000000.0);
                const std::wstring name = L"Provider." + providers_[selectedProvider_].definition.id + L".CreditBarFullCents";
                writeDword(name.c_str(), static_cast<DWORD>(std::lround(dollars * 100.0)));
                SetWindowTextW(creditBarFull_, std::format(L"{:.2f}", dollars).c_str());
                for (auto& metric : providers_[selectedProvider_].snapshot.metrics) {
                    if (metric.kind == MetricKind::ApiCredit) metric.barFullAmount = dollars;
                }
                updateAll();
            }
            return 0;
        default: {
            const int index = LOWORD(wParam) - IdWslUserFirst;
            if (index >= 0 && static_cast<std::size_t>(index) < wslUserChecks_.size()
                && static_cast<std::size_t>(index) < cachedWslHomes.size()) {
                const auto& home = cachedWslHomes[static_cast<std::size_t>(index)];
                writeDword(wide(wslUserSettingKey(utf8(home.distro), utf8(home.user))).c_str(),
                           Button_GetCheck(wslUserChecks_[static_cast<std::size_t>(index)]) == BST_CHECKED ? 1 : 0);
                reloadCliConnections();
                return 0;
            }
            break;
        }
        }
        break;
    case WM_HSCROLL:
        if (reinterpret_cast<HWND>(lParam) == volume_) writeDword(L"SoundVolume", static_cast<DWORD>(SendMessageW(volume_, TBM_GETPOS, 0, 0)));
        return 0;
    case WM_DRAWITEM: {
        const auto* draw = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);
        if (draw->CtlID != IdTab) break;
        HBRUSH brush = CreateSolidBrush((draw->itemState & ODS_SELECTED) ? RGB(54, 58, 68) : RGB(38, 41, 48));
        FillRect(draw->hDC, &draw->rcItem, brush);
        DeleteObject(brush);
        TCITEMW item{TCIF_TEXT};
        wchar_t label[80]{};
        item.pszText = label;
        item.cchTextMax = static_cast<int>(std::size(label));
        TabCtrl_GetItem(tab_, static_cast<int>(draw->itemID), &item);
        SetBkMode(draw->hDC, TRANSPARENT);
        SetTextColor(draw->hDC, RGB(232, 233, 236));
        RECT textRect = draw->rcItem;
        DrawTextW(draw->hDC, label, -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_NOCLIP);
        return TRUE;
    }
    case WM_CTLCOLORSTATIC:
        SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        SetTextColor(reinterpret_cast<HDC>(wParam), RGB(232, 233, 236));
        return reinterpret_cast<LRESULT>(darkBrush_);
    case WM_CTLCOLOREDIT:
        SetBkColor(reinterpret_cast<HDC>(wParam), RGB(45, 48, 56));
        SetTextColor(reinterpret_cast<HDC>(wParam), RGB(232, 233, 236));
        return reinterpret_cast<LRESULT>(editBrush_);
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT App::onTray(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == taskbarCreatedMessage_) {
        installTrayIcon();
        updateTrayIcon();
        return 0;
    }
    switch (message) {
    case kRefreshCompleteMessage: {
        std::unique_ptr<std::vector<RefreshResult>> completed(reinterpret_cast<std::vector<RefreshResult>*>(lParam));
        for (auto& result : *completed) {
            if (result.index >= providers_.size()) continue;
            auto& provider = providers_[result.index];
            result.snapshot.enabled = provider.snapshot.enabled;
            if (result.active) provider.snapshot = result.snapshot;
            const auto row = std::ranges::find_if(provider.monitorAccounts, [&](const MonitorAccount& account) { return account.slot == result.slot; });
            if (row != provider.monitorAccounts.end()) row->snapshot = result.snapshot;
            for (const auto& metric : result.snapshot.metrics) {
                if ((metric.state != MetricState::Current && metric.state != MetricState::Stale) || !metric.observedAt) continue;
                const std::wstring prefix = accountSettingFor(provider.definition.id, result.slot) + L"." + std::to_wstring(static_cast<int>(metric.kind));
                if (metric.used) writeQword((prefix + L".UsedMicros").c_str(), static_cast<ULONGLONG>(std::llround(*metric.used * 1000000.0)));
                if (metric.capacity) writeQword((prefix + L".CapacityMicros").c_str(), static_cast<ULONGLONG>(std::llround(*metric.capacity * 1000000.0)));
                if (metric.remaining) writeQword((prefix + L".RemainingMicros").c_str(), static_cast<ULONGLONG>(std::llround(*metric.remaining * 1000000.0)));
                writeQword((prefix + L".ObservedUnix").c_str(), static_cast<ULONGLONG>(std::chrono::duration_cast<std::chrono::seconds>(metric.observedAt->time_since_epoch()).count()));
                if (metric.lastDrawdownAt) {
                    writeQword((prefix + L".DrawdownUnix").c_str(), static_cast<ULONGLONG>(std::chrono::duration_cast<std::chrono::seconds>(metric.lastDrawdownAt->time_since_epoch()).count()));
                }
                if (metric.resetAt) {
                    writeQword((prefix + L".ResetUnix").c_str(), static_cast<ULONGLONG>(std::chrono::duration_cast<std::chrono::seconds>(metric.resetAt->time_since_epoch()).count()));
                }
                writeDword((prefix + L".Currency").c_str(), metric.currency == "CNY " ? 2 : 1);
            }
        }
        refreshing_ = false;
        if (refreshQueued_) { refreshQueued_ = false; refresh(); return 0; }
        if (rotateAccounts()) { refresh(); return 0; }
        for (std::size_t index = 0; index < providers_.size(); ++index) {
            if (index < autoReauthTried_.size()
                && !providerAuthenticationFailed(providers_[index].snapshot)
                && std::ranges::any_of(providers_[index].snapshot.metrics,
                                       [](const Metric& metric) { return metric.state == MetricState::Current; })) {
                autoReauthTried_[index] = 0;
            }
        }
        updateAll();
        const bool failed = std::ranges::any_of(providers_, [](const Provider& provider) {
            if (!provider.snapshot.enabled || !provider.connected) return false;
            return std::ranges::any_of(provider.snapshot.metrics, [](const Metric& metric) {
                return metric.state == MetricState::Error || metric.state == MetricState::Stale
                    || metric.state == MetricState::AuthenticationRequired;
            });
        });
        scheduleNextPoll(failed);
        queueAutoReauth();
        return 0;
    }
    case kAutoReauthMessage:
        processAutoReauth();
        return 0;
    case kTrayMessage:
        switch (LOWORD(lParam)) {
        case WM_CONTEXTMENU: case WM_RBUTTONUP: showTrayMenu(); break;
        case NIN_SELECT: case NIN_KEYSELECT: toggleMonitor(); break;
        }
        return 0;
    case kNetworkChangedMessage:
        // Virtual adapters (WSL, VPN) flap constantly; do not hammer providers or burn rate limits.
        if (GetTickCount64() - lastRefreshTick_ >= 60000) refresh();
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IdTrayShow: toggleMonitor(); break;
        case IdTrayRefresh: refresh(true); break;
        case IdTrayOptions: showOptions(); break;
        case IdTrayQuit:
            persistGoogleClientSecretField();
            DestroyWindow(hwnd);
            break;
        }
        return 0;
    case WM_TIMER:
        if (wParam == kPollTimer) {
            KillTimer(hwnd, kPollTimer);
            if (!autoReauthBusy_) refresh();
            else scheduleNextPoll(true);
        } else if (wParam == kFlashTimer) {
            KillTimer(hwnd, kFlashTimer);
            tickRowFlashes();
        }
        return 0;
    case WM_DESTROY: {
        NOTIFYICONDATAW data{sizeof(data)}; data.hWnd = hwnd; data.uID = 1;
        Shell_NotifyIconW(NIM_DELETE, &data);
        if (networkNotification_) CancelMibChangeNotify2(networkNotification_);
        if (trayIcon_) DestroyIcon(trayIcon_);
        if (font_) DeleteObject(font_);
        if (darkBrush_) DeleteObject(darkBrush_);
        if (editBrush_) DeleteObject(editBrush_);
        destroyMonitorBitmap();
        PostQuitMessage(0);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR commandLine, int) {
    HANDLE mutex = CreateMutexW(nullptr, TRUE, L"Local\\HypeLimits.SingleInstance");
    if (!mutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"HypeLimits is already running.", kAppName, MB_OK | MB_ICONINFORMATION);
        if (mutex) CloseHandle(mutex);
        return 0;
    }

    App app;
    if (!app.initialize(instance)) {
        MessageBoxW(nullptr, L"HypeLimits could not initialize its Windows interface.", kAppName, MB_OK | MB_ICONERROR);
        CloseHandle(mutex);
        return 1;
    }
    if (commandLine && wcsstr(commandLine, L"--options")) app.showOptionsWindow();
    const int result = app.run();
    CloseHandle(mutex);
    return result;
}
