#include "browser_cookies.hpp"

#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A00000C
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlobj.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace hypelimits {
namespace {

struct SqliteApi {
    using Open = int(__cdecl*)(const char*, void**, int, const char*);
    using Close = int(__cdecl*)(void*);
    using Prepare = int(__cdecl*)(void*, const char*, int, void**, const char**);
    using Step = int(__cdecl*)(void*);
    using Finalize = int(__cdecl*)(void*);
    using ColumnText = const unsigned char*(__cdecl*)(void*, int);
    using ColumnBlob = const void*(__cdecl*)(void*, int);
    using ColumnBytes = int(__cdecl*)(void*, int);
    using ColumnInt = int(__cdecl*)(void*, int);
    HMODULE module{};
    Open open{};
    Close close{};
    Prepare prepare{};
    Step step{};
    Finalize finalize{};
    ColumnText columnText{};
    ColumnBlob columnBlob{};
    ColumnBytes columnBytes{};
    ColumnInt columnInt{};
};

SqliteApi loadSqlite() {
    SqliteApi api;
    api.module = LoadLibraryW(L"winsqlite3.dll");
    if (!api.module) return {};
    api.open = reinterpret_cast<SqliteApi::Open>(GetProcAddress(api.module, "sqlite3_open_v2"));
    api.close = reinterpret_cast<SqliteApi::Close>(GetProcAddress(api.module, "sqlite3_close"));
    api.prepare = reinterpret_cast<SqliteApi::Prepare>(GetProcAddress(api.module, "sqlite3_prepare_v2"));
    api.step = reinterpret_cast<SqliteApi::Step>(GetProcAddress(api.module, "sqlite3_step"));
    api.finalize = reinterpret_cast<SqliteApi::Finalize>(GetProcAddress(api.module, "sqlite3_finalize"));
    api.columnText = reinterpret_cast<SqliteApi::ColumnText>(GetProcAddress(api.module, "sqlite3_column_text"));
    api.columnBlob = reinterpret_cast<SqliteApi::ColumnBlob>(GetProcAddress(api.module, "sqlite3_column_blob"));
    api.columnBytes = reinterpret_cast<SqliteApi::ColumnBytes>(GetProcAddress(api.module, "sqlite3_column_bytes"));
    api.columnInt = reinterpret_cast<SqliteApi::ColumnInt>(GetProcAddress(api.module, "sqlite3_column_int"));
    if (!api.open || !api.close || !api.prepare || !api.step || !api.finalize || !api.columnText) {
        FreeLibrary(api.module);
        return {};
    }
    return api;
}

std::wstring knownFolder(REFKNOWNFOLDERID id) {
    PWSTR raw{};
    if (FAILED(SHGetKnownFolderPath(id, 0, nullptr, &raw)) || !raw) return {};
    std::wstring path = raw;
    CoTaskMemFree(raw);
    return path;
}

std::string wideToUtf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), size, nullptr, nullptr);
    return out;
}

bool hostMatches(std::string_view cookieHost, const std::vector<std::string>& suffixes) {
    std::string host{cookieHost};
    if (host.starts_with('.')) host.erase(host.begin());
    for (const auto& suffix : suffixes) {
        if (host == suffix) return true;
        if (host.size() > suffix.size() && host.ends_with(suffix)
            && host[host.size() - suffix.size() - 1] == '.') {
            return true;
        }
    }
    return false;
}

std::vector<unsigned char> base64Decode(std::string_view in) {
    DWORD size = 0;
    if (!CryptStringToBinaryA(in.data(), static_cast<DWORD>(in.size()), CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr)) {
        return {};
    }
    std::vector<unsigned char> out(size);
    if (!CryptStringToBinaryA(in.data(), static_cast<DWORD>(in.size()), CRYPT_STRING_BASE64, out.data(), &size, nullptr, nullptr)) {
        return {};
    }
    out.resize(size);
    return out;
}

std::optional<std::vector<unsigned char>> dpapiUnprotect(const unsigned char* data, std::size_t size) {
    DATA_BLOB input{static_cast<DWORD>(size), const_cast<BYTE*>(data)};
    DATA_BLOB output{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) return std::nullopt;
    std::vector<unsigned char> plain(output.pbData, output.pbData + output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    return plain;
}

std::optional<std::vector<unsigned char>> chromiumKey(const std::wstring& userData) {
    const std::wstring path = userData + L"\\Local State";
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return std::nullopt;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 8 * 1024 * 1024) {
        CloseHandle(file);
        return std::nullopt;
    }
    std::string json(static_cast<std::size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    const BOOL ok = ReadFile(file, json.data(), static_cast<DWORD>(json.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok) return std::nullopt;
    json.resize(read);
    const auto keyPos = json.find("\"encrypted_key\"");
    if (keyPos == std::string::npos) return std::nullopt;
    const auto colon = json.find(':', keyPos);
    const auto quote = json.find('"', colon);
    if (colon == std::string::npos || quote == std::string::npos) return std::nullopt;
    const auto end = json.find('"', quote + 1);
    if (end == std::string::npos) return std::nullopt;
    auto decoded = base64Decode(std::string_view(json).substr(quote + 1, end - quote - 1));
    SecureZeroMemory(json.data(), json.size());
    constexpr char kPrefix[] = "DPAPI";
    if (decoded.size() <= 5 || std::memcmp(decoded.data(), kPrefix, 5) != 0) return std::nullopt;
    auto plain = dpapiUnprotect(decoded.data() + 5, decoded.size() - 5);
    SecureZeroMemory(decoded.data(), decoded.size());
    return plain;
}

std::optional<std::string> decryptChromiumCookie(const std::vector<unsigned char>& key,
                                                 const unsigned char* blob, int blobSize) {
    if (blobSize < 3 + 12 + 16 || !blob) return std::nullopt;
    if (std::memcmp(blob, "v10", 3) != 0 && std::memcmp(blob, "v11", 3) != 0) return std::nullopt;
    const unsigned char* nonce = blob + 3;
    const unsigned char* cipher = blob + 15;
    const int cipherLen = blobSize - 15 - 16;
    if (cipherLen < 0) return std::nullopt;
    const unsigned char* tag = blob + blobSize - 16;

    BCRYPT_ALG_HANDLE alg{};
    BCRYPT_KEY_HANDLE keyHandle{};
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return std::nullopt;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                          static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_GCM)), 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return std::nullopt;
    }
    if (BCryptGenerateSymmetricKey(alg, &keyHandle, nullptr, 0, const_cast<PUCHAR>(key.data()),
                                   static_cast<ULONG>(key.size()), 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return std::nullopt;
    }
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce);
    info.cbNonce = 12;
    info.pbTag = const_cast<PUCHAR>(tag);
    info.cbTag = 16;
    std::string out(static_cast<std::size_t>(cipherLen), '\0');
    ULONG written = 0;
    const NTSTATUS status = BCryptDecrypt(keyHandle, const_cast<PUCHAR>(cipher), static_cast<ULONG>(cipherLen), &info,
                                          nullptr, 0, reinterpret_cast<PUCHAR>(out.data()), static_cast<ULONG>(out.size()),
                                          &written, 0);
    BCryptDestroyKey(keyHandle);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (status != 0) return std::nullopt;
    out.resize(written);
    return out;
}

std::wstring copyToTemp(const std::wstring& src) {
    wchar_t tempPath[MAX_PATH]{};
    wchar_t tempFile[MAX_PATH]{};
    if (GetTempPathW(MAX_PATH, tempPath) == 0) return {};
    if (GetTempFileNameW(tempPath, L"hlc", 0, tempFile) == 0) return {};
    if (!CopyFileW(src.c_str(), tempFile, FALSE)) {
        DeleteFileW(tempFile);
        return {};
    }
    return tempFile;
}

void querySqlite(const SqliteApi& api, const std::string& utf8Path, const char* sql,
                 const std::function<void(void*)>& onRow) {
    void* db{};
    if (api.open(utf8Path.c_str(), &db, 0x00000001 /* SQLITE_OPEN_READONLY */, nullptr) != 0 || !db) {
        if (db) api.close(db);
        return;
    }
    void* stmt{};
    if (api.prepare(db, sql, -1, &stmt, nullptr) == 0 && stmt) {
        while (api.step(stmt) == 100 /* SQLITE_ROW */) onRow(stmt);
        api.finalize(stmt);
    }
    api.close(db);
}

void loadFirefox(const SqliteApi& api, const std::vector<std::string>& suffixes, std::vector<BrowserCookie>& out) {
    const std::wstring roaming = knownFolder(FOLDERID_RoamingAppData);
    if (roaming.empty()) return;
    const std::wstring root = roaming + L"\\Mozilla\\Firefox\\Profiles";
    WIN32_FIND_DATAW find{};
    HANDLE handle = FindFirstFileW((root + L"\\*").c_str(), &find);
    if (handle == INVALID_HANDLE_VALUE) return;
    do {
        if ((find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
        if (find.cFileName[0] == L'.') continue;
        const std::wstring dbPath = root + L"\\" + find.cFileName + L"\\cookies.sqlite";
        if (GetFileAttributesW(dbPath.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        const auto temp = copyToTemp(dbPath);
        if (temp.empty()) continue;
        querySqlite(api, wideToUtf8(temp),
                    "SELECT host, name, value, path, isSecure, isHttpOnly FROM moz_cookies;",
                    [&](void* stmt) {
                        const char* host = reinterpret_cast<const char*>(api.columnText(stmt, 0));
                        const char* name = reinterpret_cast<const char*>(api.columnText(stmt, 1));
                        const char* value = reinterpret_cast<const char*>(api.columnText(stmt, 2));
                        const char* path = reinterpret_cast<const char*>(api.columnText(stmt, 3));
                        if (!host || !name || !value) return;
                        if (!hostMatches(host, suffixes)) return;
                        out.push_back({host, name, value, path ? path : "/", api.columnInt(stmt, 4) != 0,
                                       api.columnInt(stmt, 5) != 0});
                    });
        DeleteFileW(temp.c_str());
    } while (FindNextFileW(handle, &find));
    FindClose(handle);
}

void loadChromiumProfile(const SqliteApi& api, const std::wstring& userData, const std::vector<std::string>& suffixes,
                         std::vector<BrowserCookie>& out) {
    auto key = chromiumKey(userData);
    if (!key || key->size() < 16) return;
    WIN32_FIND_DATAW find{};
    HANDLE handle = FindFirstFileW((userData + L"\\*").c_str(), &find);
    if (handle == INVALID_HANDLE_VALUE) {
        SecureZeroMemory(key->data(), key->size());
        return;
    }
    do {
        if ((find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
        if (find.cFileName[0] == L'.') continue;
        const std::wstring profile = userData + L"\\" + find.cFileName;
        std::wstring dbPath = profile + L"\\Network\\Cookies";
        if (GetFileAttributesW(dbPath.c_str()) == INVALID_FILE_ATTRIBUTES) dbPath = profile + L"\\Cookies";
        if (GetFileAttributesW(dbPath.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        const auto temp = copyToTemp(dbPath);
        if (temp.empty()) continue;
        querySqlite(api, wideToUtf8(temp),
                    "SELECT host_key, name, encrypted_value, path, is_secure, is_httponly FROM cookies;",
                    [&](void* stmt) {
                        const char* host = reinterpret_cast<const char*>(api.columnText(stmt, 0));
                        const char* name = reinterpret_cast<const char*>(api.columnText(stmt, 1));
                        const auto* blob = static_cast<const unsigned char*>(api.columnBlob(stmt, 2));
                        const int blobSize = api.columnBytes ? api.columnBytes(stmt, 2) : 0;
                        const char* path = reinterpret_cast<const char*>(api.columnText(stmt, 3));
                        if (!host || !name || !blob) return;
                        if (!hostMatches(host, suffixes)) return;
                        auto value = decryptChromiumCookie(*key, blob, blobSize);
                        if (!value) return;
                        out.push_back({host, name, *value, path ? path : "/", api.columnInt(stmt, 4) != 0,
                                       api.columnInt(stmt, 5) != 0});
                        SecureZeroMemory(value->data(), value->size());
                    });
        DeleteFileW(temp.c_str());
    } while (FindNextFileW(handle, &find));
    FindClose(handle);
    SecureZeroMemory(key->data(), key->size());
}

} // namespace

std::vector<BrowserCookie> loadInstalledBrowserCookies(const std::vector<std::string>& hostSuffixes) {
    std::vector<BrowserCookie> cookies;
    auto api = loadSqlite();
    if (!api.module) return cookies;
    loadFirefox(api, hostSuffixes, cookies);
    const std::wstring local = knownFolder(FOLDERID_LocalAppData);
    if (!local.empty()) {
        const std::wstring roots[] = {
            local + L"\\Google\\Chrome\\User Data",
            local + L"\\Microsoft\\Edge\\User Data",
            local + L"\\BraveSoftware\\Brave-Browser\\User Data",
            local + L"\\Chromium\\User Data",
        };
        for (const auto& root : roots) {
            if (GetFileAttributesW(root.c_str()) != INVALID_FILE_ATTRIBUTES) loadChromiumProfile(api, root, hostSuffixes, cookies);
        }
    }
    FreeLibrary(api.module);
    return cookies;
}

std::string cookieHeaderForHost(const std::vector<BrowserCookie>& cookies, std::string_view host) {
    std::string header;
    for (const auto& cookie : cookies) {
        std::string domain = cookie.host;
        if (domain.starts_with('.')) domain.erase(domain.begin());
        const bool match = host == domain
            || (host.size() > domain.size() && host.ends_with(domain)
                && host[host.size() - domain.size() - 1] == '.');
        if (!match) continue;
        if (!header.empty()) header += "; ";
        header += cookie.name;
        header += '=';
        header += cookie.value;
    }
    return header;
}

void secureClearCookies(std::vector<BrowserCookie>& cookies) {
    for (auto& cookie : cookies) {
        if (!cookie.value.empty()) SecureZeroMemory(cookie.value.data(), cookie.value.size());
        cookie = {};
    }
    cookies.clear();
}

} // namespace hypelimits
