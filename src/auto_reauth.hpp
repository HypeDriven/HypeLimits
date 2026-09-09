#pragma once

#include "browser_cookies.hpp"

#include <string>
#include <windows.h>

namespace hypelimits {

struct WebViewOAuthResult {
    std::wstring url;
    std::wstring pageText;
    bool ok{false};
};

WebViewOAuthResult runWebViewOAuth(HWND parent, const std::wstring& startUrl, const std::wstring& userDataFolder,
                                   const std::vector<BrowserCookie>& cookies, DWORD timeoutMs);

} // namespace hypelimits
