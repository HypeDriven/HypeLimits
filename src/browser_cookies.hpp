#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace hypelimits {

struct BrowserCookie {
    std::string host;
    std::string name;
    std::string value;
    std::string path{"/"};
    bool secure{true};
    bool httpOnly{false};
};

[[nodiscard]] std::vector<BrowserCookie> loadInstalledBrowserCookies(const std::vector<std::string>& hostSuffixes);
[[nodiscard]] std::string cookieHeaderForHost(const std::vector<BrowserCookie>& cookies, std::string_view host);
void secureClearCookies(std::vector<BrowserCookie>& cookies);

} // namespace hypelimits
