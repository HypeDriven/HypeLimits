#pragma once

#include "windows_command_line.hpp"

#include <cstddef>
#include <cwctype>
#include <string>
#include <string_view>

namespace hypelimits {

inline bool browserExecutableEquals(std::wstring_view left, std::wstring_view right) {
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0; i < left.size(); ++i) {
        if (std::towlower(left[i]) != std::towlower(right[i])) return false;
    }
    return true;
}

inline bool isSupportedBrowserExecutable(std::wstring_view executable) {
    const auto slash = executable.find_last_of(L"\\/");
    const auto name = slash == std::wstring_view::npos ? executable : executable.substr(slash + 1);
    for (const std::wstring_view browser : {
             L"arc.exe", L"brave.exe", L"chrome.exe", L"chromium.exe", L"firefox.exe", L"floorp.exe",
             L"iexplore.exe", L"librewolf.exe", L"msedge.exe", L"opera.exe", L"opera_gx.exe",
             L"vivaldi.exe", L"waterfox.exe", L"zen.exe",
         }) {
        if (browserExecutableEquals(name, browser)) return true;
    }
    return false;
}

class FocusedBrowserCache {
public:
    void remember(std::wstring_view executable) {
        if (isSupportedBrowserExecutable(executable)) executable_ = executable;
    }

    [[nodiscard]] bool empty() const {
        return executable_.empty();
    }

    [[nodiscard]] const std::wstring& executable() const {
        return executable_;
    }

    void clear() {
        executable_.clear();
    }

private:
    std::wstring executable_;
};

inline std::wstring buildBrowserUrlCommandLine(std::wstring_view executable, std::wstring_view url) {
    std::wstring commandLine;
    appendWindowsCommandLineArgument(commandLine, executable);
    appendWindowsCommandLineArgument(commandLine, url);
    return commandLine;
}

} // namespace hypelimits
