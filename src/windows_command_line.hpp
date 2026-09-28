#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace hypelimits {

inline std::wstring quoteWindowsCommandLineArgument(std::wstring_view value) {
    std::wstring quoted;
    quoted.reserve(value.size() + 2);
    quoted.push_back(L'"');

    std::size_t backslashes = 0;
    for (const wchar_t ch : value) {
        if (ch == L'\\') {
            ++backslashes;
        } else if (ch == L'"') {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted.push_back(ch);
            backslashes = 0;
        } else {
            quoted.append(backslashes, L'\\');
            quoted.push_back(ch);
            backslashes = 0;
        }
    }

    quoted.append(backslashes * 2, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

inline void appendWindowsCommandLineArgument(std::wstring& commandLine, std::wstring_view value) {
    if (!commandLine.empty()) commandLine.push_back(L' ');
    commandLine += quoteWindowsCommandLineArgument(value);
}

inline std::wstring buildWslCatCommandLine(std::wstring_view executable, std::wstring_view distro,
                                           std::wstring_view user, std::wstring_view path) {
    std::wstring commandLine;
    // wsl.exe treats a quoted token such as "-d" as a command for the distro shell, not as its own flag.
    appendWindowsCommandLineArgument(commandLine, executable);
    commandLine += L" -d ";
    commandLine += quoteWindowsCommandLineArgument(distro);
    if (!user.empty()) {
        commandLine += L" -u ";
        commandLine += quoteWindowsCommandLineArgument(user);
    }
    commandLine += L" --exec cat -- ";
    commandLine += quoteWindowsCommandLineArgument(path);
    return commandLine;
}

} // namespace hypelimits
