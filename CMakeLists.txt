cmake_minimum_required(VERSION 3.21)
project(HypeLimits VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

add_library(hypelimits_core
    src/model.cpp
    src/alert_engine.cpp
    src/provider_parsing.cpp
    src/token_sync.cpp
)
target_include_directories(hypelimits_core PUBLIC src)
target_compile_features(hypelimits_core PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(hypelimits_core PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(hypelimits_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

option(HYPELIMITS_BUILD_APP "Build the native desktop application" ON)
if(HYPELIMITS_BUILD_APP AND WIN32)
    add_executable(hypelimits WIN32 src/native_windows.cpp)
    target_link_libraries(hypelimits PRIVATE hypelimits_core user32 gdi32 comctl32 shell32 advapi32 dwmapi winmm winhttp credui uxtheme iphlpapi ws2_32 bcrypt)
    target_include_directories(hypelimits PRIVATE src)
    target_compile_definitions(hypelimits PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    # Antigravity (Google) OAuth client secret. Never commit this; pass it on the
    # configure line instead, e.g. -DHYPELIMITS_GOOGLE_CLIENT_SECRET=...
    if(HYPELIMITS_GOOGLE_CLIENT_SECRET)
        target_compile_definitions(hypelimits PRIVATE HYPELIMITS_GOOGLE_CLIENT_SECRET="${HYPELIMITS_GOOGLE_CLIENT_SECRET}")
    endif()
    if(MSVC)
        target_compile_options(hypelimits PRIVATE /W4 /permissive- /utf-8)
        target_link_options(hypelimits PRIVATE
            "/MANIFEST:EMBED"
            "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/resources/hypelimits.manifest"
        )
    else()
        target_compile_options(hypelimits PRIVATE -Wall -Wextra -Wpedantic)
        target_sources(hypelimits PRIVATE resources/hypelimits.rc)
    endif()
    install(TARGETS hypelimits RUNTIME DESTINATION .)
elseif(HYPELIMITS_BUILD_APP)
    message(STATUS "The HypeLimits desktop target is Windows 11 only; building portable core tests on this host.")
endif()

if(BUILD_TESTING)
    add_executable(hypelimits_tests tests/test_core.cpp)
    target_link_libraries(hypelimits_tests PRIVATE hypelimits_core)
    add_test(NAME hypelimits_core_tests COMMAND hypelimits_tests)
endif()
