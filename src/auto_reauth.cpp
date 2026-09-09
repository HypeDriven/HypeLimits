#include "auto_reauth.hpp"
#include "webview2_min.h"

#include <objbase.h>
#include <shlobj.h>

#include <algorithm>
#include <functional>
#include <string>
#include <vector>

namespace hypelimits {
namespace {

constexpr IID kEnvHandlerIid{0x4E8A3389, 0xC9D8, 0x4BD2, {0xB6, 0xB5, 0x12, 0x4F, 0xEE, 0x6C, 0xC1, 0x4D}};
constexpr IID kControllerHandlerIid{0x6C4819F3, 0xC9B7, 0x4260, {0x81, 0x27, 0xC9, 0xF5, 0xBD, 0xE7, 0xF6, 0x8C}};
constexpr IID kNavigationStartingHandlerIid{0x9ADBE429, 0xF36D, 0x432B, {0x9D, 0xDC, 0xF8, 0x88, 0x1F, 0xBD, 0x76, 0xE3}};
constexpr IID kExecuteScriptHandlerIid{0x49511172, 0xCC67, 0x4BCA, {0x99, 0x23, 0x13, 0x71, 0x12, 0xF4, 0xC4, 0xCC}};

std::wstring utf16(std::string_view value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), size);
    return out;
}

std::string utf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), size, nullptr, nullptr);
    return out;
}

struct EnvCompletedHandler : IUnknown {
    LONG refs{1};
    std::function<HRESULT(HRESULT, ICoreWebView2Environment*)> fn;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == kEnvHandlerIid) {
            *ppv = this;
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG n = InterlockedDecrement(&refs);
        if (!n) delete this;
        return n;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT result, ICoreWebView2Environment* env) { return fn(result, env); }
};

struct ControllerCompletedHandler : IUnknown {
    LONG refs{1};
    std::function<HRESULT(HRESULT, ICoreWebView2Controller*)> fn;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == kControllerHandlerIid) {
            *ppv = this;
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG n = InterlockedDecrement(&refs);
        if (!n) delete this;
        return n;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT result, ICoreWebView2Controller* controller) { return fn(result, controller); }
};

struct NavigationStartingHandler : IUnknown {
    LONG refs{1};
    std::function<HRESULT(ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs*)> fn;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == kNavigationStartingHandlerIid) {
            *ppv = this;
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG n = InterlockedDecrement(&refs);
        if (!n) delete this;
        return n;
    }
    HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2* sender, ICoreWebView2NavigationStartingEventArgs* args) {
        return fn(sender, args);
    }
};

struct ExecuteScriptHandler : IUnknown {
    LONG refs{1};
    std::function<HRESULT(HRESULT, LPCWSTR)> fn;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == kExecuteScriptHandlerIid) {
            *ppv = this;
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs); }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG n = InterlockedDecrement(&refs);
        if (!n) delete this;
        return n;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT errorCode, LPCWSTR result) { return fn(errorCode, result); }
};

CreateCoreWebView2EnvironmentWithOptionsFn loadWebView2Create() {
    HMODULE module = LoadLibraryW(L"WebView2Loader.dll");
    if (!module) {
        wchar_t exe[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        std::wstring dir{exe};
        if (const auto slash = dir.find_last_of(L"\\/"); slash != std::wstring::npos) dir.resize(slash + 1);
        module = LoadLibraryW((dir + L"WebView2Loader.dll").c_str());
    }
    if (!module) return nullptr;
    return reinterpret_cast<CreateCoreWebView2EnvironmentWithOptionsFn>(
        GetProcAddress(module, "CreateCoreWebView2EnvironmentWithOptions"));
}

void pumpUntil(DWORD timeoutMs, const std::function<bool()>& done) {
    const DWORD start = GetTickCount();
    while (!done() && GetTickCount() - start < timeoutMs) {
        MSG msg{};
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                PostQuitMessage(static_cast<int>(msg.wParam));
                return;
            }
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        MsgWaitForMultipleObjects(0, nullptr, FALSE, 100, QS_ALLINPUT);
    }
}

void injectCookies(ICoreWebView2* webview, const std::vector<BrowserCookie>& cookies) {
    ICoreWebView2_2* web2{};
    if (FAILED(webview->QueryInterface(__uuidof(ICoreWebView2_2), reinterpret_cast<void**>(&web2))) || !web2) return;
    IUnknown* managerUnk{};
    if (FAILED(web2->get_CookieManager(&managerUnk)) || !managerUnk) {
        web2->Release();
        return;
    }
    auto* manager = reinterpret_cast<ICoreWebView2CookieManager*>(managerUnk);
    for (const auto& cookie : cookies) {
        IUnknown* created{};
        if (FAILED(manager->CreateCookie(utf16(cookie.name).c_str(), utf16(cookie.value).c_str(),
                                         utf16(cookie.host).c_str(), utf16(cookie.path).c_str(), &created))
            || !created) {
            continue;
        }
        manager->AddOrUpdateCookie(created);
        created->Release();
    }
    managerUnk->Release();
    web2->Release();
}

constexpr wchar_t kPageTextScript[] = L"document.body ? document.body.innerText : ''";

} // namespace

WebViewOAuthResult runWebViewOAuth(HWND parent, const std::wstring& startUrl, const std::wstring& userDataFolder,
                                   const std::vector<BrowserCookie>& cookies, DWORD timeoutMs) {
    WebViewOAuthResult result;
    auto create = loadWebView2Create();
    if (!create) return result;

    HWND hwnd = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, L"Static", L"",
                                WS_POPUP, -32000, -32000, 8, 8, parent, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!hwnd) return result;

    ICoreWebView2Controller* controller{};
    ICoreWebView2* webview{};
    bool ready = false;
    bool failed = false;

    auto* envHandler = new EnvCompletedHandler();
    envHandler->fn = [&](HRESULT hr, ICoreWebView2Environment* env) -> HRESULT {
        if (FAILED(hr) || !env) {
            failed = true;
            return S_OK;
        }
        auto* controllerHandler = new ControllerCompletedHandler();
        controllerHandler->fn = [&](HRESULT chr, ICoreWebView2Controller* created) -> HRESULT {
            if (FAILED(chr) || !created) {
                failed = true;
                return S_OK;
            }
            controller = created;
            controller->AddRef();
            controller->put_IsVisible(FALSE);
            controller->get_CoreWebView2(&webview);
            controller->put_Bounds(RECT{0, 0, 800, 600});
            if (webview) {
                injectCookies(webview, cookies);
                auto* nav = new NavigationStartingHandler();
                nav->fn = [&](ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs* args) -> HRESULT {
                    if (!args) return S_OK;
                    LPWSTR uri{};
                    if (SUCCEEDED(args->get_Uri(&uri)) && uri) {
                        result.url = uri;
                        CoTaskMemFree(uri);
                    }
                    return S_OK;
                };
                EventRegistrationToken token{};
                webview->add_NavigationStarting(nav, &token);
                nav->Release();
                webview->Navigate(startUrl.c_str());
            }
            ready = true;
            return S_OK;
        };
        env->CreateCoreWebView2Controller(hwnd, controllerHandler);
        controllerHandler->Release();
        return S_OK;
    };

    const HRESULT created = create(nullptr, userDataFolder.empty() ? nullptr : userDataFolder.c_str(), nullptr, envHandler);
    envHandler->Release();
    if (FAILED(created)) {
        DestroyWindow(hwnd);
        return result;
    }

    pumpUntil(15000, [&] { return ready || failed; });
    if (!ready || !webview) {
        if (controller) {
            controller->Close();
            controller->Release();
        }
        DestroyWindow(hwnd);
        return result;
    }

    DWORD lastScript = 0;
    pumpUntil(timeoutMs, [&] {
        LPWSTR uri{};
        if (SUCCEEDED(webview->get_Source(&uri)) && uri) {
            result.url = uri;
            CoTaskMemFree(uri);
        }
        const DWORD now = GetTickCount();
        if (now - lastScript > 1200) {
            lastScript = now;
            auto* text = new ExecuteScriptHandler();
            text->fn = [&](HRESULT, LPCWSTR json) -> HRESULT {
                if (json) result.pageText = json;
                return S_OK;
            };
            webview->ExecuteScript(kPageTextScript, text);
            text->Release();
        }
        const auto url8 = utf8(result.url);
        const auto page8 = utf8(result.pageText);
        if (url8.find("code=") != std::string::npos || page8.find("code=") != std::string::npos) return true;
        if (url8.find('#') != std::string::npos && url8.find("code") != std::string::npos) return true;
        return false;
    });

    result.ok = !result.url.empty() || !result.pageText.empty();
    if (controller) {
        controller->Close();
        controller->Release();
    }
    if (webview) webview->Release();
    DestroyWindow(hwnd);
    return result;
}

} // namespace hypelimits
