#pragma once

#include <windows.h>
#include <unknwn.h>

using EventRegistrationToken = __int64;

MIDL_INTERFACE("76ECEACB-0462-4D94-AC83-423A6793775E")
ICoreWebView2 : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE get_Settings(IUnknown** settings) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_Source(LPWSTR* uri) = 0;
    virtual HRESULT STDMETHODCALLTYPE Navigate(LPCWSTR uri) = 0;
    virtual HRESULT STDMETHODCALLTYPE NavigateToString(LPCWSTR html) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_NavigationStarting(IUnknown* handler, EventRegistrationToken* token) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_NavigationStarting(EventRegistrationToken token) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_ContentLoading(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_ContentLoading(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_SourceChanged(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_SourceChanged(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_HistoryChanged(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_HistoryChanged(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_NavigationCompleted(IUnknown* handler, EventRegistrationToken* token) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_NavigationCompleted(EventRegistrationToken token) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_FrameNavigationStarting(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_FrameNavigationStarting(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_FrameNavigationCompleted(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_FrameNavigationCompleted(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_ScriptDialogOpening(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_ScriptDialogOpening(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_PermissionRequested(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_PermissionRequested(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_ProcessFailed(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_ProcessFailed(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE AddScriptToExecuteOnDocumentCreated(LPCWSTR, IUnknown*) = 0;
    virtual HRESULT STDMETHODCALLTYPE RemoveScriptToExecuteOnDocumentCreated(LPCWSTR) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExecuteScript(LPCWSTR javaScript, IUnknown* handler) = 0;
};

MIDL_INTERFACE("4D00C0D1-9434-4EB6-8078-8697A560334F")
ICoreWebView2Controller : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE get_IsVisible(BOOL* value) = 0;
    virtual HRESULT STDMETHODCALLTYPE put_IsVisible(BOOL value) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_Bounds(RECT* bounds) = 0;
    virtual HRESULT STDMETHODCALLTYPE put_Bounds(RECT bounds) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_ZoomFactor(double*) = 0;
    virtual HRESULT STDMETHODCALLTYPE put_ZoomFactor(double) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_ZoomFactorChanged(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_ZoomFactorChanged(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetBoundsAndZoomFactor(RECT, double) = 0;
    virtual HRESULT STDMETHODCALLTYPE MoveFocus(int) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_MoveFocusRequested(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_MoveFocusRequested(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_GotFocus(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_GotFocus(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_LostFocus(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_LostFocus(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_AcceleratorKeyPressed(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_AcceleratorKeyPressed(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_ParentWindow(HWND*) = 0;
    virtual HRESULT STDMETHODCALLTYPE put_ParentWindow(HWND) = 0;
    virtual HRESULT STDMETHODCALLTYPE NotifyParentWindowPositionChanged() = 0;
    virtual HRESULT STDMETHODCALLTYPE Close() = 0;
    virtual HRESULT STDMETHODCALLTYPE get_CoreWebView2(ICoreWebView2** webview) = 0;
};

MIDL_INTERFACE("B96D755E-0319-4E92-A296-23436F46A1FC")
ICoreWebView2Environment : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE CreateCoreWebView2Controller(HWND parentWindow, IUnknown* handler) = 0;
};

MIDL_INTERFACE("5B495469-E119-438A-9B18-7604F25F2E49")
ICoreWebView2NavigationStartingEventArgs : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE get_Uri(LPWSTR* uri) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_IsUserInitiated(BOOL*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_IsRedirected(BOOL*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_RequestHeaders(IUnknown**) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_Cancel(BOOL*) = 0;
    virtual HRESULT STDMETHODCALLTYPE put_Cancel(BOOL) = 0;
};

MIDL_INTERFACE("9E8F0CF8-E670-4B5E-B2BC-73E061E3184C")
ICoreWebView2_2 : public ICoreWebView2 {
    virtual HRESULT STDMETHODCALLTYPE add_WebResourceResponseReceived(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_WebResourceResponseReceived(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE NavigateWithWebResourceRequest(IUnknown*) = 0;
    virtual HRESULT STDMETHODCALLTYPE add_DOMContentLoaded(IUnknown*, EventRegistrationToken*) = 0;
    virtual HRESULT STDMETHODCALLTYPE remove_DOMContentLoaded(EventRegistrationToken) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_CookieManager(IUnknown** cookieManager) = 0;
};

MIDL_INTERFACE("177CD9E7-B6F5-451A-94A0-5D7A3A4C4141")
ICoreWebView2CookieManager : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE CreateCookie(LPCWSTR name, LPCWSTR value, LPCWSTR domain, LPCWSTR path,
                                                   IUnknown** cookie) = 0;
    virtual HRESULT STDMETHODCALLTYPE CopyCookie(IUnknown*, IUnknown**) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetCookies(LPCWSTR uri, IUnknown* handler) = 0;
    virtual HRESULT STDMETHODCALLTYPE AddOrUpdateCookie(IUnknown* cookie) = 0;
};

MIDL_INTERFACE("03F92659-3D9A-4C3F-A314-B785C5F1522B")
ICoreWebView2Cookie : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE get_Name(LPWSTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_Value(LPWSTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE put_Value(LPCWSTR) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_Domain(LPWSTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_Path(LPWSTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_Expires(double*) = 0;
    virtual HRESULT STDMETHODCALLTYPE put_Expires(double) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_IsHttpOnly(BOOL*) = 0;
    virtual HRESULT STDMETHODCALLTYPE put_IsHttpOnly(BOOL) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_SameSite(int*) = 0;
    virtual HRESULT STDMETHODCALLTYPE put_SameSite(int) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_IsSecure(BOOL*) = 0;
    virtual HRESULT STDMETHODCALLTYPE put_IsSecure(BOOL value) = 0;
};

using CreateCoreWebView2EnvironmentWithOptionsFn = HRESULT(STDMETHODCALLTYPE*)(
    PCWSTR browserExecutableFolder, PCWSTR userDataFolder, IUnknown* environmentOptions, IUnknown* handler);
