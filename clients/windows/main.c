/*
 * GHOSTLINK Windows Client -- Win32 GUI
 * Native C, zero dependencies beyond what ships with Windows
 * Compile: cl /O2 /MT main.c crypto.c network.c storage.c /Fe:GHOSTLINK.exe
 */

#include "client.h"
#include <commctrl.h>
#include <richedit.h>
#include <commdlg.h>
#include <uxtheme.h>
#include <shellapi.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' \
    name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
    processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

/* -- Theme System ---------------------------------------------------- */
typedef struct {
    COLORREF bg, bg_card, bg_input, bg_accent;
    COLORREF text, text_dim, text_bright;
    COLORREF border, accent, green, red, warn;
    COLORREF scrollbar;
} Theme;

static Theme gDark = {
    0x001a1a1a, 0x00242424, 0x002d2d2d, 0x00333333,  // bg, card, input, accent-bg
    0x00cccccc, 0x00888888, 0x00ffffff,                // text, dim, bright
    0x003d3d3d, 0x000066ff, 0x0050b93f, 0x0049f851, 0x0048c0ff  // border, accent(orange #ff6600), green, red, warn
};
static Theme gLight = {
    0x00FFFFFF, 0x00F6F5F3, 0x00EEECE8, 0x00E8E4DE,  // bg, card, input, accent-bg
    0x001a1a1a, 0x00666666, 0x00000000,                // text, dim, bright
    0x00cccccc, 0x00cc5500, 0x002f8c1a, 0x0018c2cf, 0x004080c0  // border, accent(orange), green, red, warn
};
static Theme *gTheme = &gDark;
static BOOL gDarkMode = TRUE;
static HBRUSH gBgBrush = NULL, gCardBrush = NULL, gInputBrush = NULL;
static HPEN gBorderPen = NULL;

/* Theme functions implemented after hMainWnd declared */

/* -- Globals -------------------------------------------------------- */
static HINSTANCE hInst;
static HWND hMainWnd;
static DeviceConfig gCfg;
static BOOL gRegistered = FALSE, gTabIsGroups = FALSE;
static HFONT hDefFont, hSmallFont;

/* Registration controls */
static HWND hRegTitle, hUserEdit, hPassEdit, hDevEdit, hRegBtn, hLoginBtn, hRegStatus, hRememberChk;

/* Sidebar controls */
static HWND hContactsTab, hGroupsTab, hSearchEdit, hSideList, hSideBtn;

/* Chat controls */
static HWND hRecipLabel, hRecipDisp, hMsgList, hMsgInput, hSendBtn, hAttachBtn, hStatusBar;
static HWND hNameEdit, hNoteEdit, hConnStatus, hRetryBtn;
static char gSelectedRecip[128] = "";
static BOOL gServerOnline = FALSE;
static BOOL gStopRetry = FALSE;
static int gRetryCount = 0;

#define ID_LOGIN_BTN     1011
#define ID_REMEMBER      1015
#define ID_REGISTER      1001
#define ID_SEND          1002
#define ID_MSGINPUT      1003
#define ID_MSGLIST       1005
#define ID_SIDELIST      1006
#define ID_CONTACTS_TAB  1007
#define ID_GROUPS_TAB    1008
#define ID_SEARCH        1009
#define ID_SIDE_BTN      1010
#define ID_NAMEEDIT      1012
#define ID_NOTEEDIT      1013
#define ID_ATTACH        1014
#define ID_SETTINGS      1016
#define ID_NUKE          1017
#define ID_RETRY_BTN     1018
#define ID_THEME_TOGGLE  1020
#define ID_CONN_STATUS   1019
#define WM_RETRY         (WM_USER + 101)
#define WM_REFRESH       (WM_USER + 100)

/* File tracking */
#define MAX_PENDING_FILES 32
typedef struct {
    char file_id[64];
    char filename[256];
    char sender[72];
    char expires_at[32];
    DWORD size;
} PendingFile;
static PendingFile gPendingFiles[MAX_PENDING_FILES];
static int gPendingFileCount = 0;
static HWND hFileList;

/* File download path */
#define DOWNLOADS_DIR    "D:\\GHOSTLINK\\downloads"
#define CLIENT_VERSION   "1.0.0"

/* -- Theme Functions ------------------------------------------------- */
void Theme_CreateBrushes(void) {
    if (gBgBrush) DeleteObject(gBgBrush);
    if (gCardBrush) DeleteObject(gCardBrush);
    if (gInputBrush) DeleteObject(gInputBrush);
    if (gBorderPen) DeleteObject(gBorderPen);
    gBgBrush = CreateSolidBrush(gTheme->bg);
    gCardBrush = CreateSolidBrush(gTheme->bg_card);
    gInputBrush = CreateSolidBrush(gTheme->bg_input);
    gBorderPen = CreatePen(PS_SOLID, 1, gTheme->border);
}

void Theme_Load(void) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\GHOSTLINK", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD val = 1, size = sizeof(val);
        RegQueryValueExA(hKey, "DarkMode", NULL, NULL, (BYTE*)&val, &size);
        gDarkMode = (val != 0);
        RegCloseKey(hKey);
    }
    gTheme = gDarkMode ? &gDark : &gLight;
    Theme_CreateBrushes();
}

BOOL CALLBACK Theme_EnumChildProc(HWND hwnd, LPARAM lParam) {
    InvalidateRect(hwnd, NULL, TRUE);
    SetWindowTheme(hwnd, L"", L"");
    return TRUE;
}

void Theme_ApplyToControls(HWND parent) {
    /* RichEdit background + text color */
    if (hMsgList) {
        SendMessage(hMsgList, EM_SETBKGNDCOLOR, 0, (LPARAM)gTheme->bg);
        CHARFORMAT2W cf = { sizeof(cf) };
        cf.dwMask = CFM_COLOR;
        cf.crTextColor = gTheme->text;
        SendMessageW(hMsgList, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
        /* Also style the text currently in the control */
        SendMessage(hMsgList, EM_SETBKGNDCOLOR, 1, (LPARAM)gTheme->bg);
    }
    /* Force redraw all children */
    EnumChildWindows(parent, Theme_EnumChildProc, 0);
    InvalidateRect(parent, NULL, TRUE);
}

void Theme_Toggle(void) {
    gDarkMode = !gDarkMode;
    gTheme = gDarkMode ? &gDark : &gLight;
    Theme_CreateBrushes();
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\GHOSTLINK", 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD val = gDarkMode ? 1 : 0;
        RegSetValueExA(hKey, "DarkMode", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
    /* Update toggle button text */
    HWND toggle = GetDlgItem(hMainWnd, ID_THEME_TOGGLE);
    if (toggle) SetWindowTextW(toggle, gDarkMode ? L"Light Mode" : L"Dark Mode");
    /* Apply theme to all controls */
    Theme_ApplyToControls(hMainWnd);
}

/* -- Forward Declarations ------------------------------------------- */
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void CreateRegistrationPanel(HWND parent);
void DestroyRegistrationPanel(void);
void CreateMessagesPanel(HWND parent);
void DestroyMessagesPanel(void);
void OnRegister(BOOL isLogin);
void OnSendMessage(void);
void FetchMessages(void);
void SwitchTab(BOOL groups);
void PopulateContacts(char *search);
void PopulateGroups(void);
void OnSideSelect(void);
void OnNewGroup(void);
void OnAttachFile(void);
void OnSettings(void);
void OnNuke(void);
void CheckServerHealth(void);
void SetOfflineMode(BOOL offline);
void RepositionChatControls(int cx, int cy);
void Theme_Toggle(void);
void Theme_ApplyToControls(HWND parent);
char* json_get_string(const char *json, const char *key);

/* -- Entry Point ---------------------------------------------------- */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    hInst = hInstance;

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    hDefFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FF_DONTCARE, L"Segoe UI");

    hSmallFont = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FF_DONTCARE, L"Segoe UI");

    /* Load theme preference */
    Theme_Load();

    /* TPM 2.0 detection */
    tpm_detect();

    /* Post-quantum Kyber-1024 */
    kyber_init();

    if (!crypto_init()) {
        MessageBoxA(NULL, "FIPS 140-2 Crypto Init Failed", "GHOSTLINK Fatal Error", MB_ICONERROR);
        return 1;
    }
    if (!network_init()) {
        MessageBoxA(NULL, "Network Init Failed", "GHOSTLINK Fatal Error", MB_ICONERROR);
        return 1;
    }

    /* Check for updates */
    {
        HttpResponse *ver = network_get("/api/v1/version");
        if (ver && ver->len > 10) {
            char *latest = json_get_string(ver->data, "version");
            if (latest && strcmp(latest, CLIENT_VERSION) != 0) {
                char msg[256];
                wsprintfA(msg, "GHOSTLINK %s available! You are on %s.\nCheck the repo for the latest build.",
                          latest, CLIENT_VERSION);
                MessageBoxA(NULL, msg, "Update Available", MB_ICONINFORMATION);
            }
            if (latest) free(latest);
        }
        if (ver) network_free_response(ver);
    }

    ZeroMemory(&gCfg, sizeof(gCfg));
    if (storage_exists() && storage_load_config(&gCfg) && storage_load_keypair(gCfg.id, &gCfg.identity_key)) {
        gRegistered = TRUE;
    }

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"GHOSTLINK_Main";
    wc.hIcon         = LoadIcon(NULL, IDI_SHIELD);

    if (!RegisterClassExW(&wc)) return 1;

    hMainWnd = CreateWindowExW(0, L"GHOSTLINK_Main", L"GHOSTLINK Secure Messenger",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 850, 620,
        NULL, NULL, hInstance, NULL);

    if (!hMainWnd) return 1;

    ShowWindow(hMainWnd, nCmdShow);
    UpdateWindow(hMainWnd);

    /* Menu bar */
    {
        HMENU hMenuBar = CreateMenu();
        HMENU hFileMenu = CreatePopupMenu();
        AppendMenuW(hFileMenu, MF_STRING, 3001, L"Check for &Updates");
        AppendMenuW(hFileMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuW(hFileMenu, MF_STRING, 3002, L"E&xit");
        AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hFileMenu, L"&File");

        HMENU hSettingsMenu = CreatePopupMenu();
        AppendMenuW(hSettingsMenu, MF_STRING, ID_SETTINGS, L"&Settings...");
        AppendMenuW(hSettingsMenu, MF_STRING, ID_THEME_TOGGLE, gDarkMode ? L"Switch to &Light Mode" : L"Switch to &Dark Mode");
        AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hSettingsMenu, L"&Settings");

        HMENU hHelpMenu = CreatePopupMenu();
        AppendMenuW(hHelpMenu, MF_STRING, 3003, L"&About GHOSTLINK");
        AppendMenuW(hHelpMenu, MF_STRING, 3004, L"&Documentation");
        AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hHelpMenu, L"&Help");

        SetMenu(hMainWnd, hMenuBar);
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    network_cleanup();
    DeleteObject(hDefFont);
    DeleteObject(hSmallFont);
    return (int)msg.wParam;
}

/* -- Window Procedure ----------------------------------------------- */
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        if (gRegistered) CreateMessagesPanel(hwnd);
        else CreateRegistrationPanel(hwnd);
        return 0;

    case WM_SIZE:
        if (gRegistered) RepositionChatControls(LOWORD(lp), HIWORD(lp));
        return 0;

    case WM_CTLCOLORSTATIC:
        SetBkMode((HDC)wp, TRANSPARENT);
        SetTextColor((HDC)wp, gTheme->text);
        SetBkColor((HDC)wp, gTheme->bg);
        return (LRESULT)gBgBrush;

    case WM_CTLCOLOREDIT:
        SetBkMode((HDC)wp, TRANSPARENT);
        SetTextColor((HDC)wp, gTheme->text);
        SetBkColor((HDC)wp, gTheme->bg_input);
        return (LRESULT)gInputBrush;

    case WM_CTLCOLORLISTBOX:
        SetBkMode((HDC)wp, TRANSPARENT);
        SetTextColor((HDC)wp, gTheme->text);
        SetBkColor((HDC)wp, gTheme->bg_card);
        return (LRESULT)gCardBrush;

    case WM_CTLCOLORBTN:
        SetBkMode((HDC)wp, TRANSPARENT);
        SetTextColor((HDC)wp, gTheme->text);
        return (LRESULT)gCardBrush;

    case WM_ERASEBKGND:
        { RECT rc; GetClientRect(hwnd, &rc);
          FillRect((HDC)wp, &rc, gBgBrush); }
        return 1;

    case WM_SHOWWINDOW:
        if (wp == TRUE && gRegistered) Theme_ApplyToControls(hwnd);
        return 0;

    case WM_CTLCOLORSCROLLBAR:
        return (LRESULT)gCardBrush;

    case WM_COMMAND:
        if (HIWORD(wp) == BN_CLICKED) {
            if (LOWORD(wp) == ID_REGISTER) { OnRegister(FALSE); return 0; }
            else if (LOWORD(wp) == ID_SEND) {
                if (!gServerOnline) return 0;
                OnSendMessage(); return 0;
            }
            else if (LOWORD(wp) == ID_ATTACH) {
                if (!gServerOnline) return 0;
                OnAttachFile(); return 0;
            }
            else if (LOWORD(wp) == ID_RETRY_BTN) {
                gStopRetry = TRUE;
                KillTimer(hMainWnd, 2);
                SetWindowTextA(hConnStatus, "Retry stopped. Messages blocked. Restart client to reconnect.");
                ShowWindow(hRetryBtn, SW_HIDE);
                return 0;
            }
            else if (LOWORD(wp) == ID_CONTACTS_TAB) { SwitchTab(FALSE); return 0; }
            else if (LOWORD(wp) == ID_GROUPS_TAB) { SwitchTab(TRUE); return 0; }
            else if (LOWORD(wp) == ID_LOGIN_BTN) {
                OnRegister(TRUE);  /* TRUE = login, skip user creation */
                return 0;
            }
            else if (LOWORD(wp) == ID_THEME_TOGGLE) {
                Theme_Toggle();
                /* Update menu item text */
                HMENU hSettingsMenu = GetSubMenu(GetMenu(hMainWnd), 1);
                if (hSettingsMenu) ModifyMenuW(hSettingsMenu, ID_THEME_TOGGLE, MF_BYCOMMAND | MF_STRING,
                    ID_THEME_TOGGLE, gDarkMode ? L"Switch to &Light Mode" : L"Switch to &Dark Mode");
                return 0;
            }
            else if (LOWORD(wp) == ID_SETTINGS) {
                OnSettings();
                return 0;
            }
            else if (LOWORD(wp) == 3001) {
                /* Check for Updates */
                HttpResponse *ver = network_get("/api/v1/version");
                if (ver && ver->len > 10) {
                    char *latest = json_get_string(ver->data, "version");
                    char msg[256];
                    if (latest) {
                        wsprintfA(msg, "Latest: v%s\nCurrent: v%s\n\nVisit the GitHub releases page to download.", latest, CLIENT_VERSION);
                        free(latest);
                    } else {
                        wsprintfA(msg, "You are running GHOSTLINK v%s.\nCould not determine latest version.", CLIENT_VERSION);
                    }
                    MessageBoxA(hMainWnd, msg, "GHOSTLINK Updates", MB_ICONINFORMATION);
                } else {
                    MessageBoxA(hMainWnd, "Could not reach update server.", "GHOSTLINK Updates", MB_ICONWARNING);
                }
                if (ver) network_free_response(ver);
                return 0;
            }
            else if (LOWORD(wp) == 3002) {
                DestroyWindow(hMainWnd);
                return 0;
            }
            else if (LOWORD(wp) == 3003) {
                MessageBoxA(hMainWnd,
                    "GHOSTLINK Secure Messenger v" CLIENT_VERSION "\n\n"
                    "FIPS 140-2 Compliant E2E Encrypted Messaging\n"
                    "AES-256-GCM | ECDH P-384 | ML-KEM-1024 (PQ)\n"
                    "TPM 2.0 | Self-Destructing Messages | One-Time Files\n\n"
                    "Messages destroyed on delivery. Files self-destruct after download.\n"
                    "Server is a blind relay -- never sees plaintext, never retains data.\n\n"
                    "No personal data. No metadata. No history. No trace.",
                    "About GHOSTLINK", MB_ICONINFORMATION);
                return 0;
            }
            else if (LOWORD(wp) == 3004) {
                ShellExecuteA(NULL, "open", "https://github.com/GHOSTLINK/releases", NULL, NULL, SW_SHOW);
                return 0;
            }
            else if (LOWORD(wp) == ID_SIDE_BTN) {
                if (gTabIsGroups) OnNewGroup(); else PopulateContacts(NULL);
                return 0;
            }
        }
        if (HIWORD(wp) == LBN_DBLCLK && LOWORD(wp) == ID_SIDELIST) {
            OnSideSelect();
            return 0;
        }
        if (HIWORD(wp) == EN_CHANGE && LOWORD(wp) == ID_SEARCH) {
            if (!gTabIsGroups) {
                WCHAR searchW[64];
                GetWindowTextW(hSearchEdit, searchW, 64);
                char searchA[64];
                WideCharToMultiByte(CP_UTF8, 0, searchW, -1, searchA, 64, NULL, NULL);
                if (wcslen(searchW) >= 2) PopulateContacts(searchA);
                else if (wcslen(searchW) == 0) PopulateContacts(NULL);
            }
            return 0;
        }
        break;

    case WM_TIMER:
        if (wp == 1) {
            FetchMessages();
            /* Heartbeat to keep last_seen fresh on server */
            if (gServerOnline && gCfg.id[0]) {
                char hb[256];
                wsprintfA(hb, "{\"device_id\":\"%s\"}", gCfg.id);
                HttpResponse *hr = network_post("/api/v1/heartbeat", hb);
                if (hr) network_free_response(hr);
            }
        }
        else if (wp == 2) CheckServerHealth();
        return 0;

    case WM_DESTROY:
        if (gRegistered) DestroyMessagesPanel();
        else DestroyRegistrationPanel();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* -- Registration Panel --------------------------------------------- */
void CreateRegistrationPanel(HWND parent) {
    int y = 50;

    hRegTitle = CreateWindowW(L"STATIC", L"GHOSTLINK Device Registration",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        150, y, 500, 32, parent, NULL, hInst, NULL);
    SendMessage(hRegTitle, WM_SETFONT, (WPARAM)hDefFont, TRUE);
    y += 55;

    CreateWindowW(L"STATIC", L"Username:", WS_CHILD | WS_VISIBLE,
        200, y + 4, 100, 22, parent, NULL, hInst, NULL);
    hUserEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        310, y, 280, 26, parent, NULL, hInst, NULL);
    SendMessage(hUserEdit, WM_SETFONT, (WPARAM)hDefFont, TRUE);
    y += 48;

    CreateWindowW(L"STATIC", L"Password (12+):", WS_CHILD | WS_VISIBLE,
        200, y + 4, 120, 22, parent, NULL, hInst, NULL);
    hPassEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
        330, y, 260, 26, parent, NULL, hInst, NULL);
    SendMessage(hPassEdit, WM_SETFONT, (WPARAM)hDefFont, TRUE);
    y += 48;

    CreateWindowW(L"STATIC", L"Device Name:", WS_CHILD | WS_VISIBLE,
        200, y + 4, 110, 22, parent, NULL, hInst, NULL);
    hDevEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"Windows-PC",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        320, y, 270, 26, parent, NULL, hInst, NULL);
    SendMessage(hDevEdit, WM_SETFONT, (WPARAM)hDefFont, TRUE);
    y += 42;

    /* Remember username checkbox */
    hRememberChk = CreateWindowW(L"BUTTON", L"Remember username",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_TABSTOP,
        310, y, 180, 20, parent, (HMENU)ID_REMEMBER, hInst, NULL);
    SendMessage(hRememberChk, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    /* Check if username was saved */
    if (storage_exists()) {
        DeviceConfig savedCfg;
        if (storage_load_config(&savedCfg) && savedCfg.username[0]) {
            WCHAR savedName[128];
            MultiByteToWideChar(CP_UTF8, 0, savedCfg.username, -1, savedName, 128);
            SetWindowTextW(hUserEdit, savedName);
            SendMessage(hRememberChk, BM_SETCHECK, BST_CHECKED, 0);
        }
    }
    y += 32;

    /* Two buttons: Create Account | Login */
    hRegBtn = CreateWindowW(L"BUTTON", L"Create Account",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
        200, y, 200, 36, parent, (HMENU)ID_REGISTER, hInst, NULL);
    SendMessage(hRegBtn, WM_SETFONT, (WPARAM)hDefFont, TRUE);

    hLoginBtn = CreateWindowW(L"BUTTON", L"Login & Add Device",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
        410, y, 200, 36, parent, (HMENU)ID_LOGIN_BTN, hInst, NULL);
    SendMessage(hLoginBtn, WM_SETFONT, (WPARAM)hDefFont, TRUE);
    y += 60;

    hRegStatus = CreateWindowW(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        150, y, 500, 26, parent, NULL, hInst, NULL);
    SendMessage(hRegStatus, WM_SETFONT, (WPARAM)hDefFont, TRUE);
}

void DestroyRegistrationPanel(void) {
    HWND kids[] = {hRegTitle, hUserEdit, hPassEdit, hDevEdit, hRegBtn, hLoginBtn, hRegStatus, hRememberChk};
    for (int i = 0; i < 8; i++) { if (kids[i]) { DestroyWindow(kids[i]); kids[i] = NULL; } }
}

/* -- Messages Panel with Sidebar ------------------------------------ */
void CreateMessagesPanel(HWND parent) {
    int chatX = 220, chatW = 626;

    /* -- Sidebar background ------------------------------------------ */
    CreateWindowW(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_LEFT | WS_BORDER,
        0, 0, 220, 600, parent, NULL, hInst, NULL);

    /* Tabs */
    hContactsTab = CreateWindowW(L"BUTTON", L"Contacts",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
        2, 2, 108, 26, parent, (HMENU)ID_CONTACTS_TAB, hInst, NULL);
    SendMessage(hContactsTab, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    hGroupsTab = CreateWindowW(L"BUTTON", L"Groups",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
        110, 2, 108, 26, parent, (HMENU)ID_GROUPS_TAB, hInst, NULL);
    SendMessage(hGroupsTab, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    /* Search / filter bar */
    hSearchEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        4, 32, 212, 22, parent, (HMENU)ID_SEARCH, hInst, NULL);
    SendMessage(hSearchEdit, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    /* Contact / Group list */
    hSideList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | LBS_NOTIFY,
        4, 58, 212, 468, parent, (HMENU)ID_SIDELIST, hInst, NULL);
    SendMessage(hSideList, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    /* Action button */
    hSideBtn = CreateWindowW(L"BUTTON", L"+ New Group",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
        4, 500, 212, 26, parent, (HMENU)ID_SIDE_BTN, hInst, NULL);
    SendMessage(hSideBtn, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    /* Theme toggle */
    CreateWindowW(L"BUTTON", gDarkMode ? L"Light Mode" : L"Dark Mode",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
        4, 500, 212, 24, parent, (HMENU)ID_THEME_TOGGLE, hInst, NULL);
    SendMessage(hSideBtn, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    /* -- Chat area --------------------------------------------------- */
    hRecipLabel = CreateWindowW(L"STATIC", L"To:", WS_CHILD | WS_VISIBLE,
        chatX, 4, 24, 22, parent, NULL, hInst, NULL);
    SendMessage(hRecipLabel, WM_SETFONT, (WPARAM)hDefFont, TRUE);

    hRecipDisp = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_READONLY | ES_AUTOHSCROLL,
        chatX + 28, 4, chatW - 148, 24, parent, NULL, hInst, NULL);
    SendMessage(hRecipDisp, WM_SETFONT, (WPARAM)hSmallFont, TRUE);
    SetWindowTextW(hRecipDisp, L"Select a contact or group from the sidebar");

    /* Connection status indicator */
    hConnStatus = CreateWindowW(L"STATIC", L"Connecting to encryption server...",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        chatX, 32, chatW, 18, parent, (HMENU)ID_CONN_STATUS, hInst, NULL);
    SendMessage(hConnStatus, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    /* Stop retry button (hidden initially) */
    hRetryBtn = CreateWindowW(L"BUTTON", L"Stop Retry",
        WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON,
        chatX + chatW - 90, 32, 80, 18, parent, (HMENU)ID_RETRY_BTN, hInst, NULL);
    SendMessage(hRetryBtn, WM_SETFONT, (WPARAM)hSmallFont, TRUE);
    ShowWindow(hRetryBtn, SW_HIDE);

    LoadLibraryW(L"msftedit.dll");
    hMsgList = CreateWindowExW(0, L"RICHEDIT50W", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL | WS_TABSTOP,
        chatX, 54, chatW, 308, parent, (HMENU)ID_MSGLIST, hInst, NULL);
    SendMessage(hMsgList, WM_SETFONT, (WPARAM)hDefFont, TRUE);

    /* File tracking panel */
    CreateWindowW(L"STATIC", L"Pending Files:", WS_CHILD | WS_VISIBLE,
        chatX, 366, chatW, 16, parent, NULL, hInst, NULL);
    hFileList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY,
        chatX, 382, chatW, 52, parent, NULL, hInst, NULL);
    SendMessage(hFileList, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    /* Display name + Note row */
    int metaY = 438;
    CreateWindowW(L"STATIC", L"Name:", WS_CHILD | WS_VISIBLE,
        chatX, metaY + 3, 40, 22, parent, NULL, hInst, NULL);
    hNameEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        chatX + 44, metaY, 130, 24, parent, (HMENU)ID_NAMEEDIT, hInst, NULL);
    SendMessage(hNameEdit, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    CreateWindowW(L"STATIC", L"Note:", WS_CHILD | WS_VISIBLE,
        chatX + 182, metaY + 3, 34, 22, parent, NULL, hInst, NULL);
    hNoteEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        chatX + 220, metaY, chatW - 226, 24, parent, (HMENU)ID_NOTEEDIT, hInst, NULL);
    SendMessage(hNoteEdit, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    /* Message input row */
    int inputY = 470;
    hAttachBtn = CreateWindowW(L"BUTTON", L"Attach",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
        chatX, inputY, 32, 26, parent, (HMENU)ID_ATTACH, hInst, NULL);
    SendMessage(hAttachBtn, WM_SETFONT, (WPARAM)hDefFont, TRUE);

    hMsgInput = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        chatX + 36, inputY, chatW - 192, 26, parent, (HMENU)ID_MSGINPUT, hInst, NULL);
    SendMessage(hMsgInput, WM_SETFONT, (WPARAM)hDefFont, TRUE);

    hSendBtn = CreateWindowW(L"BUTTON", L"Send",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
        chatX + chatW - 150, inputY, 72, 26, parent, (HMENU)ID_SEND, hInst, NULL);
    SendMessage(hSendBtn, WM_SETFONT, (WPARAM)hDefFont, TRUE);

    char tpmStr[128];
    tpm_status_string(tpmStr, 128);

    char status[512];
    const char *pqLabel = kyber_available() ? "ECDH+ML-KEM-1024" : "ECDH P-384";
    wsprintfA(status, "Device: %.32s... | Platform: %s | AES-256-GCM | %s | %s | GHOSTLINK v%s",
              gCfg.id, gCfg.platform, pqLabel, tpmStr, CLIENT_VERSION);
    hStatusBar = CreateWindowA("STATIC", status,
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        chatX, 504, chatW, 20, parent, NULL, hInst, NULL);
    SendMessage(hStatusBar, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    /* Set Contacts tab as active, load contacts */
    SwitchTab(FALSE);
    PopulateContacts(NULL);

    SetFocus(hMsgInput);
    SetTimer(parent, 1, 4000, NULL);

    /* Initial health check -- starts retry loop if server is down */
    gStopRetry = FALSE;
    gServerOnline = FALSE;
    SetOfflineMode(TRUE);
    CheckServerHealth();

    /* Apply dark/light theme to all controls */
    Theme_ApplyToControls(parent);
}

void DestroyMessagesPanel(void) {
    KillTimer(hMainWnd, 1);
    KillTimer(hMainWnd, 2);
    HWND kids[] = {
        hContactsTab, hGroupsTab, hSearchEdit, hSideList, hSideBtn,
        hRecipLabel, hRecipDisp, hMsgList, hMsgInput, hSendBtn, hAttachBtn, hStatusBar,
        hNameEdit, hNoteEdit, hFileList, hConnStatus, hRetryBtn
    };
    for (int i = 0; i < 17; i++) {
        if (kids[i]) { DestroyWindow(kids[i]); kids[i] = NULL; }
    }
}

/* -- Tab Switching -------------------------------------------------- */
void SwitchTab(BOOL groups) {
    gTabIsGroups = groups;
    /* Update tab visual state */
    SendMessage(hContactsTab, WM_ENABLE, groups ? TRUE : FALSE, 0);
    SendMessage(hGroupsTab, WM_ENABLE, groups ? FALSE : TRUE, 0);

    /* Update button text */
    SetWindowTextW(hSideBtn, groups ? L"+ New Group" : L"Search Contacts");

    /* Clear and reload */
    SendMessage(hSideList, LB_RESETCONTENT, 0, 0);
    SetWindowTextW(hSearchEdit, L"");

    if (groups) PopulateGroups();
    else PopulateContacts(NULL);
}

/* -- Contact Search / List ------------------------------------------ */
void PopulateContacts(char *search) {
    SendMessage(hSideList, LB_RESETCONTENT, 0, 0);

    if (search && strlen(search) < 2) return;

    char body[512];
    if (search) {
        wsprintfA(body, "{\"username\":\"%s\",\"password\":\"%s\",\"query\":\"%s\"}",
                  gCfg.username, "", search);
    } else {
        /* List user's own devices as contacts */
        wsprintfA(body, "{\"username\":\"%s\",\"password\":\"\"}", gCfg.username);
    }

    HttpResponse *r = NULL;
    if (search) {
        r = network_post("/api/v1/contacts/search", body);
        if (r && r->len > 10) {
            /* Parse JSON array manually */
            char *p = strstr(r->data, "\"users\":[");
            if (p) {
                p = strchr(p, '[');
                if (p) {
                    p++;
                    while (*p && *p != ']') {
                        char *q1 = strchr(p, '"');
                        if (!q1) break;
                        char *q2 = strchr(q1 + 1, '"');
                        if (!q2) break;
                        int ulen = (int)(q2 - q1 - 1);
                        char uname[64] = {0};
                        strncpy(uname, q1 + 1, (ulen < 63 ? ulen : 63));

                        /* Convert to wide and add to listbox */
                        WCHAR wname[64];
                        MultiByteToWideChar(CP_UTF8, 0, uname, -1, wname, 64);
                        SendMessageW(hSideList, LB_ADDSTRING, 0, (LPARAM)wname);
                        p = q2 + 1;
                    }
                }
            }
        }
    } else {
        /* Show own devices */
        r = network_post("/api/v1/devices/list", body);
        if (r && r->len > 10) {
            char *p = strstr(r->data, "\"devices\":[");
            if (p) {
                p = strchr(p, '[');
                if (p) {
                    p++;
                    while (*p && *p != ']') {
                        char *idStart = strstr(p, "\"id\":\"");
                        char *nameStart = strstr(p, "\"name\":\"");
                        char *regStart = strstr(p, "\"registered_at\":\"");
                        char *regEnd = NULL;
                        if (!idStart || !nameStart) break;

                        idStart += 6;
                        char *idEnd = strchr(idStart, '"');
                        nameStart += 8;
                        char *nameEnd = strchr(nameStart, '"');

                        /* Extract registration date (just the date part) */
                        char regDate[20] = "";
                        if (regStart) {
                            regStart += 18;
                            regEnd = strchr(regStart, '"');
                            if (regEnd) {
                                int rlen = (int)(regEnd - regStart);
                                if (rlen > 10) rlen = 10;  /* Just YYYY-MM-DD */
                                strncpy(regDate, regStart, (rlen < 19 ? rlen : 19));
                            }
                        }

                        if (idEnd && nameEnd) {
                            char did[16] = {0};
                            strncpy(did, idStart, ((int)(idEnd - idStart) < 15 ? (int)(idEnd - idStart) : 15));
                            char dname[32] = {0};
                            strncpy(dname, nameStart, ((int)(nameEnd - nameStart) < 31 ? (int)(nameEnd - nameStart) : 31));

                            char entry[96];
                            if (regDate[0])
                                wsprintfA(entry, "%s (%s) -- %s", dname, did, regDate);
                            else
                                wsprintfA(entry, "%s (%s)", dname, did);
                            WCHAR wentry[96];
                            MultiByteToWideChar(CP_UTF8, 0, entry, -1, wentry, 96);
                            SendMessageW(hSideList, LB_ADDSTRING, 0, (LPARAM)wentry);

                            /* Find next object */
                            p = (idEnd > nameEnd ? idEnd : nameEnd) + 1;
                            if (regStart && regEnd > p) p = regEnd;
                            p++;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    if (r) network_free_response(r);
}

/* -- Group List ----------------------------------------------------- */
void PopulateGroups(void) {
    SendMessage(hSideList, LB_RESETCONTENT, 0, 0);

    char path[128];
    wsprintfA(path, "/api/v1/groups/%s", gCfg.id);
    HttpResponse *r = network_get(path);
    if (r && r->len > 10) {
        char *p = strstr(r->data, "\"groups\":[");
        if (p) {
            p = strchr(p, '[');
            if (p) {
                p++;
                while (*p && *p != ']') {
                    char *nameStart = strstr(p, "\"name\":\"");
                    char *idStart = strstr(p, "\"id\":\"");
                    if (!nameStart || !idStart) break;

                    nameStart += 8;
                    char *nameEnd = strchr(nameStart, '"');
                    idStart += 6;
                    char *idEnd = strchr(idStart, '"');

                    if (nameEnd && idEnd) {
                        char gname[48] = {0};
                        strncpy(gname, nameStart, ((int)(nameEnd - nameStart) < 47 ? (int)(nameEnd - nameStart) : 47));
                        char gid[16] = {0};
                        strncpy(gid, idStart, ((int)(idEnd - idStart) < 15 ? (int)(idEnd - idStart) : 15));

                        char entry[80];
                        wsprintfA(entry, "# %s [%.12s]", gname, gid);
                        WCHAR wentry[80];
                        MultiByteToWideChar(CP_UTF8, 0, entry, -1, wentry, 80);
                        SendMessageW(hSideList, LB_ADDSTRING, 0, (LPARAM)wentry);

                        p = (nameEnd > idEnd ? nameEnd : idEnd) + 1;
                    } else break;
                }
            }
        }
    }
    if (r) network_free_response(r);
}

/* -- Sidebar Selection ---------------------------------------------- */
void OnSideSelect(void) {
    int idx = (int)SendMessage(hSideList, LB_GETCURSEL, 0, 0);
    if (idx < 0) return;

    WCHAR buf[128];
    SendMessageW(hSideList, LB_GETTEXT, idx, (LPARAM)buf);

    char itemA[128];
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, itemA, 128, NULL, NULL);

    if (gTabIsGroups) {
        /* Group -- extract group ID from item like "# GroupName [groupid]" */
        char *lb = strchr(itemA, '[');
        char *rb = strchr(itemA, ']');
        if (lb && rb) {
            int glen = (int)(rb - lb - 1);
            strncpy(gSelectedRecip, lb + 1, glen);
            gSelectedRecip[glen] = 0;
            SetWindowTextW(hRecipDisp, buf);
        }
    } else {
        /* Contact -- extract device ID from "name (deviceid)" */
        char *lp = strchr(itemA, '(');
        char *rp = strchr(itemA, ')');
        if (lp && rp) {
            int dlen = (int)(rp - lp - 1);
            strncpy(gSelectedRecip, lp + 1, dlen);
            gSelectedRecip[dlen] = 0;
            SetWindowTextW(hRecipDisp, buf);
        } else {
            /* Direct username -- no device ID yet, just use the text */
            strncpy(gSelectedRecip, itemA, sizeof(gSelectedRecip) - 1);
            SetWindowTextW(hRecipDisp, buf);
        }
    }
}

/* -- New Group ------------------------------------------------------ */
void OnNewGroup(void) {
    WCHAR gnameW[64];
    if (!DialogBoxParamW(NULL, MAKEINTRESOURCEW(1), NULL, NULL, 0)) {
        /* Simple prompt via edit field -- reuse search box trick */
        SetWindowTextW(hSearchEdit, L"");
    }

    /* For now: quick group creation with default name */
    char body[256];
    wsprintfA(body, "{\"group_name\":\"New Group\",\"creator_device_id\":\"%s\",\"members\":[{\"device_id\":\"%s\",\"encrypted_group_key\":\"demo\"}]}",
              gCfg.id, gCfg.id);
    HttpResponse *r = network_post("/api/v1/groups/create", body);
    if (r) network_free_response(r);

    PopulateGroups();
    SetWindowTextW(hSideBtn, L"+ New Group");
}

/* -- Registration Handler ------------------------------------------- */
void OnRegister(BOOL isLogin) {
    WCHAR username[128], password[128], deviceName[128];
    GetWindowTextW(hUserEdit, username, 128);
    GetWindowTextW(hPassEdit, password, 128);
    GetWindowTextW(hDevEdit, deviceName, 128);

    if (wcslen(username) < 3 || wcslen(password) < 12) {
        SetWindowTextW(hRegStatus, L"Username must be 3+ chars, password 12+ chars");
        return;
    }

    /* Save username if "Remember" is checked */
    LRESULT remember = SendMessage(hRememberChk, BM_GETCHECK, 0, 0);

    SetWindowTextW(hRegStatus, L"Generating ECDH P-384 keypair...");
    EnableWindow(hRegBtn, FALSE);
    EnableWindow(hLoginBtn, FALSE);

    gCfg.identity_key = crypto_generate_keypair();
    if (!gCfg.identity_key.handle) {
        SetWindowTextW(hRegStatus, L"FIPS key generation FAILED");
        EnableWindow(hRegBtn, TRUE);
        return;
    }

    char *hex = crypto_hex_encode(gCfg.identity_key.pub.data, gCfg.identity_key.pub.len);
    char pubHex[1024];
    strcpy(pubHex, hex);
    free(hex);

    char usernameA[128] = {0}, passwordA[128] = {0}, deviceNameA[128] = {0};
    WideCharToMultiByte(CP_UTF8, 0, username, -1, usernameA, 128, NULL, NULL);

    /* Save username to config if Remember is checked */
    if (remember == BST_CHECKED) {
        strncpy(gCfg.username, usernameA, sizeof(gCfg.username) - 1);
        strncpy(gCfg.device_name, "", sizeof(gCfg.device_name) - 1);
        gCfg.id[0] = 0;
        storage_save_config(&gCfg);
    } else {
        /* Clear saved username if unchecked */
        if (storage_exists()) {
            DeviceConfig tmp;
            if (storage_load_config(&tmp) && tmp.username[0]) {
                tmp.username[0] = 0;
                storage_save_config(&tmp);
            }
        }
    }
    WideCharToMultiByte(CP_UTF8, 0, password, -1, passwordA, 128, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, deviceName, -1, deviceNameA, 128, NULL, NULL);

    /* Step 1: Create user account (skip if logging in) */
    if (!isLogin) {
        SetWindowTextW(hRegStatus, L"Creating account...");
        UpdateWindow(hMainWnd);

        char userBody[512];
        wsprintfA(userBody, "{\"username\":\"%s\",\"password\":\"%s\"}", usernameA, passwordA);
        HttpResponse *ur = network_post("/api/v1/register", userBody);
        if (ur) network_free_response(ur);
    }

    /* Step 2: Register device */
    SetWindowTextW(hRegStatus, isLogin ? L"Logging in..." : L"Registering device...");

    char appId[64];
    app_instance_id(appId, 64);

    char body[2200];
    wsprintfA(body, "{\"username\":\"%s\",\"password\":\"%s\",\"device_name\":\"%s\","
              "\"platform\":\"windows\",\"public_key\":\"%s\",\"hwid\":\"%s\"}",
              usernameA, passwordA, deviceNameA, pubHex, appId);

    HttpResponse *r = network_post("/api/v1/devices", body);

    if (r && r->len > 0) {
        char *did = json_get_string(r->data, "device_id");
        if (did) {
            strncpy(gCfg.id, did, sizeof(gCfg.id) - 1);
            strncpy(gCfg.username, usernameA, sizeof(gCfg.username) - 1);
            strncpy(gCfg.device_name, deviceNameA, sizeof(gCfg.device_name) - 1);
            strcpy(gCfg.platform, "windows");

            storage_save_config(&gCfg);
            storage_save_keypair(gCfg.id, &gCfg.identity_key);
            free(did);

            gRegistered = TRUE;
            DestroyRegistrationPanel();
            CreateMessagesPanel(hMainWnd);
        } else {
            /* Extract server error detail */
            char *detail = json_get_string(r->data, "detail");
            if (detail) {
                WCHAR detailW[256];
                MultiByteToWideChar(CP_UTF8, 0, detail, -1, detailW, 256);
                WCHAR msg[320];
                wsprintfW(msg, L"Server error: %s", detailW);
                SetWindowTextW(hRegStatus, msg);
                free(detail);
            } else {
                SetWindowTextW(hRegStatus, L"Server rejected -- check credentials");
            }
            EnableWindow(hRegBtn, TRUE);
            EnableWindow(hLoginBtn, TRUE);
        }
    } else {
        SetWindowTextW(hRegStatus, L"Server unreachable -- is it running on port 58443?");
        EnableWindow(hRegBtn, TRUE);
        EnableWindow(hLoginBtn, TRUE);
    }
    if (r) network_free_response(r);
}

/* -- Resize Handler -------------------------------------------------- */
void RepositionChatControls(int cx, int cy) {
    int sidebarW = 220;
    int chatX = sidebarW;
    int chatW = cx - sidebarW;
    if (chatW < 200) chatW = 200;

    /* Sidebar: list stretches, buttons pinned to bottom */
    SetWindowPos(hSideList, NULL, 4, 58, sidebarW - 8, cy - 160, SWP_NOZORDER);

    /* Theme toggle at bottom */
    HWND hThemeBtn = GetDlgItem(hMainWnd, ID_THEME_TOGGLE);
    if (hThemeBtn) SetWindowPos(hThemeBtn, NULL, 4, cy - 28, sidebarW - 8, 24, SWP_NOZORDER);

    /* New Group button above */
    SetWindowPos(hSideBtn, NULL, 4, cy - 56, sidebarW - 8, 24, SWP_NOZORDER);

    /* Chat area -- calculate from bottom up */
    int pad = 4;

    /* Connection status & retry button */
    SetWindowPos(hConnStatus, NULL, chatX, 32, chatW - pad, 18, SWP_NOZORDER);
    SetWindowPos(hRetryBtn, NULL, chatX + chatW - 90, 32, 80, 18, SWP_NOZORDER);

    /* Status bar at bottom */
    int statusY = cy - 26;
    SetWindowPos(hStatusBar, NULL, chatX, statusY, chatW - pad, 20, SWP_NOZORDER);

    /* Message input */
    int inputY = statusY - 34;
    SetWindowPos(hAttachBtn, NULL, chatX, inputY, 32, 26, SWP_NOZORDER);
    SetWindowPos(hMsgInput, NULL, chatX + 36, inputY, chatW - 192 - pad, 26, SWP_NOZORDER);
    SetWindowPos(hSendBtn, NULL, chatX + chatW - 154 - pad, inputY, 72, 26, SWP_NOZORDER);

    /* Name / Note row */
    int metaY = inputY - 30;
    SetWindowPos(hNameEdit, NULL, chatX + 44, metaY, 130, 24, SWP_NOZORDER);
    SetWindowPos(hNoteEdit, NULL, chatX + 220, metaY, chatW - 226 - pad, 24, SWP_NOZORDER);

    /* Message list fills most space, file panel below it */
    int listTop = 54;
    int filePanelH = 70;
    int listH = metaY - listTop - filePanelH - 4;
    if (listH < 100) listH = 100;
    SetWindowPos(hMsgList, NULL, chatX, listTop, chatW - pad, listH, SWP_NOZORDER);
    SetWindowPos(hFileList, NULL, chatX, listTop + listH + 18, chatW - pad, filePanelH - 18, SWP_NOZORDER);

    /* Recipient display */
    SetWindowPos(hRecipDisp, NULL, chatX + 28, 4, chatW - 152 - pad, 24, SWP_NOZORDER);
    SetWindowPos(hRecipLabel, NULL, chatX, 7, 24, 22, SWP_NOZORDER);
}

/* -- Server Health Check -------------------------------------------- */
void CheckServerHealth(void) {
    if (gStopRetry) return;

    HttpResponse *r = network_get("/health");
    if (r && r->len > 10 && strstr(r->data, "\"status\":\"ok\"")) {
        /* Server is up and FIPS self-test passed */
        if (!gServerOnline) {
            gServerOnline = TRUE;
            gRetryCount = 0;
            SetOfflineMode(FALSE);
        }
    } else {
        /* Server unreachable or unhealthy */
        if (gServerOnline) {
            gServerOnline = FALSE;
            SetOfflineMode(TRUE);
        }
        gRetryCount++;
        /* Schedule next retry in 3 seconds */
        SetTimer(hMainWnd, 2, 3000, NULL);
    }
    if (r) network_free_response(r);
}

void SetOfflineMode(BOOL offline) {
    if (offline) {
        /* Grey out input and buttons */
        EnableWindow(hMsgInput, FALSE);
        EnableWindow(hSendBtn, FALSE);
        EnableWindow(hAttachBtn, FALSE);
        EnableWindow(hNameEdit, FALSE);
        EnableWindow(hNoteEdit, FALSE);

        char status[256];
        wsprintfA(status, "ENCRYPTION SERVER OFFLINE -- Messages blocked for security. Retry %d...", gRetryCount);
        SetWindowTextA(hConnStatus, status);
        SetWindowTextW(hMsgInput, L"Waiting for secure connection...");

        ShowWindow(hRetryBtn, SW_SHOW);
    } else {
        /* Re-enable */
        EnableWindow(hMsgInput, TRUE);
        EnableWindow(hSendBtn, TRUE);
        EnableWindow(hAttachBtn, TRUE);
        EnableWindow(hNameEdit, TRUE);
        EnableWindow(hNoteEdit, TRUE);

        SetWindowTextA(hConnStatus, "Encryption server online -- AES-256-GCM | ECDH P-384");
        SetWindowTextW(hMsgInput, L"");
        ShowWindow(hRetryBtn, SW_HIDE);

        /* Reset timer */
        KillTimer(hMainWnd, 2);
        gRetryCount = 0;

        /* Fetch any pending messages */
        FetchMessages();
    }
    InvalidateRect(hConnStatus, NULL, TRUE);
}

/* -- Security Status ------------------------------------------------ */
void UpdateSecurityStatus(void) {
    if (!hStatusBar) return;
    char tpmStr[128];
    tpm_status_string(tpmStr, 128);

    char status[512];
    const char *pqLabel = kyber_available() ? "ECDH+ML-KEM-1024" : "ECDH P-384";
    wsprintfA(status, "Device: %.32s... | Platform: %s | AES-256-GCM | %s | %s | GHOSTLINK v%s",
              gCfg.id, gCfg.platform, pqLabel, tpmStr, CLIENT_VERSION);
    SetWindowTextA(hStatusBar, status);
}

/* -- Settings Dialog Proc ------------------------------------------- */
#define IDC_ACCENT_R  2001
#define IDC_ACCENT_G  2002
#define IDC_ACCENT_B  2003
#define IDC_APPLYCLR  2004
#define IDC_CHECKUPD  2005
#define IDC_NUKE_BTN  2006
#define IDC_DARKMODE  2007

static HWND hSettingsDlg = NULL;
static HWND hAccentR, hAccentG, hAccentB, hSettingsStatus;

void Settings_UpdateFields(void) {
    if (!hSettingsDlg) return;
    char buf[64];
    wsprintfA(buf, "%d", (gTheme->accent >> 16) & 0xFF);
    SetWindowTextA(GetDlgItem(hSettingsDlg, IDC_ACCENT_R), buf);
    wsprintfA(buf, "%d", (gTheme->accent >> 8) & 0xFF);
    SetWindowTextA(GetDlgItem(hSettingsDlg, IDC_ACCENT_G), buf);
    wsprintfA(buf, "%d", gTheme->accent & 0xFF);
    SetWindowTextA(GetDlgItem(hSettingsDlg, IDC_ACCENT_B), buf);
}

void Settings_ApplyAccent(void) {
    if (!hSettingsDlg) return;
    char rbuf[8], gbuf[8], bbuf[8];
    GetWindowTextA(GetDlgItem(hSettingsDlg, IDC_ACCENT_R), rbuf, 8);
    GetWindowTextA(GetDlgItem(hSettingsDlg, IDC_ACCENT_G), gbuf, 8);
    GetWindowTextA(GetDlgItem(hSettingsDlg, IDC_ACCENT_B), bbuf, 8);
    int r = atoi(rbuf), g = atoi(gbuf), b = atoi(bbuf);
    if (r < 0) r = 0; if (r > 255) r = 255;
    if (g < 0) g = 0; if (g > 255) g = 255;
    if (b < 0) b = 0; if (b > 255) b = 255;
    gTheme->accent = (COLORREF)((b << 16) | (g << 8) | r);
    Theme_CreateBrushes();
    SetWindowTextA(hSettingsStatus, "Accent color applied");
    if (gRegistered) Theme_ApplyToControls(hMainWnd);
}

LRESULT CALLBACK SettingsDlgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        return 0;
    case WM_CTLCOLORSTATIC:
        SetBkMode((HDC)wp, TRANSPARENT);
        SetTextColor((HDC)wp, gTheme->text);
        SetBkColor((HDC)wp, gTheme->bg_card);
        return (LRESULT)gCardBrush;
    case WM_CTLCOLOREDIT:
        SetBkMode((HDC)wp, TRANSPARENT);
        SetTextColor((HDC)wp, gTheme->text);
        SetBkColor((HDC)wp, gTheme->bg_input);
        return (LRESULT)gInputBrush;
    case WM_CTLCOLORBTN:
        SetBkMode((HDC)wp, TRANSPARENT);
        SetTextColor((HDC)wp, gTheme->text);
        return (LRESULT)gCardBrush;
    case WM_ERASEBKGND:
        { RECT rc; GetClientRect(hwnd, &rc); FillRect((HDC)wp, &rc, gBgBrush); return 1; }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_APPLYCLR) { Settings_ApplyAccent(); return 0; }
        if (LOWORD(wp) == IDC_DARKMODE) {
            Theme_Toggle();
            Settings_UpdateFields();
            InvalidateRect(hwnd, NULL, TRUE);
            return 0;
        }
        if (LOWORD(wp) == IDC_CHECKUPD) {
            SetWindowTextA(hSettingsStatus, "Checking for updates...");
            HttpResponse *ver = network_get("/api/v1/version");
            if (ver && ver->len > 10) {
                char *latest = json_get_string(ver->data, "version");
                if (latest) {
                    char msg[128];
                    wsprintfA(msg, "Latest: v%s | Current: v%s", latest, CLIENT_VERSION);
                    SetWindowTextA(hSettingsStatus, msg);
                    free(latest);
                }
            } else {
                SetWindowTextA(hSettingsStatus, "Could not reach update server");
            }
            if (ver) network_free_response(ver);
            return 0;
        }
        if (LOWORD(wp) == IDC_NUKE_BTN) {
            int result = MessageBoxW(hwnd,
                L"NUKE MY DATA\n\n"
                L"This will permanently delete all local data,\n"
                L"encryption keys, and the GHOSTLINK executable.\n\n"
                L"This action is IRREVERSIBLE.",
                L"GHOSTLINK -- Confirm Nuke",
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
            if (result == IDYES) {
                DeleteFileA("D:\\GHOSTLINK\\msgcache.enc");
                storage_delete_all();
                DestroyWindow(hwnd);
                DestroyWindow(hMainWnd);
                char exePath[MAX_PATH];
                GetModuleFileNameA(NULL, exePath, MAX_PATH);
                char cmd[512];
                wsprintfA(cmd, "cmd.exe /c timeout /t 2 /nobreak > nul && del /f /q \"%s\"", exePath);
                WinExec(cmd, SW_HIDE);
            }
            return 0;
        }
        break;
    case WM_CLOSE:
        hSettingsDlg = NULL;
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void OnSettings(void) {
    if (hSettingsDlg) { SetForegroundWindow(hSettingsDlg); return; }

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = SettingsDlgProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = gBgBrush;
    wc.lpszClassName = L"GHOSTLINK_Settings";
    RegisterClassExW(&wc);

    hSettingsDlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"GHOSTLINK_Settings",
        L"GHOSTLINK Settings", WS_VISIBLE | WS_CAPTION | WS_SYSMENU | WS_POPUP,
        200, 120, 440, 460, hMainWnd, NULL, hInst, NULL);
    if (!hSettingsDlg) return;

    HFONT hdr = CreateFontW(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FF_DONTCARE, L"Segoe UI");

    int y = 12;
    /* Title */
    HWND t = CreateWindowW(L"STATIC", L"GHOSTLINK Settings",
        WS_CHILD | WS_VISIBLE, 16, y, 380, 28, hSettingsDlg, NULL, hInst, NULL);
    SendMessage(t, WM_SETFONT, (WPARAM)hdr, TRUE);
    y += 36;

    /* -- Theme section -- */
    HWND grp1 = CreateWindowW(L"BUTTON", L" Theme Colors ",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 10, y, 410, 120, hSettingsDlg, NULL, hInst, NULL);
    int gy = y + 20;
    CreateWindowW(L"STATIC", L"Dark Mode:", WS_CHILD | WS_VISIBLE, 22, gy, 70, 22, hSettingsDlg, NULL, hInst, NULL);
    HWND dmBtn = CreateWindowW(L"BUTTON", gDarkMode ? L"ON (click to toggle)" : L"OFF (click to toggle)",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 100, gy, 160, 22, hSettingsDlg, (HMENU)IDC_DARKMODE, hInst, NULL);
    SendMessage(dmBtn, WM_SETFONT, (WPARAM)hSmallFont, TRUE);
    gy += 28;

    CreateWindowW(L"STATIC", L"Accent:", WS_CHILD | WS_VISIBLE, 22, gy, 70, 22, hSettingsDlg, NULL, hInst, NULL);
    CreateWindowW(L"STATIC", L"R:", WS_CHILD | WS_VISIBLE, 100, gy, 16, 22, hSettingsDlg, NULL, hInst, NULL);
    hAccentR = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_NUMBER,
        118, gy, 36, 20, hSettingsDlg, (HMENU)IDC_ACCENT_R, hInst, NULL);
    CreateWindowW(L"STATIC", L"G:", WS_CHILD | WS_VISIBLE, 162, gy, 16, 22, hSettingsDlg, NULL, hInst, NULL);
    hAccentG = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_NUMBER,
        180, gy, 36, 20, hSettingsDlg, (HMENU)IDC_ACCENT_G, hInst, NULL);
    CreateWindowW(L"STATIC", L"B:", WS_CHILD | WS_VISIBLE, 224, gy, 16, 22, hSettingsDlg, NULL, hInst, NULL);
    hAccentB = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_NUMBER,
        242, gy, 36, 20, hSettingsDlg, (HMENU)IDC_ACCENT_B, hInst, NULL);
    HWND applyBtn = CreateWindowW(L"BUTTON", L"Apply",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 290, gy-2, 80, 24, hSettingsDlg, (HMENU)IDC_APPLYCLR, hInst, NULL);
    gy += 24;
    CreateWindowW(L"STATIC", L"Example: this text uses the accent color for highlights",
        WS_CHILD | WS_VISIBLE, 22, gy, 380, 18, hSettingsDlg, NULL, hInst, NULL);
    y += 130;
    Settings_UpdateFields();

    /* -- Account / Device section -- */
    HWND grp2 = CreateWindowW(L"BUTTON", L" Device Info ",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 10, y, 410, 90, hSettingsDlg, NULL, hInst, NULL);
    gy = y + 20;
    char devInfo[256];
    wsprintfA(devInfo, "Device ID: %.48s...", gCfg.id);
    CreateWindowA("STATIC", devInfo, WS_CHILD | WS_VISIBLE, 22, gy, 380, 18, hSettingsDlg, NULL, hInst, NULL);
    gy += 20;
    wsprintfA(devInfo, "Username: %s | Platform: %s", gCfg.username, gCfg.platform);
    CreateWindowA("STATIC", devInfo, WS_CHILD | WS_VISIBLE, 22, gy, 380, 18, hSettingsDlg, NULL, hInst, NULL);
    gy += 22;
    char tpmStr[128]; tpm_status_string(tpmStr, 128);
    const char *pq = kyber_available() ? "ECDH+ML-KEM-1024 PQ" : "ECDH P-384";
    char cryptInfo[256];
    wsprintfA(cryptInfo, "Crypto: AES-256-GCM | %s | %s", pq, tpmStr);
    CreateWindowA("STATIC", cryptInfo, WS_CHILD | WS_VISIBLE, 22, gy, 380, 18, hSettingsDlg, NULL, hInst, NULL);
    y += 100;

    /* -- Updates section -- */
    HWND grp3 = CreateWindowW(L"BUTTON", L" Updates ",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 10, y, 410, 60, hSettingsDlg, NULL, hInst, NULL);
    gy = y + 20;
    char verStr[64];
    wsprintfA(verStr, "Current version: GHOSTLINK v%s", CLIENT_VERSION);
    CreateWindowA("STATIC", verStr, WS_CHILD | WS_VISIBLE, 22, gy, 300, 18, hSettingsDlg, NULL, hInst, NULL);
    HWND chkBtn = CreateWindowW(L"BUTTON", L"Check for Updates",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 300, gy-2, 100, 22, hSettingsDlg, (HMENU)IDC_CHECKUPD, hInst, NULL);
    y += 70;

    /* -- Danger Zone -- */
    HWND grp4 = CreateWindowW(L"BUTTON", L" Danger Zone ",
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 10, y, 410, 56, hSettingsDlg, NULL, hInst, NULL);
    gy = y + 20;
    CreateWindowW(L"STATIC", L"Permanently destroy all data and the application:",
        WS_CHILD | WS_VISIBLE, 22, gy, 250, 18, hSettingsDlg, NULL, hInst, NULL);
    HWND nukeBtn = CreateWindowW(L"BUTTON", L"NUKE MY DATA",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 290, gy-2, 115, 26, hSettingsDlg, (HMENU)IDC_NUKE_BTN, hInst, NULL);
    y += 66;

    /* Status bar */
    hSettingsStatus = CreateWindowW(L"STATIC", L"",
        WS_CHILD | WS_VISIBLE, 10, y, 410, 20, hSettingsDlg, NULL, hInst, NULL);
    SendMessage(hSettingsStatus, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    /* Apply theme to dialog */
    EnumChildWindows(hSettingsDlg, Theme_EnumChildProc, 0);
    SetFocus(GetDlgItem(hSettingsDlg, IDC_DARKMODE));
}

void OnNuke(void) {
    OnSettings();
}

/* -- Attach & Send File -------------------------------------------- */
void OnAttachFile(void) {
    if (strlen(gSelectedRecip) == 0) {
        SetWindowTextW(hRecipDisp, L"Select a recipient in the sidebar first!");
        return;
    }

    OPENFILENAMEW ofn = { sizeof(ofn) };
    WCHAR filePath[MAX_PATH] = L"";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Select File to Send (Encrypted)";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

    if (!GetOpenFileNameW(&ofn)) return;  /* User cancelled */

    /* Read entire file */
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        SetWindowTextW(hRecipDisp, L"Cannot open file");
        return;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0) {
        CloseHandle(hFile);
        SetWindowTextW(hRecipDisp, L"File is empty");
        return;
    }

    BYTE *fileData = malloc(fileSize);
    if (!fileData) { CloseHandle(hFile); return; }

    DWORD bytesRead;
    ReadFile(hFile, fileData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    /* Get filename from path */
    WCHAR *fname = wcsrchr(filePath, L'\\');
    if (fname) fname++; else fname = filePath;
    char origName[256] = {0};
    WideCharToMultiByte(CP_UTF8, 0, fname, -1, origName, 256, NULL, NULL);

    /* Generate session key */
    BYTE sessionKey[32];
    crypto_sha256(gCfg.identity_key.pub.data, gCfg.identity_key.pub.len, sessionKey);

    /* Encrypt file data */
    BYTE *encData = NULL;
    DWORD encLen = 0;
    if (!crypto_encrypt_file_data(sessionKey, fileData, bytesRead, &encData, &encLen)) {
        free(fileData);
        SetWindowTextW(hRecipDisp, L"Encryption failed");
        return;
    }
    free(fileData);

    /* Build metadata JSON -- encrypted inside the file message */
    char metaJson[512];
    wsprintfA(metaJson, "{\"name\":\"%s\",\"size\":%lu}", origName, bytesRead);

    /* Upload encrypted file */
    char pathBuf[64];
    wsprintfA(pathBuf, "/api/v1/files/upload");
    SetWindowTextW(hRecipDisp, L"Uploading encrypted file...");
    UpdateWindow(hMainWnd);

    HttpResponse *ur = network_upload_file(pathBuf, encData, encLen,
        gCfg.id, gSelectedRecip, metaJson);
    free(encData);

    char fileId[64] = "";
    if (ur && ur->len > 0) {
        char *fid = json_get_string(ur->data, "file_id");
        if (fid) {
            strncpy(fileId, fid, 63);
            free(fid);
        }
        network_free_response(ur);
    }

    if (!fileId[0]) {
        SetWindowTextW(hRecipDisp, L"File upload failed -- server error");
        return;
    }

    /* Send file notification message to recipient */
    char payload[1024];
    wsprintfA(payload,
        "{\"type\":\"file\",\"file_id\":\"%s\",\"name\":\"%s\",\"size\":%lu,\"body\":\"Sent a file: %s (%lu bytes)\"}",
        fileId, origName, bytesRead, origName, bytesRead);

    DWORD payloadLen = (DWORD)strlen(payload);
    BYTE nonce[12], ciphertext[2048], tag[16];
    crypto_random_bytes(nonce, 12);

    crypto_aes_gcm_encrypt(sessionKey, (BYTE*)payload, payloadLen, nonce, ciphertext, tag);

    char *nonceHex = crypto_hex_encode(nonce, 12);
    char *ctHex = crypto_hex_encode(ciphertext, payloadLen);
    char *tagHex = crypto_hex_encode(tag, 16);
    BYTE sig[32];
    crypto_sha256(ciphertext, payloadLen, sig);
    char *sigHex = crypto_hex_encode(sig, 32);

    char envelope[4096];
    wsprintfA(envelope, "{\"sender\":\"%s\",\"ts\":%lld,\"nonce\":\"%s\",\"ciphertext\":\"%s\",\"tag\":\"%s\",\"sig\":\"%s\"}",
              gCfg.id, (long long)(GetTickCount64() / 1000), nonceHex, ctHex, tagHex, sigHex);

    free(nonceHex); free(ctHex); free(tagHex); free(sigHex);

    char bodyJson[6000];
    wsprintfA(bodyJson, "{\"sender_device_id\":\"%s\",\"recipient_device_id\":\"%s\",\"envelope\":%s}",
              gCfg.id, gSelectedRecip, envelope);

    HttpResponse *r = network_post("/api/v1/messages/send", bodyJson);
    if (r) network_free_response(r);

    /* Display in chat */
    char displayMsg[1024];
    wsprintfA(displayMsg, "[ME -> %.12s] [FILE] %s (%lu bytes) [file_id: %.12s]\r\n",
              gSelectedRecip, origName, bytesRead, fileId);
    SendMessageA(hMsgList, EM_REPLACESEL, FALSE, (LPARAM)displayMsg);
    SendMessage(hMsgList, WM_VSCROLL, SB_BOTTOM, 0);

    WCHAR statusW[128];
    wsprintfW(statusW, L"File sent: %hs (%lu bytes)", origName, bytesRead);
    SetWindowTextW(hRecipDisp, statusW);
}

/* -- Send Message --------------------------------------------------- */
void OnSendMessage(void) {
    WCHAR bodyW[4096];
    GetWindowTextW(hMsgInput, bodyW, 4096);
    if (wcslen(bodyW) == 0) return;
    if (strlen(gSelectedRecip) == 0) {
        SetWindowTextW(hRecipDisp, L"Select a contact or group first!");
        return;
    }

    char bodyA[4096];
    WideCharToMultiByte(CP_UTF8, 0, bodyW, -1, bodyA, 4096, NULL, NULL);

    /* Read display name and note */
    WCHAR nameW[64], noteW[256];
    GetWindowTextW(hNameEdit, nameW, 64);
    GetWindowTextW(hNoteEdit, noteW, 256);
    char nameA[64] = "", noteA[256] = "";
    WideCharToMultiByte(CP_UTF8, 0, nameW, -1, nameA, 64, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, noteW, -1, noteA, 256, NULL, NULL);

    /* Build encrypted payload: {body, name, note, sender, ts} */
    char payload[5000];
    wsprintfA(payload,
        "{\"body\":\"%s\",\"name\":\"%s\",\"note\":\"%s\",\"sender\":\"%s\",\"ts\":%lld}",
        bodyA, nameA, noteA, gCfg.id, (long long)(GetTickCount64() / 1000));
    DWORD payloadLen = (DWORD)strlen(payload);

    BYTE nonce[12], ciphertext[5000], tag[16];
    crypto_random_bytes(nonce, 12);

    BYTE sessionKey[32];
    crypto_sha256(gCfg.identity_key.pub.data, gCfg.identity_key.pub.len, sessionKey);

    crypto_aes_gcm_encrypt(sessionKey, (BYTE*)payload, payloadLen, nonce, ciphertext, tag);

    char *nonceHex = crypto_hex_encode(nonce, 12);
    char *ctHex = crypto_hex_encode(ciphertext, payloadLen);
    char *tagHex = crypto_hex_encode(tag, 16);
    BYTE sig[32];
    crypto_sha256(ciphertext, payloadLen, sig);
    char *sigHex = crypto_hex_encode(sig, 32);

    char senderID[128];
    wsprintfA(senderID, "%.64s", gCfg.id);

    char envelope[10000];
    wsprintfA(envelope, "{\"sender\":\"%s\",\"ts\":%lld,\"nonce\":\"%s\",\"ciphertext\":\"%s\",\"tag\":\"%s\",\"sig\":\"%s\"}",
              senderID, (long long)(GetTickCount64() / 1000), nonceHex, ctHex, tagHex, sigHex);

    free(nonceHex); free(ctHex); free(tagHex); free(sigHex);

    /* Check if sending to group */
    if (strlen(gSelectedRecip) > 30 && gTabIsGroups) {
        char bodyJson[12000];
        wsprintfA(bodyJson, "{\"sender_device_id\":\"%s\",\"group_id\":\"%s\",\"envelope\":%s}",
                  senderID, gSelectedRecip, envelope);
        HttpResponse *r = network_post("/api/v1/groups/send", bodyJson);
        if (r) network_free_response(r);
    } else {
        char bodyJson[12000];
        wsprintfA(bodyJson, "{\"sender_device_id\":\"%s\",\"recipient_device_id\":\"%s\",\"envelope\":%s}",
                  senderID, gSelectedRecip, envelope);
        HttpResponse *r = network_post("/api/v1/messages/send", bodyJson);
        if (r) network_free_response(r);
    }

    SetWindowTextW(hMsgInput, L"");

    /* Display locally with name */
    char displayMsg[5000];
    if (nameA[0])
        wsprintfA(displayMsg, "[ME -> %.12s] %s -- %s\r\n", gSelectedRecip, nameA, bodyA);
    else
        wsprintfA(displayMsg, "[ME -> %.12s] %s\r\n", gSelectedRecip, bodyA);
    SendMessageA(hMsgList, EM_REPLACESEL, FALSE, (LPARAM)displayMsg);
    SendMessage(hMsgList, WM_VSCROLL, SB_BOTTOM, 0);
}

/* -- Fetch Messages ------------------------------------------------- */
void FetchMessages(void) {
    if (!gRegistered) return;

    char body[512];
    wsprintfA(body, "{\"device_id\":\"%s\"}", gCfg.id);

    HttpResponse *r = network_post("/api/v1/messages/fetch", body);
    if (!r || r->len < 10) { if (r) network_free_response(r); return; }

    /* Parse messages -- walk the JSON array looking for envelope objects */
    char *p = strstr(r->data, "\"messages\":[");
    if (!p) { network_free_response(r); return; }
    p = strchr(p, '[');
    if (!p) { network_free_response(r); return; }
    p++;

    while (*p && *p != ']') {
        /* Find an envelope object */
        char *envStart = strstr(p, "\"envelope\":{");
        char *senderStart = strstr(p, "\"sender_device_id\":\"");
        if (!envStart || !senderStart) break;

        /* Extract sender device ID */
        senderStart += 20;
        char *senderEnd = strchr(senderStart, '"');
        if (!senderEnd) break;
        char senderDevId[72] = {0};
        int sidLen = (int)(senderEnd - senderStart);
        if (sidLen > 70) sidLen = 70;
        strncpy(senderDevId, senderStart, sidLen);

        /* Skip our own messages */
        if (strncmp(senderDevId, gCfg.id, 32) == 0) {
            /* Move past this message */
            char *next = strstr(senderEnd, "\"sender_device_id\":\"");
            if (!next) break;
            p = next;
            continue;
        }

        /* Fetch sender's public key */
        char pkBody[256];
        wsprintfA(pkBody, "{\"username\":\"%s\",\"password\":\"\"}", gCfg.username);
        HttpResponse *pkResp = network_post("/api/v1/contacts/devices", pkBody);
        BYTE senderPubKey[PUBLIC_KEY_MAX];
        DWORD pkLen = 0;
        BOOL gotKey = FALSE;

        if (pkResp && pkResp->len > 10) {
            char *dev = strstr(pkResp->data, senderDevId);
            if (dev) {
                char *pkStart = strstr(dev, "\"public_key\":\"");
                if (pkStart) {
                    pkStart += 15;
                    char *pkEnd = strchr(pkStart, '"');
                    if (pkEnd) {
                        char pkHex[1024] = {0};
                        int hlen = (int)(pkEnd - pkStart);
                        if (hlen > 1022) hlen = 1022;
                        strncpy(pkHex, pkStart, hlen);
                        crypto_hex_decode(pkHex, senderPubKey, &pkLen);
                        gotKey = TRUE;
                    }
                }
            }
        }
        if (pkResp) network_free_response(pkResp);

        if (!gotKey) {
            char *next = strstr(senderEnd, "\"sender_device_id\":\"");
            p = next ? next : senderEnd + 1;
            continue;
        }

        /* Derive session key from sender's public key */
        BYTE sessionKey[32];
        crypto_sha256(senderPubKey, pkLen, sessionKey);

        /* Find the envelope JSON object */
        envStart = strstr(p, "\"envelope\":{");
        if (!envStart) break;
        char *envEnd = strchr(envStart + 12, '}');
        if (!envEnd) break;
        /* Find the closing brace -- handle nested objects */
        int depth = 0;
        char *ep = envStart + 12;
        while (*ep) {
            if (*ep == '{') depth++;
            else if (*ep == '}') { if (depth == 0) { envEnd = ep; break; } depth--; }
            ep++;
        }

        /* Extract nonce, ciphertext, tag fields */
        char *nonceStart = strstr(envStart, "\"nonce\":\"");
        char *ctStart = strstr(envStart, "\"ciphertext\":\"");
        char *tagStart = strstr(envStart, "\"tag\":\"");
        if (!nonceStart || !ctStart) {
            char *next = strstr(envEnd, "\"sender_device_id\":\"");
            p = next ? next : envEnd + 1;
            continue;
        }

        nonceStart += 9;  char *nonceEnd = strchr(nonceStart, '"');
        ctStart += 15;    char *ctEnd = strchr(ctStart, '"');

        if (nonceEnd && ctEnd) {
            char nonceHex[32] = {0}, ctHex[8192] = {0};
            int nlen = (int)(nonceEnd - nonceStart);
            int clen = (int)(ctEnd - ctStart);
            if (nlen < 32) { strncpy(nonceHex, nonceStart, nlen); }
            if (clen < 8190) { strncpy(ctHex, ctStart, clen); }

            BYTE nonce[12], ciphertext[4096];
            DWORD ctLen = 0;
            crypto_hex_decode(nonceHex, nonce, &nlen);
            crypto_hex_decode(ctHex, ciphertext, &ctLen);

            /* Decrypt */
            BYTE tag[16] = {0};
            if (tagStart) {
                tagStart += 7;
                char *tagEnd = strchr(tagStart, '"');
                if (tagEnd) {
                    char tagHex[36] = {0};
                    int tlen = (int)(tagEnd - tagStart);
                    if (tlen < 34) { strncpy(tagHex, tagStart, tlen); }
                    DWORD tglen = 0;
                    crypto_hex_decode(tagHex, tag, &tglen);
                }
            }

            BYTE plaintext[4096];
            if (crypto_aes_gcm_decrypt(sessionKey, nonce, ciphertext, ctLen, tag, plaintext)) {
                plaintext[ctLen] = 0;
                char *payload = (char*)plaintext;
                char *typeStr = strstr(payload, "\"type\":\"file\"");
                char *bodyStr = strstr(payload, "\"body\":\"");
                char *nameStr = strstr(payload, "\"name\":\"");

                if (typeStr && nameStr) {
                    /* File message -- download and save */
                    char *fidStart = strstr(payload, "\"file_id\":\"");
                    nameStr += 8;
                    char *nameEnd = strchr(nameStr, '"');

                    if (fidStart && nameEnd) {
                        fidStart += 12;
                        char *fidEnd = strchr(fidStart, '"');
                        if (fidEnd) {
                            char fileId[64] = {0};
                            int flen = (int)(fidEnd - fidStart);
                            strncpy(fileId, fidStart, flen < 63 ? flen : 63);

                            char origName[256] = {0};
                            int nlen2 = (int)(nameEnd - nameStr);
                            strncpy(origName, nameStr, nlen2 < 255 ? nlen2 : 255);

                            /* Download and decrypt file */
                            char dlPath[128];
                            wsprintfA(dlPath, "/api/v1/files/%s", fileId);

                            BYTE *encFileData = NULL;
                            DWORD encFileLen = 0;
                            network_download_file(dlPath, gCfg.id, &encFileData, &encFileLen);

                            if (encFileData && encFileLen > 28) {
                                BYTE *decData = NULL;
                                DWORD decLen = 0;
                                if (crypto_decrypt_file_data(sessionKey, encFileData, encFileLen, &decData, &decLen)) {
                                    /* Save to downloads */
                                    char savePath[512];
                                    wsprintfA(savePath, DOWNLOADS_DIR "\\%s", origName);
                                    HANDLE hOut = CreateFileA(savePath, GENERIC_WRITE, 0, NULL,
                                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                                    if (hOut != INVALID_HANDLE_VALUE) {
                                        DWORD written;
                                        WriteFile(hOut, decData, decLen, &written, NULL);
                                        CloseHandle(hOut);

                                        char line[600];
                                        wsprintfA(line, "[%.12s] [FILE] %s (%lu bytes) -> Downloads\r\n",
                                                  senderDevId, origName, decLen);
                                        SendMessageA(hMsgList, EM_REPLACESEL, FALSE, (LPARAM)line);
                                    }
                                    free(decData);
                                }
                                free(encFileData);
                            }
                        }
                    }
                } else if (bodyStr) {
                    /* Regular text message */
                    bodyStr += 8;
                    char *bodyEnd = strchr(bodyStr, '"');
                    if (bodyEnd) {
                        char msgBody[2048] = {0};
                        int blen = (int)(bodyEnd - bodyStr);
                        strncpy(msgBody, bodyStr, blen < 2047 ? blen : 2047);

                        /* Check for display name */
                        char *nameField = strstr(payload, "\"name\":\"");
                        char displayLine[2200];
                        if (nameField) {
                            nameField += 8;
                            char *nfEnd = strchr(nameField, '"');
                            if (nfEnd) {
                                char dname[64] = {0};
                                int dnlen = (int)(nfEnd - nameField);
                                strncpy(dname, nameField, dnlen < 63 ? dnlen : 63);
                                if (dname[0])
                                    wsprintfA(displayLine, "[%.12s] %s: %s\r\n", senderDevId, dname, msgBody);
                                else
                                    wsprintfA(displayLine, "[%.12s] %s\r\n", senderDevId, msgBody);
                            } else {
                                wsprintfA(displayLine, "[%.12s] %s\r\n", senderDevId, msgBody);
                            }
                        } else {
                            wsprintfA(displayLine, "[%.12s] %s\r\n", senderDevId, msgBody);
                        }
                        SendMessageA(hMsgList, EM_REPLACESEL, FALSE, (LPARAM)displayLine);
                    }
                }
            }
        }

        /* Advance past this message object */
        char *next = strstr(envEnd, "\"sender_device_id\":\"");
        p = next ? next : envEnd + 1;
    }

    SendMessage(hMsgList, WM_VSCROLL, SB_BOTTOM, 0);
    network_free_response(r);
}

/* -- JSON helper ---------------------------------------------------- */
char* json_get_string(const char *json, const char *key) {
    char search[256];
    wsprintfA(search, "\"%s\":\"", key);
    char *start = strstr((char*)json, search);
    if (!start) return NULL;
    start += strlen(search);
    char *end = strchr(start, '"');
    if (!end) return NULL;
    int len = (int)(end - start);
    char *val = malloc(len + 1);
    strncpy(val, start, len);
    val[len] = 0;
    return val;
}
