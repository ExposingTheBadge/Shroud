/*
 * SHROUD Qt6 Client — Clean cross-platform desktop client
 * Compile: cmake -B build && cmake --build build --config Release
 */
#include <QtWidgets>
#include <QtNetwork>
#include <QtCore>

/* CLIENT_VERSION is injected by CMake from PROJECT_VERSION (which mirrors
 * the repo VERSION file). Fallback string here is only used when somebody
 * builds main.cpp outside the project CMakeLists — never in release. */
#ifndef CLIENT_VERSION
#define CLIENT_VERSION "0.0.0-localdev"
#endif

extern "C" {
#include <QRegularExpression>
#include "client.h"
extern "C" {
#include "ratchet.h"
}
#include "error_reporter.h"
#include "anon_client.h"
}

/* ===================================================================
 *  THEME — Dark/Light stylesheets
 * =================================================================== */
/* ===================================================================
 *  Theme palette — PowerShell/Terminal-style. A Theme holds nine colors
 *  that drive the entire app stylesheet (NOT just the chat). Users can
 *  pick a named preset or roll their own via QColorDialog. The current
 *  theme is persisted to HKCU and reloaded on next launch.
 * =================================================================== */
struct Theme {
    QString name;
    QColor bg;          // window background
    QColor surface;     // panels, list backgrounds
    QColor input;       // text-input background
    QColor border;      // separator lines
    QColor text;        // primary foreground — applies to ALL labels/inputs/lists
    QColor dim;         // secondary text (placeholders, status)
    QColor accent;      // buttons-pressed, selection, focus
    QColor link;        // hyperlinks and contact names in chat
    QColor danger;      // destructive actions
};

static QList<Theme> THEME_PRESETS = {
    /* Default — SHROUD dark/orange (unchanged from v2.0) */
    {"SHROUD Dark",       "#1a1a1a", "#222222", "#2d2d2d", "#333333", "#cccccc", "#888888", "#ff8c1e", "#ff8c1e", "#cc3333"},
    {"SHROUD Light",      "#ffffff", "#f5f5f0", "#f0f0e8", "#dddddd", "#1a1a1a", "#666666", "#ff8c1e", "#cc4400", "#cc0000"},
    {"Solarized Dark",       "#002b36", "#073642", "#073642", "#586e75", "#93a1a1", "#586e75", "#268bd2", "#b58900", "#dc322f"},
    {"Solarized Light",      "#fdf6e3", "#eee8d5", "#eee8d5", "#93a1a1", "#586e75", "#839496", "#268bd2", "#b58900", "#dc322f"},
    {"Nord",                 "#2e3440", "#3b4252", "#434c5e", "#4c566a", "#eceff4", "#88c0d0", "#5e81ac", "#88c0d0", "#bf616a"},
    {"Dracula",              "#282a36", "#1e1f29", "#44475a", "#44475a", "#f8f8f2", "#6272a4", "#bd93f9", "#8be9fd", "#ff5555"},
    {"Monokai",              "#272822", "#1e1f1c", "#3e3d32", "#75715e", "#f8f8f2", "#75715e", "#a6e22e", "#66d9ef", "#f92672"},
    {"One Dark",             "#282c34", "#21252b", "#3e4451", "#3e4451", "#abb2bf", "#7f848e", "#61afef", "#56b6c2", "#e06c75"},
    {"Tokyo Night",          "#1a1b26", "#16161e", "#24283b", "#414868", "#c0caf5", "#565f89", "#7aa2f7", "#bb9af7", "#f7768e"},
    {"Gruvbox Dark",         "#282828", "#3c3836", "#504945", "#665c54", "#ebdbb2", "#a89984", "#fe8019", "#83a598", "#fb4934"},
    {"Cobalt",               "#002240", "#001833", "#001b3a", "#3a4960", "#e0f0ff", "#7fa0c0", "#ffc600", "#ff9d00", "#ff628c"},
    {"High Contrast",        "#000000", "#0a0a0a", "#101010", "#444444", "#ffffff", "#bbbbbb", "#ffff00", "#00ffff", "#ff5555"},
};

static bool gDark = true;
static Theme gTheme = THEME_PRESETS[0];

static QString cN(const QColor &c) { return c.name(QColor::HexRgb); }

static bool isDarkTheme(const Theme &t) {
    return (t.bg.red() * 299 + t.bg.green() * 587 + t.bg.blue() * 114) / 1000 < 128;
}

/* Status colours (0 = ok, 1 = warn, 2 = error) tuned per background so
 * they stay readable on both light and dark palettes. Error reuses the
 * theme's own danger colour. */
static QColor statusColor(const Theme &t, int level) {
    bool dark = isDarkTheme(t);
    if (level == 0) return dark ? QColor("#3ddc84") : QColor("#1e8e3e");
    if (level == 1) return dark ? QColor("#ffb74d") : QColor("#b26a00");
    return t.danger;
}

QString themeQSS(const Theme &t) {
    QString s;
    QString bg = cN(t.bg), su = cN(t.surface), in = cN(t.input), bd = cN(t.border);
    QString tx = cN(t.text), dm = cN(t.dim), ac = cN(t.accent), lk = cN(t.link);
    /* On-accent text: pick black or white based on accent luminance.   */
    int lum = (t.accent.red() * 299 + t.accent.green() * 587 + t.accent.blue() * 114) / 1000;
    QString onAc = (lum > 160) ? "#1a1a1a" : "#ffffff";
    QString dg = cN(t.danger);
    s += QString("* { background-color: %1; color: %2; font-family: \"Segoe UI\", \"Segoe UI Emoji\", \"Noto Color Emoji\"; font-size: 10pt; }").arg(bg, tx);
    s += QString("QMainWindow { background-color: %1; }").arg(bg);
    s += QString("QMenuBar { background-color: %1; color: %2; border-bottom: 1px solid %3; padding: 2px; }").arg(su, tx, bd);
    s += QString("QMenuBar::item { padding: 4px 10px; border-radius: 4px; background: transparent; }");
    s += QString("QMenuBar::item:selected { background-color: %1; color: %2; }").arg(ac, onAc);
    s += QString("QMenu { background-color: %1; color: %2; border: 1px solid %3; padding: 4px; }").arg(su, tx, bd);
    s += QString("QMenu::item { padding: 6px 22px; border-radius: 4px; background: transparent; }");
    s += QString("QMenu::item:selected { background-color: %1; color: %2; }").arg(ac, onAc);
    s += QString("QMenu::separator { height: 1px; background: %1; margin: 4px 8px; }").arg(bd);
    s += QString("QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox { background-color: %1; color: %2; border: 1px solid %3; padding: 7px 9px; border-radius: 8px; selection-background-color: %4; selection-color: %5; }").arg(in, tx, bd, ac, onAc);
    s += QString("QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus { border: 1px solid %1; }").arg(ac);
    s += QString("QLineEdit:disabled { color: %1; }").arg(dm);
    s += QString("QLineEdit[invalid=\"true\"] { border: 1px solid %1; }").arg(dg);
    s += QString("QSpinBox::up-button, QSpinBox::down-button { background-color: %1; border: 0; width: 16px; }").arg(su);
    s += QString("QComboBox::drop-down { border: 0; width: 22px; }");
    s += QString("QComboBox QAbstractItemView { background-color: %1; color: %2; border: 1px solid %3; selection-background-color: %4; selection-color: %5; }").arg(su, tx, bd, ac, onAc);
    s += QString("QPushButton { background-color: %1; color: %2; border: 1px solid %3; padding: 7px 16px; border-radius: 8px; }").arg(in, tx, bd);
    s += QString("QPushButton:hover { background-color: %1; border-color: %2; }").arg(su, ac);
    s += QString("QPushButton:pressed { background-color: %1; color: %2; }").arg(ac, onAc);
    s += QString("QPushButton:disabled { background-color: %1; color: %2; border-color: %3; }").arg(bg, dm, bd);
    /* Primary call-to-action: filled with the accent colour. */
    s += QString("QPushButton#primary { background-color: %1; color: %2; border: 1px solid %1; font-weight: 600; }").arg(ac, onAc);
    s += QString("QPushButton#primary:hover { background-color: %1; border-color: %1; }").arg(cN(t.accent.lighter(115)));
    s += QString("QPushButton#primary:pressed { background-color: %1; }").arg(cN(t.accent.darker(120)));
    s += QString("QPushButton#primary:disabled { background-color: %1; color: %2; border-color: %3; }").arg(su, dm, bd);
    /* Text-only link button. */
    s += QString("QPushButton#link { background: transparent; border: none; color: %1; padding: 4px; }").arg(lk);
    s += QString("QPushButton#link:hover { text-decoration: underline; background: transparent; }");
    /* Destructive action. */
    s += QString("QPushButton#danger { background-color: %1; color: #ffffff; border: 1px solid %1; font-weight: 600; }").arg(dg);
    /* Segmented toggle (Contacts / Groups) and small icon buttons. */
    s += QString("QPushButton#segment { border-radius: 8px; padding: 6px 10px; background: transparent; border: 1px solid transparent; color: %1; }").arg(dm);
    s += QString("QPushButton#segment:checked { background-color: %1; color: %2; border: 1px solid %3; font-weight: 600; }").arg(in, tx, bd);
    s += QString("QPushButton#iconBtn { font-size: 13pt; padding: 3px 8px; border-radius: 8px; background: transparent; border: 1px solid transparent; }");
    s += QString("QPushButton#iconBtn:hover { background-color: %1; border-color: %2; }").arg(in, bd);
    s += QString("QPushButton#iconBtn:checked { background-color: %1; color: %2; border-color: %1; }").arg(ac, onAc);
    s += QString("QListWidget { background-color: %1; color: %2; border: none; outline: 0; }").arg(su, tx);
    s += QString("QListWidget::item { padding: 6px 8px; border-radius: 8px; margin: 1px 2px; }");
    s += QString("QListWidget::item:hover { background-color: %1; }").arg(in);
    s += QString("QListWidget::item:selected { background-color: %1; color: %2; }").arg(ac, onAc);
    s += QString("QCheckBox, QRadioButton { color: %1; spacing: 8px; background: transparent; }").arg(tx);
    /* Draw the indicators ourselves: with a stylesheet on "*" the native
     * box can vanish against light backgrounds. */
    s += QString("QCheckBox::indicator, QRadioButton::indicator { width: 16px; height: 16px; border: 1px solid %1; background-color: %2; }").arg(dm, in);
    s += QString("QCheckBox::indicator { border-radius: 4px; }");
    s += QString("QRadioButton::indicator { border-radius: 9px; }");
    s += QString("QCheckBox::indicator:hover, QRadioButton::indicator:hover { border-color: %1; }").arg(ac);
    s += QString("QCheckBox::indicator:checked { background-color: %1; border-color: %1; image: url(%2); }").arg(ac, onAc == "#ffffff" ? ":/check-light.png" : ":/check-dark.png");
    s += QString("QRadioButton::indicator:checked { background-color: %1; border: 4px solid %2; }").arg(ac, in);
    s += QString("QCheckBox::indicator:disabled, QRadioButton::indicator:disabled { border-color: %1; }").arg(bd);
    s += QString("QGroupBox { color: %1; border: 1px solid %2; border-radius: 10px; margin-top: 14px; padding: 14px 10px 10px 10px; }").arg(tx, bd);
    s += QString("QGroupBox::title { color: %1; subcontrol-origin: margin; left: 12px; padding: 0 4px; font-weight: 600; }").arg(dm);
    s += QString("QLabel { color: %1; background: transparent; }").arg(tx);
    s += QString("QLabel#muted { color: %1; }").arg(dm);
    s += QString("QLabel#heading { font-size: 18pt; font-weight: 700; }");
    s += QString("QLabel#subheading { font-size: 12pt; font-weight: 600; }");
    s += QString("QLabel#hint { color: %1; font-size: 9pt; }").arg(dm);
    /* Status pills — state property is set by setStatusLabel(). */
    s += QString("QLabel[state=\"ok\"]   { color: %1; font-weight: 600; }").arg(cN(statusColor(t, 0)));
    s += QString("QLabel[state=\"warn\"] { color: %1; font-weight: 600; }").arg(cN(statusColor(t, 1)));
    s += QString("QLabel[state=\"err\"]  { color: %1; font-weight: 600; }").arg(cN(statusColor(t, 2)));
    s += QString("QLabel[state=\"info\"] { color: %1; }").arg(dm);
    s += QString("QWidget#sidebar { background-color: %1; border-right: 1px solid %2; }").arg(su, bd);
    s += QString("QWidget#sidebar QLabel, QWidget#sidebar QCheckBox { background: transparent; }");
    s += QString("QWidget#chatHeader { background-color: %1; border-bottom: 1px solid %2; }").arg(bg, bd);
    s += QString("QWidget#composer { background-color: %1; border-top: 1px solid %2; }").arg(bg, bd);
    s += QString("QWidget#card { background-color: %1; border: 1px solid %2; border-radius: 14px; }").arg(su, bd);
    s += QString("QWidget#card QLabel, QWidget#card QCheckBox { background: transparent; }");
    s += QString("QFrame#banner { background-color: %1; border: 1px solid %2; border-radius: 8px; }").arg(in, bd);
    s += QString("QTextBrowser#chatLog { border: none; background-color: %1; padding: 6px 10px; }").arg(bg);
    s += QString("QProgressBar { background-color: %1; border: none; border-radius: 3px; max-height: 6px; }").arg(in);
    s += QString("QProgressBar::chunk { border-radius: 3px; background-color: %1; }").arg(ac);
    s += QString("QTabWidget::pane { border: 1px solid %1; background-color: %2; border-radius: 8px; top: -1px; }").arg(bd, bg);
    s += QString("QTabBar::tab { background-color: transparent; color: %1; padding: 7px 14px; border: none; border-bottom: 2px solid transparent; }").arg(dm);
    s += QString("QTabBar::tab:hover { color: %1; }").arg(tx);
    s += QString("QTabBar::tab:selected { color: %1; border-bottom: 2px solid %2; }").arg(tx, ac);
    s += QString("QScrollBar:vertical { background: transparent; width: 10px; border: 0; margin: 2px; }");
    s += QString("QScrollBar::handle:vertical { background: %1; border-radius: 4px; min-height: 24px; }").arg(bd);
    s += QString("QScrollBar::handle:vertical:hover { background: %1; }").arg(dm);
    s += QString("QScrollBar:horizontal { background: transparent; height: 10px; border: 0; margin: 2px; }");
    s += QString("QScrollBar::handle:horizontal { background: %1; border-radius: 4px; min-width: 24px; }").arg(bd);
    s += QString("QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }");
    s += QString("QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }");
    s += QString("QStatusBar { background-color: %1; color: %2; border-top: 1px solid %3; }").arg(su, dm, bd);
    s += QString("QStatusBar QLabel { color: %1; padding: 0 6px; }").arg(dm);
    s += QString("QToolTip { background-color: %1; color: %2; border: 1px solid %3; padding: 5px 8px; border-radius: 6px; }").arg(su, tx, bd);
    s += QString("QDialog { background-color: %1; }").arg(bg);
    return s;
}

static const Theme *findPreset(const QString &name) {
    for (const Theme &t : THEME_PRESETS) if (t.name == name) return &t;
    return nullptr;
}

/* Quick light/dark flip. Presets with a named counterpart ("X Dark" <->
 * "X Light") swap to it; everything else (Nord, Dracula, Custom...) goes
 * to the SHROUD pair, so the toggle always does something visible
 * instead of only working on the two default themes. */
static void toggleLightDark() {
    bool dark = isDarkTheme(gTheme);
    QString name = gTheme.name;
    QString twin = dark ? QString(name).replace("Dark", "Light")
                        : QString(name).replace("Light", "Dark");
    const Theme *t = (twin != name) ? findPreset(twin) : nullptr;
    if (!t) t = findPreset(dark ? "SHROUD Light" : "SHROUD Dark");
    if (t) gTheme = *t;
    gDark = isDarkTheme(gTheme);
    qApp->setStyleSheet(themeQSS(gTheme));
}

/* Set a label's text plus a state ("ok"/"warn"/"err"/"info") that the
 * stylesheet colours, so status text follows the active theme instead of
 * carrying hard-coded colours. */
static void setStatusLabel(QLabel *l, const QString &text, const char *state) {
    if (!l) return;
    l->setText(text);
    if (l->property("state").toString() != QLatin1String(state)) {
        l->setProperty("state", state);
        l->style()->unpolish(l);
        l->style()->polish(l);
    }
}

/* Mark an input as invalid (red border) or clear the mark. */
static void setInvalid(QWidget *w, bool bad) {
    if (!w || w->property("invalid").toBool() == bad) return;
    w->setProperty("invalid", bad);
    w->style()->unpolish(w);
    w->style()->polish(w);
}

/* Round letter avatar with a colour derived from the name, so each
 * contact is recognisable at a glance without any profile picture (and
 * therefore without any extra data leaving the device). */
static QIcon avatarIcon(const QString &name, int size = 32, bool group = false) {
    QPixmap pm(size * 2, size * 2);
    pm.setDevicePixelRatio(2.0);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    uint h = qHash(name.toLower());
    QColor c = QColor::fromHsl((int)(h % 360), 150, 110);
    p.setBrush(c);
    p.setPen(Qt::NoPen);
    if (group) p.drawRoundedRect(QRectF(0, 0, size, size), size * 0.28, size * 0.28);
    else       p.drawEllipse(QRectF(0, 0, size, size));
    QString letter = group ? QString("#") : name.left(1).toUpper();
    if (letter.isEmpty()) letter = "?";
    QFont f("Segoe UI", 1, QFont::DemiBold);
    f.setPixelSize(int(size * 0.46));
    p.setFont(f);
    p.setPen(Qt::white);
    p.drawText(QRectF(0, 0, size, size), Qt::AlignCenter, letter);
    return QIcon(pm);
}

/* ── User preferences (theme, disappearing messages, rich text) ─── */
static bool gDisappearEnabled = false;
static int  gDisappearSeconds = 60;
static bool gRichText = true;
static bool gFlashOnMessage = true;   /* flash the taskbar button on new messages */

/* Network-layer transport selector — one transport at a time, exclusive.
 *
 * This deals with *one* specific threat: an on-path observer (ISP, gateway,
 * server-side logger) linking a client IP to a username over time. The rest
 * of the anonymity stack (E2EE Double Ratchet, padded envelopes, RSA-3072
 * blind-signature anonymous credentials, PII-free signup) is already in
 * effect whether this is set to Direct or Tor.
 *
 *   Direct: WinHTTP talks straight to the server. Default.
 *   Tor   : SOCKS5 -> local tor daemon (127.0.0.1:9050 stock, 9150 Browser).
 *           Hides client IP from the server and server IP from the client.
 *           See docs/tor.md.
 *
 * Failure semantics: fails closed. If tor isn't running, requests error out
 * — we never silently fall back to clearnet. */
enum class Transport { Direct = 0, Tor = 1 };

static Transport gTransport = Transport::Direct;
static QString   gTorProxy  = "127.0.0.1:9050";

static void applyTransport() {
    if (gTransport == Transport::Tor) {
        QByteArray a = ("socks=" + gTorProxy).toUtf8();
        network_set_proxy(a.constData());
    } else {
        network_set_proxy(NULL);
    }
}

/* Minimal Markdown → safe HTML: **bold**, *italic*, `code`, autolinks.
 * Always escapes < > & first so user text can't inject raw HTML. When
 * gRichText is false the body is just escaped and returned verbatim. */
QString mdToHtml(QString s) {
    s = s.toHtmlEscaped();
    if (!gRichText) return s;
    QRegularExpression bold("\\*\\*([^*\\n]+?)\\*\\*");
    s.replace(bold, "<b>\\1</b>");
    QRegularExpression italic("(?<![\\w*])\\*([^*\\n]+?)\\*(?!\\w)");
    s.replace(italic, "<i>\\1</i>");
    QRegularExpression code("`([^`\\n]+?)`");
    s.replace(code, "<code style='background:rgba(128,128,128,0.18);padding:0 4px;border-radius:3px'>\\1</code>");
    QRegularExpression url("(https?://[^\\s<]+)");
    s.replace(url, QString("<a href=\"\\1\" style='color:%1'>\\1</a>").arg(cN(gTheme.link)));
    return s;
}

static void loadUserPrefs() {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\SHROUD\\Prefs", 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
    DWORD val, sz = sizeof(val);
    char str[128]; DWORD ssz;
    if (RegQueryValueExA(hk, "Dark", NULL, NULL, (BYTE*)&val, &sz) == ERROR_SUCCESS) gDark = val != 0;
    if (RegQueryValueExA(hk, "DisappearEnabled", NULL, NULL, (BYTE*)&val, &sz) == ERROR_SUCCESS) gDisappearEnabled = val != 0;
    if (RegQueryValueExA(hk, "DisappearSec",     NULL, NULL, (BYTE*)&val, &sz) == ERROR_SUCCESS) gDisappearSeconds = (int)val;
    if (RegQueryValueExA(hk, "RichText",         NULL, NULL, (BYTE*)&val, &sz) == ERROR_SUCCESS) gRichText = val != 0;
    if (RegQueryValueExA(hk, "FlashOnMessage",   NULL, NULL, (BYTE*)&val, &sz) == ERROR_SUCCESS) gFlashOnMessage = val != 0;
    /* Transport selector (Direct / Tor). v2.3.0 stored TorEnabled as a bool;
     * v2.3.1 briefly added a Transport DWORD with a Nym value (removed in
     * v2.3.2). Honor TorEnabled for back-compat, then accept Transport but
     * clamp away any leftover value of 2 (Nym) to Direct. */
    if (RegQueryValueExA(hk, "TorEnabled", NULL, NULL, (BYTE*)&val, &sz) == ERROR_SUCCESS)
        gTransport = val ? Transport::Tor : Transport::Direct;
    if (RegQueryValueExA(hk, "Transport", NULL, NULL, (BYTE*)&val, &sz) == ERROR_SUCCESS) {
        if (val == (DWORD)Transport::Tor)         gTransport = Transport::Tor;
        else if (val == (DWORD)Transport::Direct) gTransport = Transport::Direct;
        /* anything else (Nym=2 from v2.3.1) falls back to Direct */
    }
    char proxyBuf[128]; DWORD pssz = sizeof(proxyBuf);
    if (RegQueryValueExA(hk, "TorProxy", NULL, NULL, (BYTE*)proxyBuf, &pssz) == ERROR_SUCCESS) {
        gTorProxy = QString::fromUtf8(proxyBuf);
    }
    ssz = sizeof(str);
    if (RegQueryValueExA(hk, "ThemeName", NULL, NULL, (BYTE*)str, &ssz) == ERROR_SUCCESS) {
        QString want = QString::fromUtf8(str);
        for (const Theme &t : THEME_PRESETS) if (t.name == want) { gTheme = t; break; }
    }
    /* Custom palette overrides individual colors when set. */
    auto loadColor = [&](const char *k, QColor &out) {
        DWORD v, s = sizeof(v);
        if (RegQueryValueExA(hk, k, NULL, NULL, (BYTE*)&v, &s) == ERROR_SUCCESS && v != 0) {
            out = QColor::fromRgb((v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
        }
    };
    if (gTheme.name == "Custom") {
        loadColor("Custom_bg", gTheme.bg);
        loadColor("Custom_surface", gTheme.surface);
        loadColor("Custom_input", gTheme.input);
        loadColor("Custom_border", gTheme.border);
        loadColor("Custom_text", gTheme.text);
        loadColor("Custom_dim", gTheme.dim);
        loadColor("Custom_accent", gTheme.accent);
        loadColor("Custom_link", gTheme.link);
        loadColor("Custom_danger", gTheme.danger);
    }
    RegCloseKey(hk);
    /* The theme is the source of truth for light vs dark. */
    gDark = isDarkTheme(gTheme);
}

static void saveUserPrefs() {
    HKEY hk;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\SHROUD\\Prefs", 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hk, NULL) != ERROR_SUCCESS) return;
    DWORD v;
    v = gDark ? 1 : 0;                RegSetValueExA(hk, "Dark", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    v = gDisappearEnabled ? 1 : 0;    RegSetValueExA(hk, "DisappearEnabled", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    v = (DWORD)gDisappearSeconds;     RegSetValueExA(hk, "DisappearSec", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    v = gRichText ? 1 : 0;            RegSetValueExA(hk, "RichText", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    v = gFlashOnMessage ? 1 : 0;      RegSetValueExA(hk, "FlashOnMessage", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    v = static_cast<DWORD>(gTransport); RegSetValueExA(hk, "Transport", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    /* Keep TorEnabled written too, so v2.3.0 installs that read this key
     * (e.g. a downgrade) still see the right Tor state. */
    v = (gTransport == Transport::Tor) ? 1 : 0;
    RegSetValueExA(hk, "TorEnabled", 0, REG_DWORD, (BYTE*)&v, sizeof(v));
    QByteArray tp = gTorProxy.toUtf8();
    RegSetValueExA(hk, "TorProxy", 0, REG_SZ, (BYTE*)tp.constData(), tp.size() + 1);
    /* Best-effort cleanup of v2.3.1 Nym leftovers; ignore failures. */
    RegDeleteValueA(hk, "NymProxy");
    RegDeleteValueA(hk, "NymSpAddress");
    QByteArray nm = gTheme.name.toUtf8();
    RegSetValueExA(hk, "ThemeName", 0, REG_SZ, (BYTE*)nm.constData(), nm.size() + 1);
    auto saveColor = [&](const char *k, const QColor &c) {
        DWORD pack = (c.red() << 16) | (c.green() << 8) | c.blue();
        if (pack == 0) pack = 0x000001;  /* avoid collision with sentinel 0 */
        RegSetValueExA(hk, k, 0, REG_DWORD, (BYTE*)&pack, sizeof(pack));
    };
    if (gTheme.name == "Custom") {
        saveColor("Custom_bg", gTheme.bg);
        saveColor("Custom_surface", gTheme.surface);
        saveColor("Custom_input", gTheme.input);
        saveColor("Custom_border", gTheme.border);
        saveColor("Custom_text", gTheme.text);
        saveColor("Custom_dim", gTheme.dim);
        saveColor("Custom_accent", gTheme.accent);
        saveColor("Custom_link", gTheme.link);
        saveColor("Custom_danger", gTheme.danger);
    }
    RegCloseKey(hk);
}

/* ===================================================================
 *  Password reveal icon — eye with lashes, drawn at runtime
 * =================================================================== */
static QIcon eyeIcon(bool open) {
    QPixmap pm(18, 18);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    QColor col = gDark ? QColor(180, 180, 180) : QColor(80, 80, 80);
    p.setPen(QPen(col, 1.4));
    p.setBrush(Qt::NoBrush);
    /* Almond eye shape */
    QPainterPath eye;
    eye.moveTo(2, 9);
    eye.quadTo(9, open ? 2 : 6, 16, 9);
    eye.quadTo(9, open ? 16 : 12, 2, 9);
    p.drawPath(eye);
    /* Lashes (top) */
    p.drawLine(QPointF(9,  1.5), QPointF(9,  3.5));
    p.drawLine(QPointF(4.5, 2.5), QPointF(5.5, 4.5));
    p.drawLine(QPointF(13.5, 2.5), QPointF(12.5, 4.5));
    if (open) {
        p.setBrush(col);
        p.drawEllipse(QPointF(9, 9), 2.2, 2.2);
    } else {
        /* Slash through the closed eye */
        p.setPen(QPen(col, 1.4));
        p.drawLine(QPointF(3, 4), QPointF(15, 14));
    }
    return QIcon(pm);
}

static void attachPasswordReveal(QLineEdit *field) {
    QAction *act = field->addAction(eyeIcon(false), QLineEdit::TrailingPosition);
    act->setToolTip("Show password");
    QObject::connect(act, &QAction::triggered, field, [field, act]() {
        bool shown = field->echoMode() == QLineEdit::Normal;
        field->setEchoMode(shown ? QLineEdit::Password : QLineEdit::Normal);
        act->setIcon(eyeIcon(!shown));
        act->setToolTip(shown ? "Show password" : "Hide password");
    });
}

/* ===================================================================
 *  ImageViewer — borderless full-screen image dialog with a very
 *  visible X close button (top-right) and a delete option.
 * =================================================================== */
class ImageViewer : public QDialog {
    Q_OBJECT
public:
    ImageViewer(const QString &fileId, const QString &path, QWidget *parent = nullptr)
        : QDialog(parent), m_fileId(fileId)
    {
        setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
        setAttribute(Qt::WA_DeleteOnClose);
        setModal(true);
        setStyleSheet("QDialog { background-color: rgba(0,0,0,235); }");

        QImage src(path);
        if (src.isNull()) {
            QMessageBox::warning(this, "Image", "Could not load image."); QTimer::singleShot(0, this, &QDialog::reject); return;
        }
        QScreen *scr = QGuiApplication::primaryScreen();
        QRect g = scr ? scr->availableGeometry() : QRect(0, 0, 1280, 720);
        const int margin = 60;
        QSize maxSize(g.width() - margin, g.height() - margin);
        QImage scaled = src.scaled(maxSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);

        resize(g.size());
        move(g.topLeft());

        auto *layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);

        m_label = new QLabel(this);
        m_label->setAlignment(Qt::AlignCenter);
        m_label->setPixmap(QPixmap::fromImage(scaled));
        layout->addWidget(m_label, 1);

        /* Top-right close button — bright, high-contrast, always visible. */
        m_close = new QPushButton("✕", this);  // ✕
        m_close->setFixedSize(48, 48);
        m_close->setCursor(Qt::PointingHandCursor);
        m_close->setToolTip("Close (Esc)");
        m_close->setStyleSheet(
            "QPushButton {"
            "  background-color: #ff8c1e; color: #1a1a1a;"
            "  border: 2px solid #ffffff; border-radius: 24px;"
            "  font-size: 22px; font-weight: bold;"
            "}"
            "QPushButton:hover { background-color: #ffa040; }"
            "QPushButton:pressed { background-color: #cc6e10; }"
        );
        connect(m_close, &QPushButton::clicked, this, &QDialog::accept);

        /* Bottom-right delete button. */
        m_del = new QPushButton("Delete", this);
        m_del->setFixedSize(120, 36);
        m_del->setCursor(Qt::PointingHandCursor);
        m_del->setStyleSheet(
            "QPushButton {"
            "  background-color: rgba(40,40,40,220); color: #ff8888;"
            "  border: 1px solid #ff8888; border-radius: 6px;"
            "  font-weight: bold;"
            "}"
            "QPushButton:hover { background-color: rgba(80,30,30,240); color: #ffaaaa; }"
        );
        connect(m_del, &QPushButton::clicked, this, [this]() {
            emit deleteRequested(m_fileId);
            accept();
        });

        positionOverlays();
    }

signals:
    void deleteRequested(const QString &fileId);

protected:
    void keyPressEvent(QKeyEvent *e) override {
        if (e->key() == Qt::Key_Escape) { accept(); return; }
        QDialog::keyPressEvent(e);
    }
    void resizeEvent(QResizeEvent *) override { positionOverlays(); }

private:
    void positionOverlays() {
        if (m_close) m_close->move(width() - m_close->width() - 24, 24);
        if (m_del)   m_del->move(width() - m_del->width() - 24,
                                  height() - m_del->height() - 24);
    }
    QString m_fileId;
    QLabel *m_label = nullptr;
    QPushButton *m_close = nullptr;
    QPushButton *m_del = nullptr;
};

/* ===================================================================
 *  MAIN WINDOW
 * =================================================================== */
class ShroudWindow : public QMainWindow {
    Q_OBJECT
public:
    ShroudWindow() {
        setWindowTitle("SHROUD Secure Messenger");
        resize(880, 620);
        loadUserPrefs();
        qApp->setStyleSheet(themeQSS(gTheme));

        /* Block screen-capture / screen-share tools from recording this
           window. WDA_EXCLUDEFROMCAPTURE is Win 10 2004+; degrades to
           WDA_MONITOR (black-out on capture) on older builds. */
#ifndef SHROUD_UI_PREVIEW
        HWND hwnd = (HWND)this->winId();
        if (!SetWindowDisplayAffinity(hwnd, /*WDA_EXCLUDEFROMCAPTURE=*/0x00000011)) {
            SetWindowDisplayAffinity(hwnd, /*WDA_MONITOR=*/0x00000001);
        }
#endif
        /* SHROUD_UI_PREVIEW is a developer-only build flag for looking at
         * UI changes against a local relay (see the note in
         * CMakeLists.txt): it leaves the window capturable so screenshots work
         * and keeps crash reports off the operator inbox. Release and CI
         * builds never define it. */

        /* Init crypto + network */
        crypto_init();
        network_init();
        applyTransport();          /* honor saved transport pref before first request */
        tpm_detect();
        kyber_init();

        /* Check saved identity */
        DeviceConfig cfg; ZeroMemory(&cfg, sizeof(cfg));
        if (storage_exists() && storage_load_config(&cfg) && storage_load_keypair(cfg.id, &cfg.identity_key)) {
            m_deviceId = cfg.id;
            m_username = cfg.username;
            m_deviceName = cfg.device_name;
            m_platform = cfg.platform;
            m_registered = true;
        }

        setupMenuBar();
        m_stack = new QStackedWidget;
        setCentralWidget(m_stack);

        if (m_registered) buildChatUI();
        else buildRegisterUI();

        /* Background update check on startup — silent unless a newer version
           is available. Delayed so it doesn't block UI paint. */
        QTimer::singleShot(2000, this, [this]() { checkForUpdates(false); });
    }

private:
    QStackedWidget *m_stack;
    QListWidget *m_sideList;
    QTextBrowser *m_chatLog;
    QMap<QString, QString> m_imagePaths; // file_id -> local plaintext image path
    QLineEdit *m_msgInput = nullptr;
    QPushButton *m_sendBtn = nullptr, *m_attachBtn = nullptr;
    QLabel *m_statusBar = nullptr;
    bool m_registered = false, m_tabGroups = false;
    bool m_maintenanceMode = false;   // server-wide; set from heartbeat + send 503s
    QString m_deviceId, m_username, m_deviceName, m_platform, m_password;
    QString m_selectedRecip;
    QStringList m_friends;
    QLabel *m_maintenanceBanner = nullptr;

    /* ── Anonymous routing (Rules 1 & 2) ──────────────────────────────
     * The legacy /messages/{send,fetch} path posts sender_device_id and
     * recipient_device_id in clear, so the relay learns exactly who is
     * talking to whom — the two things Rules 1 and 2 exist to prevent.
     * anon_client.cpp shipped and was compiled into the binary months
     * ago but nothing ever called it, so Windows stayed on the
     * identified path while Android moved over.
     *
     * On by default, matching the Android client's useAnonRouting flag.
     * Falls back to the legacy path per-message whenever a routing
     * context can't be built (peer has no published ratchet bundle,
     * i.e. a pre-v1.6 client), so a mixed fleet keeps working. */
    bool m_anonRouting = true;
    QHash<QString, QByteArray> m_peerX25519;   // device_id -> 32-byte pub

    /* Single source of truth for whether the server is in maintenance.
     * Called from the heartbeat poll and from any send-attempt that
     * gets a 503. Flips the banner, disables the send button + input,
     * and reverts everything when maintenance ends. */
    void setMaintenanceMode(bool on) {
        m_maintenanceMode = on;
        if (m_maintenanceBanner) {
            QWidget *wrap = qobject_cast<QWidget*>(m_maintenanceBanner->property("wrap").value<QObject*>());
            (wrap ? wrap : (QWidget*)m_maintenanceBanner)->setVisible(on);
        }
        updateComposerState();
    }

    /* Search result panel widgets — built once in buildChatUI, shown when a
       lookup hits or misses. */
    QWidget *m_searchResult = nullptr;
    QLabel *m_searchResultLabel = nullptr;
    QPushButton *m_btnMsg = nullptr, *m_btnFriend = nullptr, *m_btnGroupInvite = nullptr;
    QString m_searchHit;          // username of currently-shown search result (empty if miss)
    bool m_searchHitIsFriend = false;

    /* Inject-safe JSON builder. Uses Qt's encoder so quotes, backslashes,
       control chars, and unicode in user input get escaped properly. */
    static QByteArray jsonBody(std::initializer_list<std::pair<QString, QVariant>> fields) {
        QJsonObject obj;
        for (const auto &p : fields) obj.insert(p.first, QJsonValue::fromVariant(p.second));
        return QJsonDocument(obj).toJson(QJsonDocument::Compact);
    }

    /* Network helper: call C module and return QByteArray */
    QByteArray httpPost(const char *path, const char *body) {
        HttpResponse *r = network_post(path, body);
        QByteArray data;
        if (r && r->len > 0) { data = QByteArray(r->data, (int)r->len); network_free_response(r); }
        return data;
    }

    /* Overload that takes a pre-built JSON body. */
    QByteArray httpPost(const char *path, const QByteArray &body) {
        return httpPost(path, body.constData());
    }

    /* Overload that adds an extra HTTP header (e.g. X-Expires-In for
     * disappearing messages). header should be a single "Name: Value" line. */
    QByteArray httpPost(const char *path, const QByteArray &body, const QByteArray &header) {
        HttpResponse *r = network_post_h(path, body.constData(),
            header.isEmpty() ? nullptr : header.constData());
        QByteArray data;
        if (r && r->len > 0) { data = QByteArray(r->data, (int)r->len); network_free_response(r); }
        return data;
    }

    QByteArray httpGet(const char *path) {
        HttpResponse *r = network_get(path);
        QByteArray data;
        if (r && r->len > 0) { data = QByteArray(r->data, (int)r->len); network_free_response(r); }
        return data;
    }

    QString jsonStr(const QByteArray &j, const char *k) {
        char *v = json_get_string(j.constData(), k);
        QString s = v ? QString::fromUtf8(v) : QString();
        if (v) free(v);
        return s;
    }

    /* ===============================================================
     *  MENU BAR
     * =============================================================== */
    /* Naive semver compare: returns +1 if a>b, -1 if a<b, 0 if equal. */
    static int versionCompare(const QString &a, const QString &b) {
        QStringList pa = a.split('.'), pb = b.split('.');
        int n = pa.size() > pb.size() ? pa.size() : pb.size();
        for (int i = 0; i < n; i++) {
            int ai = (i < pa.size()) ? pa[i].toInt() : 0;
            int bi = (i < pb.size()) ? pb[i].toInt() : 0;
            if (ai != bi) return ai > bi ? 1 : -1;
        }
        return 0;
    }

    void setupMenuBar() {
        QMenu *file = menuBar()->addMenu("&File");
        QAction *upd = file->addAction("Check for &updates");
        connect(upd, &QAction::triggered, [this]() { checkForUpdates(true); });
        file->addSeparator();
        QAction *ex = file->addAction("E&xit");
        ex->setShortcut(QKeySequence("Ctrl+Q"));
        connect(ex, &QAction::triggered, this, &QWidget::close);

        QMenu *view = menuBar()->addMenu("&View");
        QAction *th = view->addAction("Switch &light / dark");
        th->setShortcut(QKeySequence("Ctrl+Shift+L"));
        connect(th, &QAction::triggered, this, [this]() {
            if (m_chatLog) onToggleTheme();
            else { toggleLightDark(); saveUserPrefs(); }
        });
        QAction *themes = view->addAction("&Themes and colours…");
        connect(themes, &QAction::triggered, [this]() { openSettings(0); });

        QMenu *sett = menuBar()->addMenu("&Settings");
        QAction *st = sett->addAction("&Settings…");
        st->setShortcut(QKeySequence("Ctrl+,"));
        connect(st, &QAction::triggered, [this]() { openSettings(0); });
        QAction *dis = sett->addAction("&Disappearing messages…");
        connect(dis, &QAction::triggered, [this]() { openSettings(1); });
        QAction *net = sett->addAction("&Network and Tor…");
        connect(net, &QAction::triggered, [this]() { openSettings(2); });
        QAction *dev = sett->addAction("&Link another device…");
        connect(dev, &QAction::triggered, [this]() { openSettings(3); });

        QMenu *help = menuBar()->addMenu("&Help");
        QAction *guide = help->addAction("&Quick guide");
        guide->setShortcut(QKeySequence::HelpContents);
        connect(guide, &QAction::triggered, [this]() { openSettings(5); });
        QAction *keys = help->addAction("&Keyboard shortcuts");
        connect(keys, &QAction::triggered, [this]() {
            QMessageBox box(this);
            box.setWindowTitle("Keyboard shortcuts");
            box.setTextFormat(Qt::RichText);
            box.setText(
                "<table cellpadding='4'>"
                "<tr><td><b>Enter</b></td><td>Send message</td></tr>"
                "<tr><td><b>Ctrl+K</b></td><td>Find someone by username</td></tr>"
                "<tr><td><b>Ctrl+F</b></td><td>Find in this conversation</td></tr>"
                "<tr><td><b>Ctrl+Tab</b></td><td>Next conversation (Ctrl+Shift+Tab: previous)</td></tr>"
                "<tr><td><b>Win + .</b></td><td>Emoji panel</td></tr>"
                "<tr><td><b>Ctrl+Shift+L</b></td><td>Switch light / dark</td></tr>"
                "<tr><td><b>Ctrl+,</b></td><td>Settings</td></tr>"
                "<tr><td><b>F1</b></td><td>Quick guide</td></tr>"
                "<tr><td><b>Esc</b></td><td>Close find bar / search result</td></tr>"
                "</table>");
            box.exec();
        });
        help->addSeparator();
        QAction *ab = help->addAction("&About SHROUD"); connect(ab, &QAction::triggered, [this]() {
            const char *tname =
                gTransport == Transport::Tor ? "Tor (SOCKS5)" :
                                                "Direct (clearnet)";
            QMessageBox box(this);
            box.setWindowTitle("About SHROUD");
            box.setIconPixmap(QIcon(":/shroud.png").pixmap(64, 64));
            box.setTextFormat(Qt::RichText);
            box.setText(QString(
                "<p style='font-size:14pt'><b>SHROUD</b> v%1</p>"
                "<p>Private messaging with no phone number, no email and no metadata.</p>"
                "<p style='color:%3'>AES-256-GCM · ECDH P-384 · ML-KEM-1024<br>"
                "Double Ratchet · sealed sender · disappearing messages</p>"
                "<p>Active transport: %2</p>"
                "<p><a href='https://github.com/ExposingTheBadge/Shroud'>github.com/ExposingTheBadge/Shroud</a></p>")
                .arg(CLIENT_VERSION, tname, cN(gTheme.dim)));
            box.exec();
        });
    }

    /* Query /api/v1/version, compare against CLIENT_VERSION, and prompt the
       user to open the download URL when newer. If verbose=false (background
       check), stays silent unless an update is available. */
    void checkForUpdates(bool verbose) {
        QByteArray r = httpGet("/api/v1/version");
        if (r.isEmpty()) {
            if (verbose) QMessageBox::warning(this, "Updates", "Could not reach server.");
            return;
        }
        QJsonObject obj = QJsonDocument::fromJson(r).object();
        QString latest = obj.value("version").toString();
        QString winUrl = obj.value("windows").toString();
        QString releaseUrl = obj.value("release_url").toString();
        QString changelog = obj.value("changelog").toString();
        if (latest.isEmpty()) {
            if (verbose) QMessageBox::warning(this, "Updates", "Server returned no version info.");
            return;
        }
        int cmp = versionCompare(latest, CLIENT_VERSION);
        if (cmp <= 0) {
            if (verbose) QMessageBox::information(this, "Updates",
                QString("You are up to date.\n\nCurrent: v%1\nLatest:  v%2").arg(CLIENT_VERSION, latest));
            return;
        }
        QString openUrl = !winUrl.isEmpty() ? winUrl : releaseUrl;
        QMessageBox box(this);
        box.setWindowTitle("Update Available");
        box.setIcon(QMessageBox::Information);
        box.setText(QString("<b>SHROUD v%1</b> is available.<br>You have v%2.").arg(latest, CLIENT_VERSION));
        if (!changelog.isEmpty()) box.setInformativeText(changelog);
        QPushButton *dl = box.addButton("Download", QMessageBox::AcceptRole);
        box.addButton("Later", QMessageBox::RejectRole);
        box.exec();
        if (box.clickedButton() == dl && !openUrl.isEmpty()) {
            QDesktopServices::openUrl(QUrl(openUrl));
        }
    }

    /* ===============================================================
     *  REGISTRATION
     * =============================================================== */
    void buildRegisterUI() {
    auto *w = new QWidget;
    auto *lay = new QVBoxLayout(w);
    lay->setAlignment(Qt::AlignCenter);
    lay->setContentsMargins(24, 24, 24, 24);

    auto *card = new QWidget;
    card->setObjectName("card");
    card->setAttribute(Qt::WA_StyledBackground, true);
    card->setFixedWidth(430);
    auto *cl = new QVBoxLayout(card);
    cl->setContentsMargins(32, 28, 32, 24);
    cl->setSpacing(6);

    auto *logo = new QLabel;
    logo->setPixmap(QIcon(":/shroud.png").pixmap(64, 64));
    logo->setFixedSize(64, 64);
    cl->addWidget(logo, 0, Qt::AlignHCenter);

    auto *title = new QLabel("Welcome back");
    title->setObjectName("heading");
    title->setAlignment(Qt::AlignCenter);
    cl->addWidget(title);

    auto *subtitle = new QLabel("Sign in to pick up your encrypted conversations.");
    subtitle->setObjectName("muted");
    subtitle->setAlignment(Qt::AlignCenter);
    subtitle->setWordWrap(true);
    cl->addWidget(subtitle);
    cl->addSpacing(14);

    auto fieldLabel = [cl](const QString &t) {
        auto *l = new QLabel(t);
        l->setStyleSheet("font-weight: 600;");
        cl->addWidget(l);
        return l;
    };
    auto hintLabel = [cl](const QString &t) {
        auto *l = new QLabel(t);
        l->setObjectName("hint");
        l->setWordWrap(true);
        cl->addWidget(l);
        return l;
    };

    /* Shared fields */
    fieldLabel("Username");
    auto *uname = new QLineEdit; uname->setPlaceholderText("e.g. nightowl");
    uname->setMaxLength(64);
    cl->addWidget(uname);
    auto *unameHint = hintLabel("At least 3 characters. This is how friends find you, so pick something that doesn't reveal who you are.");
    unameHint->hide();
    cl->addSpacing(6);

    fieldLabel("Password");
    auto *pass = new QLineEdit; pass->setPlaceholderText("At least 12 characters"); pass->setEchoMode(QLineEdit::Password);
    attachPasswordReveal(pass);
    cl->addWidget(pass);

    /* Strength meter — register mode only. */
    auto *strengthBar = new QProgressBar;
    strengthBar->setRange(0, 4);
    strengthBar->setTextVisible(false);
    strengthBar->setFixedHeight(6);
    strengthBar->hide();
    cl->addWidget(strengthBar);
    auto *strengthLbl = hintLabel("");
    strengthLbl->hide();

    /* Caps Lock warning chip — appears below the password field whenever
     * VK_CAPITAL is on and the password field has focus. Saves a lot of
     * "decryption failed" support tickets. */
    auto *capsWarn = new QLabel(QString::fromUtf8("\xE2\x9A\xA0  Caps Lock is on"));
    capsWarn->setProperty("state", "warn");
    capsWarn->hide();
    cl->addWidget(capsWarn);

    /* Register-only fields */
    auto *confirmLbl = fieldLabel("Confirm password");
    auto *confirm = new QLineEdit; confirm->setPlaceholderText("Type it again"); confirm->setEchoMode(QLineEdit::Password);
    attachPasswordReveal(confirm);
    cl->addWidget(confirm);
    auto *confirmHint = hintLabel("There is no password reset: SHROUD never learns your password. Keep it somewhere safe.");
    confirmLbl->hide(); confirm->hide(); confirmHint->hide();

    auto *dnameLbl = fieldLabel("Device name");
    auto *dname = new QLineEdit; dname->setPlaceholderText("Device Name"); dname->setText("Windows-PC");
    cl->addWidget(dname);
    auto *dnameHint = hintLabel("Helps you tell your devices apart when you link more than one.");
    dnameLbl->hide(); dname->hide(); dnameHint->hide();

    // Poll caps-lock state on a short cadence so toggling it outside the
    // field reflects within a few hundred ms. Keep it cheap — Win32
    // GetKeyState is a no-op syscall.
    auto *capsTimer = new QTimer(pass);
    capsTimer->setInterval(200);
    QObject::connect(capsTimer, &QTimer::timeout, [pass, confirm, capsWarn]() {
        bool on = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
        capsWarn->setVisible(on && (pass->hasFocus() || confirm->hasFocus()));
    });
    capsTimer->start();

    cl->addSpacing(4);
    auto *remChk = new QCheckBox("Remember my username on this PC"); cl->addWidget(remChk);

    DeviceConfig sc;
    ZeroMemory(&sc, sizeof(sc));
    if (storage_load_config(&sc) && sc.username[0]) {
        uname->setText(sc.username);
        remChk->setChecked(true);
    }

    auto *status = new QLabel; status->setAlignment(Qt::AlignCenter);
    status->setWordWrap(true);
    status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    cl->addSpacing(4);
    cl->addWidget(status);

    auto *actionBtn = new QPushButton("Sign in");
    actionBtn->setObjectName("primary");
    actionBtn->setMinimumHeight(40);
    actionBtn->setCursor(Qt::PointingHandCursor);
    cl->addWidget(actionBtn);

    auto *toggleLink = new QPushButton("New to SHROUD? Create an account");
    toggleLink->setObjectName("link");
    toggleLink->setCursor(Qt::PointingHandCursor);
    cl->addWidget(toggleLink, 0, Qt::AlignCenter);

    auto *footer = new QLabel(QString::fromUtf8("\xF0\x9F\x94\x92  End-to-end encrypted  \xC2\xB7  No phone number  \xC2\xB7  No email"));
    footer->setObjectName("hint");
    footer->setAlignment(Qt::AlignCenter);
    cl->addSpacing(6);
    cl->addWidget(footer);

    lay->addWidget(card);
    m_stack->addWidget(w);
    if (uname->text().isEmpty()) uname->setFocus(); else pass->setFocus();

    /* Mode flag lives on the button so it outlives this stack frame.
       Capturing a stack-local bool by reference would dangle once
       buildRegisterUI() returns. */
    actionBtn->setProperty("registerMode", false);

    auto updateStrength = [pass, strengthBar, strengthLbl]() {
        const QString p = pass->text();
        int classes = 0;
        if (p.contains(QRegularExpression("[a-z]"))) classes++;
        if (p.contains(QRegularExpression("[A-Z]"))) classes++;
        if (p.contains(QRegularExpression("[0-9]"))) classes++;
        if (p.contains(QRegularExpression("[^A-Za-z0-9]"))) classes++;
        int score, level; QString text;
        if (p.isEmpty())          { score = 0; level = 3; }
        else if (p.length() < 12) {
            int need = 12 - (int)p.length();
            score = 1; level = 2;
            text = QString("Too short: %1 more character%2 needed").arg(need).arg(need == 1 ? "" : "s");
        }
        else if (p.length() < 16 && classes < 3) { score = 2; level = 1; text = "Okay. A longer passphrase would be stronger."; }
        else if (p.length() < 20 && classes < 3) { score = 3; level = 0; text = "Good"; }
        else                                     { score = 4; level = 0; text = "Strong"; }
        strengthBar->setValue(score);
        QColor c = level == 3 ? gTheme.border : statusColor(gTheme, level);
        strengthBar->setStyleSheet(QString("QProgressBar::chunk { background-color: %1; border-radius: 3px; }").arg(cN(c)));
        strengthLbl->setText(text);
    };
    QObject::connect(pass, &QLineEdit::textChanged, updateStrength);

    auto updateMode = [=]() {
        bool reg = actionBtn->property("registerMode").toBool();
        for (QWidget *x : {(QWidget*)dname, (QWidget*)dnameLbl, (QWidget*)dnameHint,
                           (QWidget*)confirm, (QWidget*)confirmLbl, (QWidget*)confirmHint,
                           (QWidget*)strengthBar, (QWidget*)strengthLbl, (QWidget*)unameHint})
            x->setVisible(reg);
        title->setText(reg ? "Create your account" : "Welcome back");
        subtitle->setText(reg
            ? "No email, no phone number. Just a username and a password only you know."
            : "Sign in to pick up your encrypted conversations.");
        actionBtn->setText(reg ? "Create account" : "Sign in");
        toggleLink->setText(reg ? "Already have an account? Sign in" : "New to SHROUD? Create an account");
        setStatusLabel(status, "", "info");
        setInvalid(uname, false); setInvalid(pass, false); setInvalid(confirm, false);
        updateStrength();
    };

    QObject::connect(toggleLink, &QPushButton::clicked, [actionBtn, updateMode]() {
        actionBtn->setProperty("registerMode", !actionBtn->property("registerMode").toBool());
        updateMode();
    });
    /* Clear the red border as soon as the user starts fixing a field. */
    QObject::connect(uname, &QLineEdit::textChanged, [uname]() { setInvalid(uname, false); });
    QObject::connect(pass, &QLineEdit::textChanged, [pass]() { setInvalid(pass, false); });
    QObject::connect(confirm, &QLineEdit::textChanged, [confirm]() { setInvalid(confirm, false); });

    auto doAction = [=]() {
        bool showRegister = actionBtn->property("registerMode").toBool();
        if (!actionBtn->isEnabled()) return;   /* already working */
        QString u = uname->text().trimmed();
        QString p = pass->text();
        QString d = dname->text().trimmed();
        if (d.isEmpty()) d = "Windows-PC";
        if (u.length() < 3) {
            setInvalid(uname, true); uname->setFocus();
            setStatusLabel(status, u.isEmpty() ? "Enter your username." : "Usernames are at least 3 characters.", "err");
            return;
        }
        if (p.length() < 12) {
            setInvalid(pass, true); pass->setFocus();
            setStatusLabel(status, p.isEmpty() ? "Enter your password." : "Passwords are at least 12 characters.", "err");
            return;
        }
        if (showRegister && confirm->text() != p) {
            setInvalid(confirm, true); confirm->setFocus();
            setStatusLabel(status, "The two passwords don't match.", "err");
            return;
        }

        /* Lock the form while the (synchronous) handshake runs and put it
         * back on every exit path, success or failure. */
        struct Busy {
            QPointer<QPushButton> b; QString text;
            Busy(QPushButton *btn, const QString &busyText) : b(btn), text(btn->text()) {
                b->setEnabled(false); b->setText(busyText);
                QApplication::setOverrideCursor(Qt::WaitCursor);
            }
            ~Busy() {
                if (b) { b->setEnabled(true); b->setText(text); }
                QApplication::restoreOverrideCursor();
            }
        } busy(actionBtn, showRegister ? QString::fromUtf8("Creating account\xE2\x80\xA6")
                                       : QString::fromUtf8("Signing in\xE2\x80\xA6"));

        if (remChk->isChecked()) {
            DeviceConfig sc2; memcpy(&sc2, &sc, sizeof(sc2));
            strncpy(sc2.username, u.toUtf8().constData(), sizeof(sc2.username)-1);
            storage_save_config(&sc2);
        }

        setStatusLabel(status, QString::fromUtf8("Checking the relay's identity\xE2\x80\xA6"), "info");
        QApplication::processEvents();

        /* Plain-English message for "we never got an answer". */
        auto unreachable = [&]() {
            setStatusLabel(status,
                gTransport == Transport::Tor
                    ? "Can't reach the SHROUD relay through Tor. Make sure Tor is running "
                      "(Settings > Network), then try again."
                    : "Can't reach the SHROUD relay. Check your internet connection and try again.",
                "err");
        };

        /* 0. Server identity check (TOFU pin). Triple-hybrid signature
              suite Ed25519 + ML-DSA-87 + SPHINCS+-256s. If the server's
              fingerprint differs from what we pinned earlier, refuse. */
        QString serverFp;
        int idStatus = verifyServerIdentity(&serverFp);
        if (idStatus == -1) {
            QMessageBox::critical(this, "Server identity changed",
                "The server's identity fingerprint does NOT match the one this device pinned.\n\n"
                "Pinned:  " + loadPinnedFingerprint() + "\n"
                "Server:  " + serverFp + "\n\n"
                "This usually means one of:\n"
                "  • The server operator rotated the identity (verify out of band).\n"
                "  • Someone is impersonating the server (MITM attack).\n\n"
                "Refusing to authenticate. If the change is legitimate, delete\n"
                + serverPinPath() + " and try again.");
            setStatusLabel(status, "Stopped: this relay's identity has changed since you last connected. "
                                   "See the warning for what to do.", "err");
            return;
        }
        if (idStatus == -2 && httpGet("/health").isEmpty()) {
            unreachable();
            return;
        }
        if (idStatus == 1) {
            setStatusLabel(status, "First connection to this relay: remembered its fingerprint "
                                   + serverFp.left(8) + QString::fromUtf8("\xE2\x80\xA6"), "info");
            QApplication::processEvents();
        }

        setStatusLabel(status, QString::fromUtf8("Setting up a secure channel\xE2\x80\xA6"), "info");
        QApplication::processEvents();

        /* Generate our ECDH keypair — used by both v1 and v2 paths. */
        KeyPair kp = crypto_generate_keypair();
        if (!kp.handle) {
            setStatusLabel(status, "Couldn't generate encryption keys on this PC. Try restarting SHROUD.", "err");
            return;
        }
        char *ourPubHex = crypto_hex_encode(kp.pub.data, kp.pub.len);
        QString pubHex = QString::fromUtf8(ourPubHex); free(ourPubHex);

        QByteArray resp;
        bool usedPq = false;

        /* ── v2 hybrid PQ handshake (ECDH-P384 + ML-KEM-1024) ───────────
              Opportunistic: if liboqs.dll is present we use it. The server
              attests the handshake with its triple-hybrid signature; the
              fingerprint was already pinned at step 0 above. */
        if (kyber_available()) {
            QByteArray kxV2 = httpGet("/api/v1/key-exchange-v2");
            QString sidV2 = jsonStr(kxV2, "session_id");
            QString blobHexV2 = jsonStr(kxV2, "server_public_key_blob");
            QString sigHexV2 = jsonStr(kxV2, "server_signature");
            if (!sidV2.isEmpty() && !blobHexV2.isEmpty()) {
                QByteArray blobBytesQ = QByteArray::fromHex(blobHexV2.toUtf8());

                /* If liboqs.dll is available, cryptographically verify the
                   server's attestation against the long-term identity blob
                   we fetched at step 0. Defeats MITM even with a corrupted
                   pin file. If liboqs.dll is missing we accept based on the
                   fingerprint pin alone. */
                if (oqs_sig_available() && !sigHexV2.isEmpty()) {
                    QByteArray idResp = httpGet("/api/v1/server-identity");
                    QByteArray pkBlob = QByteArray::fromHex(jsonStr(idResp, "pubkey_blob").toUtf8());
                    QByteArray sigBlob = QByteArray::fromHex(sigHexV2.toUtf8());
                    QByteArray msg = QByteArray("SHROUD-KEX-v2|") + sidV2.toUtf8() + "|" + blobBytesQ;
                    if (!shroud_verify_server_sig(
                            (const BYTE*)pkBlob.constData(), pkBlob.size(),
                            (const BYTE*)sigBlob.constData(), sigBlob.size(),
                            (const BYTE*)msg.constData(), msg.size())) {
                        QMessageBox::critical(this, "Server attestation FAILED",
                            "The server's PQ handshake signature did not verify.\n"
                            "Refusing to authenticate — this is a MITM-grade error.");
                        crypto_free_keypair(&kp);
                        return;
                    }
                }

                BYTE clientBlob[2048]; DWORD cbLen = sizeof(clientBlob);
                BYTE sessionKey[32];
                if (crypto_pq_hybrid_client((const BYTE*)blobBytesQ.constData(), blobBytesQ.size(),
                                            clientBlob, &cbLen, sessionKey)) {
                    /* Auth key = SHA-256(session_key || "SHROUD-AUTH-PQ-v1") */
                    BYTE authKey[32]; BYTE buf[32 + 21];
                    memcpy(buf, sessionKey, 32);
                    memcpy(buf + 32, "SHROUD-AUTH-PQ-v1", 21);
                    crypto_sha256(buf, sizeof(buf), authKey);

                    /* v2.4.6 — pass the persisted device_id on login so
                       the server can reuse our existing devices row
                       instead of issuing a fresh one every time. */
                    QString existingDid = showRegister ? QString() : m_deviceId;
                    QByteArray payload = jsonBody({
                        {"username", u}, {"password", p}, {"device_name", d},
                        {"platform", QString("windows")}, {"register", showRegister},
                        {"public_key", pubHex},
                        {"existing_device_id", existingDid}
                    });
                    BYTE nonce[12], ct[4096], tag[16];
                    crypto_random_bytes(nonce, 12);
                    crypto_aes_gcm_encrypt(authKey, (const BYTE*)payload.constData(),
                                           payload.size(), nonce, ct, tag);
                    char *nh = crypto_hex_encode(nonce, 12);
                    char *ch = crypto_hex_encode(ct, payload.size());
                    char *th = crypto_hex_encode(tag, 16);
                    char *bh = crypto_hex_encode(clientBlob, cbLen);
                    QByteArray body = jsonBody({
                        {"session_id", sidV2},
                        {"client_pubkey_blob", QString::fromUtf8(bh)},
                        {"nonce", QString::fromUtf8(nh)},
                        {"ciphertext", QString::fromUtf8(ch)},
                        {"tag", QString::fromUtf8(th)},
                    });
                    free(nh); free(ch); free(th); free(bh);
                    resp = httpPost("/api/v1/auth-v2", body);
                    QString didV2 = jsonStr(resp, "device_id");
                    if (!didV2.isEmpty()) usedPq = true;
                }
            }
        }

        /* ── v1 classical fallback ─────────────────────────────────── */
        if (!usedPq) {
            QByteArray keyResp = httpGet("/api/v1/key-exchange");
            QString sessionId = jsonStr(keyResp, "session_id");
            QString serverPubBlobHex = jsonStr(keyResp, "server_public_key_blob");
            if (sessionId.isEmpty() || serverPubBlobHex.isEmpty()) {
                unreachable(); crypto_free_keypair(&kp); return;
            }
            BYTE serverBlob[512]; DWORD blobLen = 0;
            QByteArray blobHex = serverPubBlobHex.toUtf8();
            crypto_hex_decode(blobHex.constData(), serverBlob, &blobLen);
            BYTE authKey[32];
            if (!crypto_auth_derive_key(kp.handle, serverBlob, blobLen, authKey)) {
                setStatusLabel(status, "Setting up the secure channel failed (key derivation). "
                                       "Please try again.", "err");
                crypto_free_keypair(&kp); return;
            }
            /* v2.4.6 — pass existing device_id on login so the server
               reuses our row instead of issuing a new one every login. */
            QString existingDid_v1 = showRegister ? QString() : m_deviceId;
            QByteArray payload = jsonBody({
                {"username", u}, {"password", p}, {"device_name", d},
                {"platform", QString("windows")}, {"register", showRegister},
                {"public_key", pubHex},
                {"existing_device_id", existingDid_v1}
            });
            BYTE nonce[12], ct[4096], tag[16];
            crypto_random_bytes(nonce, 12);
            crypto_aes_gcm_encrypt(authKey, (const BYTE*)payload.constData(),
                                   payload.size(), nonce, ct, tag);
            char *nonceHex = crypto_hex_encode(nonce, 12);
            char *ctHex = crypto_hex_encode(ct, payload.size());
            char *tagHex = crypto_hex_encode(tag, 16);
            QByteArray authBody = jsonBody({
                {"session_id", sessionId}, {"client_public_key", pubHex},
                {"nonce", QString::fromUtf8(nonceHex)},
                {"ciphertext", QString::fromUtf8(ctHex)},
                {"tag", QString::fromUtf8(tagHex)}
            });
            free(nonceHex); free(ctHex); free(tagHex);
            resp = httpPost("/api/v1/auth", authBody);
        }
        // v2.6.x: server errors now carry a stable error_code (catalog at
        // /api/v1/error-codes, source crypto/errors.py). When present we
        // surface "[EA002] Auth payload decryption failed" instead of a
        // bare "Decryption failed" so a user filing a support ticket can
        // quote the code and the operator can look up the exact failure
        // mode. jsonStr nested under "detail" handles FastAPI's wrap.
        auto errCode = [&]() -> QString {
            QString c = jsonStr(resp, "error_code");
            if (!c.isEmpty()) return c;
            // FastAPI nests our raise_http() body under "detail"
            QJsonObject root = QJsonDocument::fromJson(resp).object();
            QJsonValue det = root.value("detail");
            if (det.isObject()) return det.toObject().value("error_code").toString();
            return QString();
        }();
        QString did = jsonStr(resp, "device_id");
        if (!did.isEmpty()) {
            m_deviceId = did; m_username = u; m_deviceName = d; m_platform = "windows"; m_password = p;
            DeviceConfig scSave; ZeroMemory(&scSave, sizeof(scSave));
            strncpy(scSave.id, did.toUtf8().constData(), sizeof(scSave.id)-1);
            strncpy(scSave.username, u.toUtf8().constData(), sizeof(scSave.username)-1);
            strncpy(scSave.device_name, d.toUtf8().constData(), sizeof(scSave.device_name)-1);
            scSave.identity_key = kp;
            strcpy(scSave.platform, "windows");
            storage_save_config(&scSave);
            storage_save_keypair(scSave.id, &scSave.identity_key);

            /* Publish our ratchet bundle. Generates one long-term X25519
               identity + 32 one-time prekeys, stores the privs locally,
               and uploads the pubs to /api/v1/ratchet/publish-key so peers
               can bootstrap a Double Ratchet conversation with us. Best-
               effort — failure is non-fatal for v1.7 (clients fall back
               to the v1 envelope flow). */
            publishRatchetBundle(did);

            m_registered = true;
            QWidget *old = m_stack->currentWidget();
            buildChatUI();
            m_stack->removeWidget(old);
            old->deleteLater();
        } else {
            QString detailTxt = jsonStr(resp, "detail");
            QString title;
            {
                QJsonObject root = QJsonDocument::fromJson(resp).object();
                QJsonValue det = root.value("detail");
                if (det.isObject()) {
                    title    = det.toObject().value("title").toString();
                    if (detailTxt == "[object Object]" || detailTxt.startsWith("{")) {
                        detailTxt = det.toObject().value("detail").toString();
                    }
                }
            }
            if (resp.isEmpty()) { unreachable(); return; }
            QString shown = title.isEmpty() ? detailTxt : title;
            if (!detailTxt.isEmpty() && !title.isEmpty() && detailTxt != title)
                shown += QString::fromUtf8(" \xE2\x80\x94 ") + detailTxt;
            if (shown.isEmpty()) shown = "the relay turned the request down without saying why.";
            shown = (showRegister ? "Couldn't create the account: " : "Couldn't sign in: ") + shown;
            /* Keep the stable code so a support request can quote it. */
            if (!errCode.isEmpty()) shown += QString(" (code %1)").arg(errCode);
            setStatusLabel(status, shown, "err");
        }
    };

    QObject::connect(actionBtn, &QPushButton::clicked, doAction);
    QObject::connect(pass, &QLineEdit::returnPressed, doAction);
    QObject::connect(uname, &QLineEdit::returnPressed, [pass]() { pass->setFocus(); });
    QObject::connect(confirm, &QLineEdit::returnPressed, doAction);
    QObject::connect(dname, &QLineEdit::returnPressed, doAction);
    }

    /* ===============================================================
     *  CHAT UI
     *
     *  Each conversation (a contact's username, or "#<group id>") keeps
     *  its own history in memory only. Nothing is written to disk and
     *  everything is gone when the app closes, which is what the
     *  single shared log did before, just no longer mixing everyone's
     *  messages together.
     * =============================================================== */
    struct ChatMsg {
        QString from;          // display name; "You" for our own messages
        QString html;          // body, already escaped / rendered
        qint64  ts = 0;        // local send / receive time
        bool    mine = false;
        bool    system = false;
        bool    timed = false; // sent with a disappearing timer
        bool    failed = false;
        QString imageId;
    };
    QHash<QString, QList<ChatMsg>> m_conv;
    QHash<QString, int> m_unread;
    QString m_currentConv, m_currentName;
    bool m_currentIsGroup = false;
    QStringList m_extraConvs;              // non-friends who messaged us this session
    QHash<QString, QImage> m_imageCache;
    int  m_pollTick = 0;
    bool m_friendsLoaded = false;
    int  m_pendingFriendReqs = 0, m_pendingGroupInvites = 0;
    QLabel *m_chatAvatar = nullptr, *m_chatTitle = nullptr, *m_chatSub = nullptr;
    QPushButton *m_timerBtn = nullptr, *m_verifyBtn = nullptr, *m_findBtn = nullptr;
    QPushButton *m_ctBtn = nullptr, *m_gtBtn = nullptr, *m_reqBtn = nullptr, *m_grpBtn = nullptr;
    QPushButton *m_emojiBtn = nullptr;
    QWidget *m_findBar = nullptr; QLineEdit *m_findEdit = nullptr; QLabel *m_findStatus = nullptr;
    QLineEdit *m_search = nullptr;

    /* QTextBrowser that serves inline images straight from the in-memory
     * cache. addResource() entries get dropped whenever the document is
     * rebuilt (switching conversations), so resolving on demand is the
     * robust way to keep images showing. */
    class ChatBrowser : public QTextBrowser {
    public:
        std::function<QVariant(const QUrl &)> resolver;
        QVariant loadResource(int type, const QUrl &name) override {
            if (type == QTextDocument::ImageResource && resolver) {
                QVariant v = resolver(name);
                if (v.isValid()) return v;
            }
            return QTextBrowser::loadResource(type, name);
        }
    };

    bool timerOn() const { return gDisappearEnabled && gDisappearSeconds > 0; }

    static QString durationLabel(int s, bool shortForm = false) {
        struct U { int secs; const char *one; const char *many; const char *abbr; };
        static const U units[] = {
            {604800, "week", "weeks", "w"}, {86400, "day", "days", "d"},
            {3600, "hour", "hours", "h"}, {60, "minute", "minutes", "m"},
        };
        for (const U &u : units) {
            if (s >= u.secs && s % u.secs == 0) {
                int n = s / u.secs;
                return shortForm ? QString("%1%2").arg(n).arg(u.abbr)
                                 : QString("%1 %2").arg(n).arg(n == 1 ? u.one : u.many);
            }
        }
        if (s >= 60 && !shortForm) return QString("%1 min %2 sec").arg(s / 60).arg(s % 60);
        return shortForm ? QString("%1s").arg(s) : QString("%1 seconds").arg(s);
    }

    static QColor nameColorFor(const QString &name) {
        uint h = qHash(name.toLower());
        return isDarkTheme(gTheme) ? QColor::fromHsl((int)(h % 360), 170, 170)
                                   : QColor::fromHsl((int)(h % 360), 170, 85);
    }

    void notify(const QString &text, int timeoutMs = 8000) {
        statusBar()->showMessage(text, timeoutMs);
    }

    void buildChatUI() {
        auto *mainW = new QWidget;
        auto *hbox = new QHBoxLayout(mainW);
        hbox->setContentsMargins(0, 0, 0, 0);
        hbox->setSpacing(0);

        /* === SIDEBAR === */
        auto *sidebar = new QWidget;
        sidebar->setObjectName("sidebar");
        sidebar->setAttribute(Qt::WA_StyledBackground, true);
        sidebar->setFixedWidth(280);
        auto *sl = new QVBoxLayout(sidebar);
        sl->setContentsMargins(12, 12, 12, 12);
        sl->setSpacing(8);

        /* Who am I + connection state */
        auto *meRow = new QHBoxLayout;
        meRow->setSpacing(10);
        auto *meAvatar = new QLabel;
        meAvatar->setPixmap(avatarIcon(m_username, 38).pixmap(38, 38));
        meRow->addWidget(meAvatar);
        auto *meCol = new QVBoxLayout;
        meCol->setSpacing(0);
        auto *meName = new QLabel(m_username);
        meName->setStyleSheet("font-weight: 700; font-size: 11pt;");
        meName->setTextInteractionFlags(Qt::TextSelectableByMouse);
        meName->setToolTip("Your username. Friends find you by typing it exactly.");
        meCol->addWidget(meName);
        m_statusBar = new QLabel;
        m_statusBar->setStyleSheet("font-size: 9pt;");
        setStatusLabel(m_statusBar, "● Connecting…", "warn");
        meCol->addWidget(m_statusBar);
        meRow->addLayout(meCol, 1);
        auto *themeBtn = new QPushButton("◐");
        themeBtn->setObjectName("iconBtn");
        themeBtn->setToolTip("Switch light / dark (Ctrl+Shift+L)");
        themeBtn->setCursor(Qt::PointingHandCursor);
        meRow->addWidget(themeBtn);
        auto *settingsBtn = new QPushButton("⚙");
        settingsBtn->setObjectName("iconBtn");
        settingsBtn->setToolTip("Settings (Ctrl+,)");
        settingsBtn->setCursor(Qt::PointingHandCursor);
        meRow->addWidget(settingsBtn);
        sl->addLayout(meRow);
        sl->addSpacing(4);

        /* Contacts / Groups segmented switch */
        auto *segRow = new QHBoxLayout;
        segRow->setSpacing(4);
        m_ctBtn = new QPushButton("Contacts");
        m_gtBtn = new QPushButton("Groups");
        for (QPushButton *b : {m_ctBtn, m_gtBtn}) {
            b->setObjectName("segment");
            b->setCheckable(true);
            b->setCursor(Qt::PointingHandCursor);
            segRow->addWidget(b, 1);
        }
        auto *segGroup = new QButtonGroup(sidebar);
        segGroup->setExclusive(true);
        segGroup->addButton(m_ctBtn);
        segGroup->addButton(m_gtBtn);
        m_ctBtn->setChecked(true);
        sl->addLayout(segRow);

        m_search = new QLineEdit;
        m_search->setPlaceholderText("Find someone by exact username");
        m_search->setClearButtonEnabled(true);
        m_search->setToolTip("Type a username exactly and press Enter (Ctrl+K)");
        sl->addWidget(m_search);

        /* Search result card: shown only after an explicit lookup. */
        m_searchResult = new QWidget;
        m_searchResult->setObjectName("card");
        m_searchResult->setAttribute(Qt::WA_StyledBackground, true);
        m_searchResult->setVisible(false);
        auto *srl = new QVBoxLayout(m_searchResult);
        srl->setContentsMargins(10, 10, 10, 10);
        srl->setSpacing(6);
        m_searchResultLabel = new QLabel;
        m_searchResultLabel->setWordWrap(true);
        srl->addWidget(m_searchResultLabel);
        m_btnMsg = new QPushButton("Message");
        m_btnMsg->setObjectName("primary");
        m_btnFriend = new QPushButton("Add friend");
        m_btnGroupInvite = new QPushButton("Invite to a group");
        srl->addWidget(m_btnMsg);
        srl->addWidget(m_btnFriend);
        srl->addWidget(m_btnGroupInvite);
        sl->addWidget(m_searchResult);

        m_sideList = new QListWidget;
        m_sideList->setIconSize(QSize(32, 32));
        m_sideList->setWordWrap(true);
        m_sideList->setSpacing(1);
        m_sideList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        sl->addWidget(m_sideList, 1);

        auto *bottomRow = new QHBoxLayout;
        bottomRow->setSpacing(6);
        m_reqBtn = new QPushButton("Requests");
        m_reqBtn->setToolTip("Friend requests and group invites waiting for you");
        m_grpBtn = new QPushButton("+ New group");
        bottomRow->addWidget(m_reqBtn, 1);
        bottomRow->addWidget(m_grpBtn, 1);
        sl->addLayout(bottomRow);

        hbox->addWidget(sidebar);

        /* === CHAT AREA === */
        auto *chatArea = new QWidget;
        auto *cl = new QVBoxLayout(chatArea);
        cl->setContentsMargins(0, 0, 0, 0);
        cl->setSpacing(0);

        /* Header: who you're talking to + per-conversation tools */
        auto *header = new QWidget;
        header->setObjectName("chatHeader");
        header->setAttribute(Qt::WA_StyledBackground, true);
        auto *hl = new QHBoxLayout(header);
        hl->setContentsMargins(16, 10, 12, 10);
        hl->setSpacing(10);
        m_chatAvatar = new QLabel;
        m_chatAvatar->setFixedSize(38, 38);
        hl->addWidget(m_chatAvatar);
        auto *titleCol = new QVBoxLayout;
        titleCol->setSpacing(0);
        m_chatTitle = new QLabel;
        m_chatTitle->setObjectName("subheading");
        m_chatSub = new QLabel;
        m_chatSub->setObjectName("muted");
        m_chatSub->setStyleSheet("font-size: 9pt;");
        titleCol->addWidget(m_chatTitle);
        titleCol->addWidget(m_chatSub);
        hl->addLayout(titleCol, 1);
        m_findBtn = new QPushButton("🔍");
        m_findBtn->setObjectName("iconBtn");
        m_findBtn->setCheckable(true);
        m_findBtn->setToolTip("Find in this conversation (Ctrl+F)");
        m_timerBtn = new QPushButton("⏱");
        m_timerBtn->setObjectName("iconBtn");
        m_timerBtn->setToolTip("Disappearing messages: make the messages you send delete themselves");
        m_verifyBtn = new QPushButton("🛡 Verify");
        m_verifyBtn->setObjectName("iconBtn");
        m_verifyBtn->setStyleSheet("font-size: 10pt; padding: 5px 10px;");
        m_verifyBtn->setToolTip("Compare safety numbers to make sure nobody is in the middle");
        for (QPushButton *b : {m_findBtn, m_timerBtn, m_verifyBtn}) {
            b->setCursor(Qt::PointingHandCursor);
            hl->addWidget(b);
        }
        cl->addWidget(header);

        /* Find bar (Ctrl+F) */
        auto *findWrap = new QWidget;
        auto *fwl = new QVBoxLayout(findWrap);
        fwl->setContentsMargins(12, 8, 12, 0);
        m_findBar = new QFrame;
        m_findBar->setObjectName("banner");
        auto *fbl = new QHBoxLayout(m_findBar);
        fbl->setContentsMargins(8, 4, 4, 4);
        fbl->setSpacing(4);
        m_findEdit = new QLineEdit;
        m_findEdit->setPlaceholderText("Find in conversation");
        m_findEdit->setClearButtonEnabled(true);
        fbl->addWidget(m_findEdit, 1);
        m_findStatus = new QLabel;
        fbl->addWidget(m_findStatus);
        auto *findPrev = new QPushButton("↑");
        auto *findNext = new QPushButton("↓");
        auto *findClose = new QPushButton("✕");
        findPrev->setToolTip("Previous match (Shift+Enter)");
        findNext->setToolTip("Next match (Enter)");
        findClose->setToolTip("Close (Esc)");
        for (QPushButton *b : {findPrev, findNext, findClose}) {
            b->setObjectName("iconBtn");
            fbl->addWidget(b);
        }
        fwl->addWidget(m_findBar);
        findWrap->setVisible(false);
        cl->addWidget(findWrap);

        /* Maintenance banner — shown ONLY when the server has flipped the
         * maintenance_mode flag. setMaintenanceMode() handles the banner
         * and the composer in one place. */
        auto *bannerWrap = new QWidget;
        auto *bwl = new QVBoxLayout(bannerWrap);
        bwl->setContentsMargins(12, 8, 12, 0);
        m_maintenanceBanner = new QLabel(
            "The relay is undergoing maintenance. Sending is paused for your safety "
            "and will resume automatically.");
        m_maintenanceBanner->setAlignment(Qt::AlignCenter);
        m_maintenanceBanner->setWordWrap(true);
        m_maintenanceBanner->setStyleSheet(QString(
            "QLabel { background: %1; color: #ffffff; padding: 8px 12px; "
            "border-radius: 8px; font-weight: 600; }").arg(cN(gTheme.danger)));
        bwl->addWidget(m_maintenanceBanner);
        bannerWrap->setVisible(false);
        m_maintenanceBanner->setProperty("wrap", QVariant::fromValue<QObject*>(bannerWrap));
        cl->addWidget(bannerWrap);

        /* Chat log — QTextBrowser so we can click inline images. */
        auto *browser = new ChatBrowser;
        browser->resolver = [this](const QUrl &u) -> QVariant {
            QString n = u.toString();
            if (!n.startsWith("image_")) return QVariant();
            QString fid = n.mid(6);
            QImage img = m_imageCache.value(fid);
            if (img.isNull()) {
                QString path = m_imagePaths.value(fid);
                if (!path.isEmpty() && img.load(path)) m_imageCache.insert(fid, img);
            }
            return img.isNull() ? QVariant() : QVariant(img);
        };
        m_chatLog = browser;
        m_chatLog->setObjectName("chatLog");
        m_chatLog->setReadOnly(true);
        m_chatLog->setOpenLinks(false);
        m_chatLog->setOpenExternalLinks(false);
        m_chatLog->setAcceptDrops(false);   /* file drops go to the window */
        connect(m_chatLog, &QTextBrowser::anchorClicked, this, &ShroudWindow::onChatAnchorClicked);
        m_chatLog->setContextMenuPolicy(Qt::CustomContextMenu);
        /* Ensure emoji glyphs render via Segoe UI Emoji fallback. */
        {
            QFont f = m_chatLog->font();
            f.setFamilies({"Segoe UI", "Segoe UI Emoji", "Noto Color Emoji"});
            f.setPointSize(10);
            m_chatLog->setFont(f);
        }
        connect(m_chatLog, &QWidget::customContextMenuRequested, this, &ShroudWindow::onChatContextMenu);
        cl->addWidget(m_chatLog, 1);

        /* Composer */
        auto *composer = new QWidget;
        composer->setObjectName("composer");
        composer->setAttribute(Qt::WA_StyledBackground, true);
        auto *inputRow = new QHBoxLayout(composer);
        inputRow->setContentsMargins(12, 10, 12, 12);
        inputRow->setSpacing(6);
        m_attachBtn = new QPushButton("📎");
        m_attachBtn->setObjectName("iconBtn");
        m_attachBtn->setToolTip("Send a file or image, end-to-end encrypted. You can also drag files onto the window.");
        m_attachBtn->setCursor(Qt::PointingHandCursor);
        inputRow->addWidget(m_attachBtn);
        m_emojiBtn = new QPushButton("😀");
        m_emojiBtn->setObjectName("iconBtn");
        m_emojiBtn->setToolTip("Open the Windows emoji panel (Win + .)");
        m_emojiBtn->setCursor(Qt::PointingHandCursor);
        connect(m_emojiBtn, &QPushButton::clicked, [this]() {
            m_msgInput->setFocus();
            INPUT in[4] = {};
            in[0].type = INPUT_KEYBOARD; in[0].ki.wVk = VK_LWIN;
            in[1].type = INPUT_KEYBOARD; in[1].ki.wVk = VK_OEM_PERIOD;
            in[2].type = INPUT_KEYBOARD; in[2].ki.wVk = VK_OEM_PERIOD; in[2].ki.dwFlags = KEYEVENTF_KEYUP;
            in[3].type = INPUT_KEYBOARD; in[3].ki.wVk = VK_LWIN;       in[3].ki.dwFlags = KEYEVENTF_KEYUP;
            SendInput(4, in, sizeof(INPUT));
        });
        inputRow->addWidget(m_emojiBtn);
        m_msgInput = new QLineEdit;
        m_msgInput->setMinimumHeight(40);
        m_msgInput->setAcceptDrops(false);
        /* Force a font with emoji glyphs as fallback so 🎯 etc render in-place. */
        {
            QFont f = m_msgInput->font();
            f.setFamilies({"Segoe UI", "Segoe UI Emoji", "Noto Color Emoji"});
            m_msgInput->setFont(f);
        }
        inputRow->addWidget(m_msgInput, 1);
        m_sendBtn = new QPushButton("Send");
        m_sendBtn->setObjectName("primary");
        m_sendBtn->setMinimumHeight(40);
        m_sendBtn->setCursor(Qt::PointingHandCursor);
        inputRow->addWidget(m_sendBtn);
        cl->addWidget(composer);

        hbox->addWidget(chatArea, 1);

        /* Status bar: transient notices on the left, what's protecting
         * the session on the right. */
        QStatusBar *sb = statusBar();
        sb->setSizeGripEnabled(false);
        QString tpmStr; { char buf[128]; tpm_status_string(buf, 128); tpmStr = buf; }
        const char *pq = kyber_available() ? "ML-KEM-1024 + ECDH P-384" : "ECDH P-384";
        auto *cryptoLbl = new QLabel(QString("🔒 %1 · AES-256-GCM").arg(pq));
        cryptoLbl->setToolTip(QString("Device: %1…\nKey storage: %2")
            .arg(m_deviceId.left(16), tpmStr));
        /* Always-visible relay endpoint — so the operator (or user
         * reporting a bug) can tell at a glance which relay this
         * client is talking to. SERVER_HOST/PORT/USE_TLS are baked at
         * build time today; the manifest pin work is the path to
         * making this user-switchable later. */
        QString relayDisplay = QString("relay %1:%2%3")
            .arg(QString::fromWCharArray(SERVER_HOST))
            .arg(SERVER_PORT)
            .arg(gTransport == Transport::Tor ? " via Tor" : "");
        auto *relayLbl = new QLabel(relayDisplay);
        relayLbl->setTextInteractionFlags(Qt::TextSelectableByMouse);
        relayLbl->setToolTip(QString("%1://%2:%3. Set at build time; future versions will switch via the operator manifest pin.")
            .arg(SERVER_USE_TLS ? "https" : "http").arg(QString::fromWCharArray(SERVER_HOST)).arg(SERVER_PORT));
        auto *verLbl = new QLabel(QString("v%1").arg(CLIENT_VERSION));
        sb->addPermanentWidget(cryptoLbl);
        sb->addPermanentWidget(relayLbl);
        sb->addPermanentWidget(verLbl);
        notify(QString("Signed in as %1").arg(m_username), 6000);

        m_stack->addWidget(mainW);
        m_stack->setCurrentWidget(mainW);
        setAcceptDrops(true);

        buildTimerMenu();

        /* === CONNECTIONS === */
        connect(m_ctBtn, &QPushButton::clicked, [this]() { m_tabGroups = false; hideSearchResult(); loadContacts(); });
        connect(m_gtBtn, &QPushButton::clicked, [this]() { m_tabGroups = true; hideSearchResult(); loadGroups(); });
        connect(m_grpBtn, &QPushButton::clicked, [this]() {
            bool ok = false;
            QString name = QInputDialog::getText(this, "New group",
                "What should the group be called?", QLineEdit::Normal, "", &ok);
            if (ok && !name.trimmed().isEmpty()) {
                createGroup(name.trimmed());
                m_tabGroups = true; m_gtBtn->setChecked(true);
                loadGroups();
                notify(QString("Group \"%1\" created. Find friends with the search box to invite them.").arg(name.trimmed()));
            }
        });
        connect(m_reqBtn, &QPushButton::clicked, this, &ShroudWindow::openRequestsDialog);
        connect(themeBtn, &QPushButton::clicked, this, &ShroudWindow::onToggleTheme);
        connect(settingsBtn, &QPushButton::clicked, [this]() { openSettings(0); });
        connect(m_sideList, &QListWidget::itemClicked, this, &ShroudWindow::sideSelect);
        connect(m_sideList, &QListWidget::itemActivated, this, &ShroudWindow::sideSelect);
        /* Arrow keys (and assistive tech selecting an item) open it too. */
        connect(m_sideList, &QListWidget::itemSelectionChanged, this, [this]() {
            const auto sel = m_sideList->selectedItems();
            if (sel.size() == 1 && sel[0]->data(Qt::UserRole).toString() != m_currentConv) sideSelect(sel[0]);
        });
        m_sideList->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(m_sideList, &QListWidget::customContextMenuRequested, this, &ShroudWindow::onContactContextMenu);
        connect(m_sendBtn, &QPushButton::clicked, this, &ShroudWindow::sendMessage);
        connect(m_attachBtn, &QPushButton::clicked, [this]() { attachFile(); });
        connect(m_msgInput, &QLineEdit::returnPressed, this, &ShroudWindow::sendMessage);
        connect(m_msgInput, &QLineEdit::textChanged, [this]() { updateComposerState(); });
        connect(m_verifyBtn, &QPushButton::clicked, [this]() {
            if (!m_currentConv.isEmpty() && !m_currentIsGroup) showSafetyNumber(m_currentName);
        });
        connect(m_findBtn, &QPushButton::toggled, [this, findWrap](bool on) {
            findWrap->setVisible(on);
            if (on) { m_findEdit->setFocus(); m_findEdit->selectAll(); }
            else    { setStatusLabel(m_findStatus, "", "info"); m_msgInput->setFocus(); }
        });
        connect(m_findEdit, &QLineEdit::returnPressed, [this]() {
            findInChat(QApplication::keyboardModifiers() & Qt::ShiftModifier);
        });
        connect(m_findEdit, &QLineEdit::textChanged, [this]() {
            /* Search as you type, from the top. */
            QTextCursor c = m_chatLog->textCursor();
            c.movePosition(QTextCursor::Start);
            m_chatLog->setTextCursor(c);
            findInChat(false);
        });
        connect(findPrev, &QPushButton::clicked, [this]() { findInChat(true); });
        connect(findNext, &QPushButton::clicked, [this]() { findInChat(false); });
        connect(findClose, &QPushButton::clicked, [this]() { m_findBtn->setChecked(false); });

        /* Keyboard shortcuts */
        auto *scFind = new QShortcut(QKeySequence::Find, this);
        connect(scFind, &QShortcut::activated, [this]() {
            if (m_currentConv.isEmpty()) return;
            if (m_findBtn->isChecked()) { m_findEdit->setFocus(); m_findEdit->selectAll(); }
            else m_findBtn->setChecked(true);
        });
        auto *scSearch = new QShortcut(QKeySequence("Ctrl+K"), this);
        connect(scSearch, &QShortcut::activated, [this]() { m_search->setFocus(); m_search->selectAll(); });
        auto *scEsc = new QShortcut(QKeySequence(Qt::Key_Escape), this);
        connect(scEsc, &QShortcut::activated, [this]() {
            if (m_findBtn->isChecked()) m_findBtn->setChecked(false);
            else if (m_searchResult->isVisible()) { m_search->clear(); hideSearchResult(); }
        });
        auto *scNext = new QShortcut(QKeySequence("Ctrl+Tab"), this);
        connect(scNext, &QShortcut::activated, [this]() { stepConversation(+1); });
        auto *scPrev = new QShortcut(QKeySequence("Ctrl+Shift+Tab"), this);
        connect(scPrev, &QShortcut::activated, [this]() { stepConversation(-1); });

        /* Exact-match search only fires on Enter. */
        connect(m_search, &QLineEdit::returnPressed, [this]() {
            if (m_tabGroups) { m_tabGroups = false; m_ctBtn->setChecked(true); loadContacts(); }
            doExactSearch(m_search->text());
        });
        connect(m_search, &QLineEdit::textChanged, [this](const QString &t) {
            if (t.isEmpty()) hideSearchResult();
        });
        /* Search-result action buttons */
        connect(m_btnMsg, &QPushButton::clicked, [this]() {
            if (!m_searchHit.isEmpty()) selectUsernameForChat(m_searchHit);
        });
        connect(m_btnFriend, &QPushButton::clicked, [this]() {
            if (!m_searchHit.isEmpty()) sendFriendRequest(m_searchHit);
        });
        connect(m_btnGroupInvite, &QPushButton::clicked, [this]() {
            if (!m_searchHit.isEmpty()) inviteToGroup(m_searchHit);
        });

        /* Timer for message polling + heartbeat + health check */
        auto *timer = new QTimer(this);
        connect(timer, &QTimer::timeout, this, [this]() {
            fetchMessages();
            if (!m_deviceId.isEmpty()) {
                QByteArray hb = httpPost("/api/v1/heartbeat",
                    jsonBody({{"device_id", m_deviceId}}));
                /* Server includes "maintenance_mode": true/false on every
                 * successful beat. Mirror it into the UI so the composer
                 * locks the moment the admin toggles it on, no
                 * send-attempt required. */
                if (!hb.isEmpty()) {
                    setMaintenanceMode(hb.contains("\"maintenance_mode\":true"));
                }
            }
            /* Health check */
            QByteArray hr = httpGet("/health");
            if (!hr.isEmpty() && hr.contains("\"status\":\"ok\"")) {
                if (m_maintenanceMode) setStatusLabel(m_statusBar, "● Relay in maintenance", "warn");
                else                   setStatusLabel(m_statusBar, "● Online", "ok");
            } else {
                setStatusLabel(m_statusBar,
                    gTransport == Transport::Tor ? "● Offline (is Tor running?)" : "● Offline, retrying…", "err");
            }
            /* Requests and new friendships don't need 4-second freshness. */
            if (++m_pollTick % 8 == 0) refreshRequests();
        });
        timer->start(4000);

        /* Initial load */
        loadContacts();
        refreshRequests();
        openConversation(QString(), QString(), false, QString());
#ifdef SHROUD_UI_PREVIEW
        if (qEnvironmentVariableIsSet("SHROUD_PREVIEW_DEMO")) seedPreviewDemo();
#endif
    }

#ifdef SHROUD_UI_PREVIEW
    /* Local-only sample conversations for eyeballing the chat UI in a
     * preview build. Nothing is sent anywhere. */
    void seedPreviewDemo() {
        qint64 now = QDateTime::currentSecsSinceEpoch();
        auto msg = [](const QString &from, const QString &text, qint64 ts, bool mine) {
            ChatMsg m; m.from = from; m.html = mdToHtml(text); m.ts = ts; m.mine = mine; return m;
        };
        for (const char *n : {"carol", "dave"}) if (!m_extraConvs.contains(n)) m_extraConvs << n;
        loadContacts();
        m_conv["carol"] = {
            msg("carol", "Did you get the files from yesterday?", now - 86400 - 3600, false),
            msg("You", "Yes, all three. Thanks!", now - 86400 - 3500, true),
            msg("carol", "Great. Let's go over them **tomorrow** at 10?", now - 600, false),
            msg("carol", "Here's the agenda: https://example.org/agenda", now - 590, false),
            msg("You", "Works for me 👍", now - 120, true),
        };
        m_conv["carol"].last().timed = true;
        m_conv["dave"] = { msg("dave", "ping", now - 60, false), msg("dave", "you around?", now - 30, false) };
        m_unread["dave"] = 2;
        refreshSidebarBadges();
        updateWindowTitle();
        openConversation("carol", "carol", false, QString("preview-device"));
    }
#endif

    /* ── Conversation model ───────────────────────────────────────── */

    void onToggleTheme() {
        toggleLightDark();
        saveUserPrefs();
        onThemeChanged();
    }

    /* Everything that bakes theme colours into content rather than
     * picking them up from the stylesheet. */
    void onThemeChanged() {
        if (m_maintenanceBanner)
            m_maintenanceBanner->setStyleSheet(QString(
                "QLabel { background: %1; color: #ffffff; padding: 8px 12px; "
                "border-radius: 8px; font-weight: 600; }").arg(cN(gTheme.danger)));
        if (m_chatLog) renderConversation();
    }

    QString dayLabel(const QDate &d) const {
        QDate today = QDate::currentDate();
        if (d == today) return "Today";
        if (d == today.addDays(-1)) return "Yesterday";
        return QLocale::system().toString(d, QLocale::LongFormat);
    }

    QString messageHtml(const ChatMsg &m, const ChatMsg *prev) const {
        const QString dim = cN(gTheme.dim);
        QString out;
        QDateTime dt = QDateTime::fromSecsSinceEpoch(m.ts);
        bool newDay = !prev || QDateTime::fromSecsSinceEpoch(prev->ts).date() != dt.date();
        if (newDay)
            out += QString("<p align='center' style='margin-top:14px; margin-bottom:2px; color:%1; font-size:8pt;'>%2</p>")
                .arg(dim, dayLabel(dt.date()));
        if (m.system) {
            out += QString("<p align='center' style='margin-top:6px; margin-bottom:6px; color:%1; font-size:9pt;'><i>%2</i></p>")
                .arg(dim, m.html);
            return out;
        }
        bool grouped = !newDay && prev && !prev->system && prev->mine == m.mine
                    && prev->from == m.from && m.ts - prev->ts < 300;
        if (!grouped) {
            QString nameColor = m.mine ? cN(gTheme.accent) : cN(nameColorFor(m.from));
            out += QString("<p style='margin-top:10px; margin-bottom:0px;'>"
                           "<span style='color:%1; font-weight:600;'>%2</span>"
                           "&nbsp;&nbsp;<span style='color:%3; font-size:8pt;'>%4%5</span></p>")
                .arg(nameColor, m.from.toHtmlEscaped(), dim,
                     QLocale::system().toString(dt.time(), QLocale::ShortFormat),
                     m.timed ? QString(" · ⏱") : QString());
        }
        QString body = m.html;
        if (!m.imageId.isEmpty()) {
            QImage img = m_imageCache.value(m.imageId);
            int w = img.isNull() ? 280 : qMin(280, img.width());
            body = QString("<a href=\"shroud-img://%1\"><img src=\"image_%1\" width=\"%2\"/></a>")
                .arg(m.imageId).arg(w);
        }
        if (m.failed)
            body += QString("&nbsp;<span style='color:%1; font-size:8pt;'>⚠ not delivered</span>")
                .arg(cN(gTheme.danger));
        out += QString("<p style='margin-top:1px; margin-bottom:0px;'>%1</p>").arg(body);
        return out;
    }

    QString welcomeHtml() const {
        const QString dim = cN(gTheme.dim), lk = cN(gTheme.link);
        int pending = m_pendingFriendReqs + m_pendingGroupInvites;
        QString html = QString(
            "<br><br><p align='center' style='font-size:34pt;'>🔐</p>"
            "<p align='center' style='font-size:15pt; font-weight:600;'>Welcome, %1</p>"
            "<p align='center' style='color:%2;'>Pick a conversation on the left to start chatting.<br>"
            "Everything you send is encrypted on this PC before it leaves.</p>")
            .arg(m_username.toHtmlEscaped(), dim);
        if (pending > 0)
            html += QString("<p align='center' style='color:%1; font-weight:600;'>You have %2 pending request%3. "
                            "Open <i>Requests</i> at the bottom left.</p>")
                .arg(lk).arg(pending).arg(pending == 1 ? "" : "s");
        auto row = [&](const QString &icon, const QString &title, const QString &text) {
            return QString("<tr><td style='font-size:16pt; padding:6px 10px;'>%1</td>"
                           "<td style='padding:6px 4px;'><b>%2</b><br><span style='color:%3;'>%4</span></td></tr>")
                .arg(icon, title, dim, text);
        };
        html += "<br><table align='center' cellspacing='0' cellpadding='0'>";
        html += row("🔎", "Add a friend", "Type their exact username in the search box and press Enter.");
        html += row("🛡", "Verify who you're talking to", "Compare safety numbers so you know nobody is in the middle.");
        html += row("⏱", "Disappearing messages", "Use the timer in a chat's header to make what you send delete itself.");
        html += row("📎", "Share files privately", "Drag a file onto the window or click the paperclip.");
        html += "</table>";
        return html;
    }

    QString introHtml() const {
        const QString dim = cN(gTheme.dim);
        QString html = QString(
            "<br><p align='center' style='font-size:12pt; font-weight:600;'>%1</p>"
            "<p align='center' style='color:%2; font-size:9pt;'>")
            .arg(m_currentIsGroup
                     ? QString("Group: %1").arg(m_currentName.toHtmlEscaped())
                     : QString("This is the start of your conversation with %1").arg(m_currentName.toHtmlEscaped()),
                 dim);
        html += "Messages are end-to-end encrypted and only kept in memory: "
                "they're gone from this PC when you close SHROUD.";
        if (timerOn())
            html += QString("<br>⏱ Messages you send disappear after %1.").arg(durationLabel(gDisappearSeconds));
        if (!m_currentIsGroup)
            html += "<br>Tip: click <b>Verify</b> above to compare safety numbers.";
        html += "</p>";
        return html;
    }

    void renderConversation() {
        if (!m_chatLog) return;
        if (m_currentConv.isEmpty()) {
            m_chatLog->setHtml(welcomeHtml());
            return;
        }
        QString html = introHtml();
        auto it = m_conv.constFind(m_currentConv);
        if (it != m_conv.constEnd()) {
            const ChatMsg *prev = nullptr;
            for (const ChatMsg &m : it.value()) { html += messageHtml(m, prev); prev = &m; }
        }
        m_chatLog->setHtml(html);
        scrollChatToBottom();
    }

    void scrollChatToBottom() {
        if (QScrollBar *sb = m_chatLog->verticalScrollBar()) sb->setValue(sb->maximum());
    }

    void appendMessage(const QString &conv, ChatMsg m) {
        if (conv.isEmpty()) return;
        if (!m.ts) m.ts = QDateTime::currentSecsSinceEpoch();
        QList<ChatMsg> &list = m_conv[conv];
        const bool isCurrent = (conv == m_currentConv);
        if (isCurrent) {
            if (list.isEmpty()) {
                list.append(m);
                renderConversation();
            } else {
                QScrollBar *sb = m_chatLog->verticalScrollBar();
                bool atBottom = !sb || sb->value() >= sb->maximum() - 40 || m.mine;
                m_chatLog->append(messageHtml(m, &list.last()));
                list.append(m);
                if (atBottom) scrollChatToBottom();
            }
        } else {
            list.append(m);
        }
        /* Bound memory for very long sessions. */
        while (list.size() > 1000) list.removeFirst();

        if (!m.mine && !m.system) {
            if (!isCurrent) m_unread[conv]++;
            if (!isCurrent || !isActiveWindow()) {
                if (gFlashOnMessage) QApplication::alert(this);
            }
            /* Someone we haven't friended messaged us: surface them. */
            if (!conv.startsWith('#') && !m_friends.contains(conv) && !m_extraConvs.contains(conv)) {
                m_extraConvs << conv;
                if (!m_tabGroups) {
                    auto *it = makeConvItem(conv, conv, false, QString());
                    it->setToolTip("Not in your contacts. Right-click for options.");
                    m_sideList->addItem(it);
                }
            }
            refreshSidebarBadges();
            updateWindowTitle();
        }
    }

    void addSystemNote(const QString &conv, const QString &text) {
        ChatMsg m; m.system = true; m.html = text.toHtmlEscaped();
        appendMessage(conv, m);
    }

    QListWidgetItem *makeConvItem(const QString &key, const QString &name, bool group, const QString &recip) {
        auto *it = new QListWidgetItem(avatarIcon(name, 32, group), name);
        it->setData(Qt::UserRole, key);
        it->setData(Qt::UserRole + 1, name);
        it->setData(Qt::UserRole + 2, recip);
        it->setSizeHint(QSize(0, 46));
        return it;
    }

    QListWidgetItem *placeholderItem(const QString &text) {
        auto *it = new QListWidgetItem(text);
        it->setFlags(Qt::NoItemFlags);
        it->setForeground(gTheme.dim);
        it->setTextAlignment(Qt::AlignCenter);
        it->setSizeHint(QSize(0, 110));
        return it;
    }

    void refreshSidebarBadges() {
        if (!m_sideList) return;
        QSignalBlocker block(m_sideList);
        for (int i = 0; i < m_sideList->count(); i++) {
            QListWidgetItem *it = m_sideList->item(i);
            QString key = it->data(Qt::UserRole).toString();
            if (key.isEmpty()) continue;
            QString name = it->data(Qt::UserRole + 1).toString();
            int n = m_unread.value(key);
            it->setText(n > 0 ? QString("%1   • %2 new").arg(name).arg(n) : name);
            QFont f = it->font(); f.setBold(n > 0); it->setFont(f);
            if (key == m_currentConv) m_sideList->setCurrentItem(it);
        }
        if (m_currentConv.isEmpty()) m_sideList->clearSelection();
        if (m_reqBtn) {
            int pending = m_pendingFriendReqs + m_pendingGroupInvites;
            m_reqBtn->setText(pending > 0 ? QString("Requests (%1)").arg(pending) : QString("Requests"));
            const char *want = pending > 0 ? "primary" : "";
            if (m_reqBtn->objectName() != QLatin1String(want)) {
                m_reqBtn->setObjectName(want);
                m_reqBtn->style()->unpolish(m_reqBtn);
                m_reqBtn->style()->polish(m_reqBtn);
            }
        }
    }

    void updateWindowTitle() {
        int total = 0;
        for (int n : m_unread) total += n;
        setWindowTitle(total > 0 ? QString("(%1) SHROUD Secure Messenger").arg(total)
                                 : QString("SHROUD Secure Messenger"));
    }

    void updateChatHeader() {
        if (!m_chatTitle) return;
        if (m_currentConv.isEmpty()) {
            m_chatAvatar->setPixmap(QIcon(":/shroud.png").pixmap(38, 38));
            m_chatTitle->setText("SHROUD");
            m_chatSub->setText("Choose a conversation to start");
        } else {
            m_chatAvatar->setPixmap(avatarIcon(m_currentName, 38, m_currentIsGroup).pixmap(38, 38));
            m_chatTitle->setText(m_currentName);
            QString sub;
            if (m_currentIsGroup)            sub = "Group";
            else if (m_selectedRecip.isEmpty()) sub = "No active device right now, so messages can't be delivered";
            else                             sub = "🔒 End-to-end encrypted";
            if (timerOn() && !m_currentIsGroup && !m_selectedRecip.isEmpty())
                sub += QString(" · ⏱ your messages disappear after %1").arg(durationLabel(gDisappearSeconds));
            m_chatSub->setText(sub);
        }
        bool haveChat = !m_currentConv.isEmpty();
        m_findBtn->setEnabled(haveChat);
        m_verifyBtn->setVisible(haveChat && !m_currentIsGroup);
        m_timerBtn->setText(timerOn() ? QString("⏱ %1").arg(durationLabel(gDisappearSeconds, true))
                                      : QString("⏱"));
        m_timerBtn->setToolTip(timerOn()
            ? QString("Disappearing messages are on: what you send is deleted after %1. Click to change.")
                  .arg(durationLabel(gDisappearSeconds))
            : QString("Disappearing messages are off. Click to make what you send delete itself."));
    }

    void updateComposerState() {
        if (!m_msgInput) return;
        bool haveChat = !m_currentConv.isEmpty();
        bool canSend = !m_maintenanceMode && haveChat && !m_currentIsGroup && !m_selectedRecip.isEmpty();
        m_msgInput->setEnabled(canSend);
        m_attachBtn->setEnabled(canSend);
        m_emojiBtn->setEnabled(canSend);
        m_sendBtn->setEnabled(canSend && !m_msgInput->text().trimmed().isEmpty());
        QString ph;
        if (m_maintenanceMode)             ph = "The relay is in maintenance. Sending is paused for your safety.";
        else if (!haveChat)                ph = "Select a conversation to start typing";
        else if (m_currentIsGroup)         ph = "Group chat isn't available in the Windows client yet";
        else if (m_selectedRecip.isEmpty()) ph = QString("%1 has no active device right now").arg(m_currentName);
        else                               ph = QString("Message %1   (Win + . for emoji)").arg(m_currentName);
        m_msgInput->setPlaceholderText(ph);
    }

    void openConversation(const QString &key, const QString &name, bool group, const QString &recip) {
        m_currentConv = key;
        m_currentName = name;
        m_currentIsGroup = group;
        m_selectedRecip = recip;
        m_unread.remove(key);
        if (m_findBtn && m_findBtn->isChecked()) m_findBtn->setChecked(false);
        renderConversation();
        updateChatHeader();
        updateComposerState();
        refreshSidebarBadges();
        updateWindowTitle();
        if (!key.isEmpty() && m_msgInput->isEnabled()) m_msgInput->setFocus();
    }

    /* Ctrl+Tab / Ctrl+Shift+Tab through the sidebar. */
    void stepConversation(int dir) {
        int n = m_sideList->count();
        if (n == 0) return;
        int cur = m_sideList->currentRow();
        for (int i = 1; i <= n; i++) {
            int r = ((cur < 0 ? (dir > 0 ? -1 : 0) : cur) + dir * i + n * 2) % n;
            QListWidgetItem *it = m_sideList->item(r);
            if (it && !it->data(Qt::UserRole).toString().isEmpty()) { sideSelect(it); return; }
        }
    }

    void findInChat(bool backward) {
        QString t = m_findEdit->text();
        if (t.isEmpty()) { setStatusLabel(m_findStatus, "", "info"); return; }
        QTextDocument::FindFlags f;
        if (backward) f |= QTextDocument::FindBackward;
        if (!m_chatLog->find(t, f)) {
            QTextCursor c = m_chatLog->textCursor();
            c.movePosition(backward ? QTextCursor::End : QTextCursor::Start);
            m_chatLog->setTextCursor(c);
            if (!m_chatLog->find(t, f)) { setStatusLabel(m_findStatus, "No matches", "err"); return; }
        }
        setStatusLabel(m_findStatus, "", "info");
    }

    void buildTimerMenu() {
        auto *menu = new QMenu(m_timerBtn);
        auto *grp = new QActionGroup(menu);
        struct Opt { const char *label; int secs; };
        static const Opt opts[] = {
            {"Off", 0}, {"30 seconds", 30}, {"5 minutes", 300}, {"1 hour", 3600},
            {"8 hours", 28800}, {"1 day", 86400}, {"1 week", 604800},
        };
        QAction *title = menu->addAction("Messages you send disappear after…");
        title->setEnabled(false);
        menu->addSeparator();
        for (const Opt &o : opts) {
            QAction *a = menu->addAction(o.label);
            a->setCheckable(true);
            a->setData(o.secs);
            grp->addAction(a);
        }
        menu->addSeparator();
        QAction *custom = menu->addAction("Custom time…");
        connect(menu, &QMenu::aboutToShow, [grp]() {
            for (QAction *a : grp->actions()) {
                int s = a->data().toInt();
                a->setChecked(s == 0 ? !(gDisappearEnabled && gDisappearSeconds > 0)
                                     : (gDisappearEnabled && gDisappearSeconds == s));
            }
        });
        connect(grp, &QActionGroup::triggered, [this](QAction *a) {
            int s = a->data().toInt();
            gDisappearEnabled = s > 0;
            if (s > 0) gDisappearSeconds = s;
            saveUserPrefs();
            onTimerChanged();
        });
        connect(custom, &QAction::triggered, [this]() { openSettings(1); });
        connect(m_timerBtn, &QPushButton::clicked, [this, menu]() {
            menu->exec(m_timerBtn->mapToGlobal(QPoint(0, m_timerBtn->height())));
        });
    }

    void onTimerChanged() {
        updateChatHeader();
        if (!m_currentConv.isEmpty() && !m_currentIsGroup)
            addSystemNote(m_currentConv, timerOn()
                ? QString("Disappearing messages on: what you send from now on is deleted after %1.")
                      .arg(durationLabel(gDisappearSeconds))
                : QString("Disappearing messages off."));
    }

    /* Drag files from Explorer onto the window to send them. */
    void dragEnterEvent(QDragEnterEvent *e) override {
        if (e->mimeData()->hasUrls() && m_msgInput && m_msgInput->isEnabled()) {
            for (const QUrl &u : e->mimeData()->urls())
                if (u.isLocalFile()) { e->acceptProposedAction(); return; }
        }
        e->ignore();
    }
    void dropEvent(QDropEvent *e) override {
        if (!m_msgInput || !m_msgInput->isEnabled()) return;
        QStringList files;
        for (const QUrl &u : e->mimeData()->urls())
            if (u.isLocalFile() && QFileInfo(u.toLocalFile()).isFile()) files << u.toLocalFile();
        e->acceptProposedAction();
        for (const QString &f : files) attachFile(f);
    }

    /* ===============================================================
     *  SIDEBAR LOGIC
     * =============================================================== */
    /* Friends-only contact list. Never lists all users. */
    void loadContacts() {
        m_sideList->clear();
        m_friends.clear();
        QByteArray r = httpPost("/api/v1/friends/list", jsonBody({{"device_id", m_deviceId}}));
        QJsonObject root = QJsonDocument::fromJson(r).object();
        QJsonArray arr = root.value("friends").toArray();
        for (const QJsonValue &v : arr) {
            QString name = v.toObject().value("username").toString();
            if (!name.isEmpty()) { m_friends << name; m_sideList->addItem(makeConvItem(name, name, false, QString())); }
        }
        if (!r.isEmpty()) m_friendsLoaded = true;
        if (root.contains("incoming")) m_pendingFriendReqs = root.value("incoming").toArray().size();
        for (const QString &x : m_extraConvs) {
            if (m_friends.contains(x)) continue;
            auto *it = makeConvItem(x, x, false, QString());
            it->setToolTip("Not in your contacts. Right-click for options.");
            m_sideList->addItem(it);
        }
        if (m_sideList->count() == 0) {
            m_sideList->addItem(placeholderItem(r.isEmpty()
                ? "Couldn't load your contacts.\nCheck your connection; SHROUD\nwill keep trying."
                : "No contacts yet.\n\nSearch for a friend's exact\nusername above, then send\nthem a friend request."));
        }
        refreshSidebarBadges();
    }

    /* Pending friend requests + group invites, for the Requests badge.
     * Also notices when a request we sent was accepted. */
    void refreshRequests() {
        QByteArray r = httpPost("/api/v1/friends/list", jsonBody({{"device_id", m_deviceId}}));
        if (!r.isEmpty()) {
            QJsonObject root = QJsonDocument::fromJson(r).object();
            m_pendingFriendReqs = root.value("incoming").toArray().size();
            QStringList now;
            for (const QJsonValue &v : root.value("friends").toArray()) {
                QString n = v.toObject().value("username").toString();
                if (!n.isEmpty()) now << n;
            }
            QStringList added;
            for (const QString &n : now) if (!m_friends.contains(n)) added << n;
            if (!added.isEmpty() && !m_tabGroups) {
                bool knewBefore = m_friendsLoaded;
                loadContacts();
                if (knewBefore)
                    notify(QString("%1 is now in your contacts.").arg(added.join(", ")));
            }
        }
        QByteArray gi = httpPost("/api/v1/groups/invites/list", jsonBody({{"device_id", m_deviceId}}));
        if (!gi.isEmpty())
            m_pendingGroupInvites = QJsonDocument::fromJson(gi).object().value("invites").toArray().size();
        refreshSidebarBadges();
        if (m_currentConv.isEmpty()) renderConversation();
    }

    /* Exact-match lookup. Updates the search-result panel. */
    void doExactSearch(const QString &raw) {
        QString q = raw.trimmed();
        if (q.isEmpty()) { hideSearchResult(); return; }
        QByteArray r = httpPost("/api/v1/contacts/search",
            jsonBody({{"device_id", m_deviceId}, {"query", q}}));
        if (r.isEmpty()) {
            notify("Couldn't search: the relay isn't answering. Try again in a moment.");
            return;
        }
        QJsonArray users = QJsonDocument::fromJson(r).object().value("users").toArray();
        QString hit = users.isEmpty() ? QString() : users[0].toString();
        showSearchResult(hit, q);
    }

    void hideSearchResult() {
        if (m_searchResult) m_searchResult->setVisible(false);
        m_searchHit.clear();
    }

    void showSearchResult(const QString &found, const QString &queried) {
        if (!m_searchResult) return;
        m_searchResult->setVisible(true);
        if (found.isEmpty()) {
            m_searchHit.clear();
            m_searchResultLabel->setText(QString("Nobody is called <b>%1</b>.<br>"
                "<span style='color:%2'>Usernames have to match exactly, including capital letters.</span>")
                .arg(queried.toHtmlEscaped(), cN(gTheme.dim)));
            m_btnMsg->setVisible(false);
            m_btnFriend->setVisible(false);
            m_btnGroupInvite->setVisible(false);
        } else {
            m_searchHit = found;
            m_searchHitIsFriend = m_friends.contains(found, Qt::CaseSensitive);
            m_searchResultLabel->setText(QString("<b>%1</b><br><span style='color:%2'>%3</span>")
                .arg(found.toHtmlEscaped(), cN(gTheme.dim),
                     m_searchHitIsFriend ? QString("Already in your contacts")
                                         : QString("Not in your contacts yet")));
            m_btnMsg->setVisible(true);
            m_btnFriend->setVisible(!m_searchHitIsFriend);
            m_btnGroupInvite->setVisible(true);
        }
    }

    /* Resolve a username to its first device_id by calling /contacts/devices. */
    /* ── Anonymous-routing helpers ────────────────────────────────── */

    /* Our long-term X25519 identity, as written by publishRatchetBundle:
     * a DPAPI-wrapped 64-byte blob of (priv || pub). */
    bool loadAnonIdentity(BYTE priv[32], BYTE pub[32]) {
        std::wstring wIdPath = (ratchetKeyDir() + "/identity.x25519").toStdWString();
        BYTE *plain = NULL; DWORD plainLen = 0;
        if (!storage_load_blob(wIdPath.c_str(), &plain, &plainLen)) return false;
        if (plainLen < 64) { free(plain); return false; }
        memcpy(priv, plain, 32);
        memcpy(pub,  plain + 32, 32);
        SecureZeroMemory(plain, plainLen);
        free(plain);
        return true;
    }

    /* Peer's published X25519 identity pubkey, cached per device id. */
    QByteArray peerX25519Pub(const QString &deviceId) {
        if (deviceId.isEmpty()) return QByteArray();
        auto it = m_peerX25519.constFind(deviceId);
        if (it != m_peerX25519.constEnd()) return it.value();
        /* /ratchet/identity, not /ratchet/bundle: the bundle endpoint
         * also hands out -- and deletes -- one of the peer's one-time
         * prekeys, which a plain identity lookup must not consume. */
        QByteArray b = httpGet(QString("/api/v1/ratchet/identity/%1").arg(deviceId).toUtf8().constData());
        QString hex = jsonStr(b, "x25519_pub");
        if (hex.isEmpty()) return QByteArray();          // pre-v1.6 peer
        QByteArray pub = QByteArray::fromHex(hex.toUtf8());
        if (pub.size() != 32) return QByteArray();
        m_peerX25519.insert(deviceId, pub);
        return pub;
    }

    /* Build the routing context for one peer.
     *
     * shared_root is ECDH(my_identity_priv, peer_identity_pub). Both
     * sides compute the same value with no extra state, which is what
     * makes the per-pair routing tag agree. The Double Ratchet's chain
     * root would give the tag forward secrecy too, but reaching it means
     * parsing the on-disk session blob format — a wrong layout
     * assumption there silently corrupts encrypted state in production.
     * The sealed envelope itself (Rule 1) is unaffected either way: that
     * uses the recipient's identity pubkey directly. */
    bool buildRoutingContext(const QString &peerDeviceId, shroud::RoutingContext &ctx) {
        QByteArray peerPub = peerX25519Pub(peerDeviceId);
        if (peerPub.size() != 32) return false;
        BYTE myPriv[32], myPub[32];
        if (!loadAnonIdentity(myPriv, myPub)) return false;
        memcpy(ctx.my_priv,  myPriv, 32);
        memcpy(ctx.my_pub,   myPub,  32);
        memcpy(ctx.peer_pub, peerPub.constData(), 32);
        bool ok = ratchet_x25519_dh(myPriv, (const BYTE *)peerPub.constData(),
                                    ctx.shared_root) ? true : false;
        SecureZeroMemory(myPriv, sizeof(myPriv));
        return ok;
    }

    shroud::AnonClient makeAnonClient() {
        return shroud::AnonClient(SERVER_HOST, SERVER_PORT, /*tolerate_self_signed=*/true);
    }

    QString resolveUsernameToDevice(const QString &username) {
        QByteArray r = httpPost("/api/v1/contacts/devices",
            jsonBody({{"device_id", m_deviceId}, {"contact_username", username}}));
        QJsonArray devs = QJsonDocument::fromJson(r).object().value("devices").toArray();
        /* Remember which username each device belongs to, so incoming
         * file/image notices (whose "name" field is the file name, not
         * the sender) can still be filed under the right person. */
        for (const QJsonValue &d : devs) {
            QString id = d.toObject().value("id").toString();
            if (!id.isEmpty()) m_deviceOwner.insert(id, username);
        }
        return devs.isEmpty() ? QString() : devs[0].toObject().value("id").toString();
    }

    QHash<QString, QString> m_deviceOwner;   // device id -> username (session cache)
    int m_undecryptable = 0;

    /* Who sent this? Text messages carry the sender's username in the
     * encrypted "name" field; file and image notices reuse "name" for the
     * file name, so for those go by the sending device instead. */
    QString senderLabelFor(const QJsonObject &plain, const QString &senderDevice) {
        QString type = plain.value("type").toString();
        bool isFileNotice = !plain.value("file_id").toString().isEmpty()
                         || type == "image" || type == "file";
        QString owner = m_deviceOwner.value(senderDevice);
        if (isFileNotice) return owner.isEmpty() ? QString("Unknown sender") : owner;
        QString name = plain.value("name").toString();
        if (!name.isEmpty()) return name;
        return owner.isEmpty() ? QString("Unknown sender") : owner;
    }

    /* A message arrived but couldn't be opened: say so instead of
     * dropping it without a trace. */
    void reportUndecryptable() {
        m_undecryptable++;
        notify(m_undecryptable == 1
            ? QString("A message arrived that couldn't be decrypted. The sender may need to update SHROUD or sign in again.")
            : QString("%1 messages this session couldn't be decrypted. The senders may need to update SHROUD or sign in again.")
                  .arg(m_undecryptable), 15000);
    }

    /* ── Server identity pinning (TOFU) ─────────────────────────────
       On first connect we record the server's triple-hybrid identity
       fingerprint (Ed25519 + ML-DSA-87 + SPHINCS+-256s). Every later
       connect we refuse if the fingerprint changed — MITM has to either
       impersonate three independent signature schemes or hijack the
       file on the user's disk. */
    /* The pin is per relay endpoint, not global.
     *
     * Every relay in the federation carries its OWN identity keypair —
     * the four production relays currently have four different
     * fingerprints. A single shared server.pin therefore meant a client
     * could only ever speak to whichever relay it happened to meet
     * first: point it at any other member and the pin check hard-refuses
     * before authentication is even attempted. That defeats the entire
     * reason for running a multi-region federation, because failing over
     * to a healthy relay looks exactly like an attack.
     *
     * Keying by host:port keeps the TOFU guarantee intact per endpoint —
     * a given relay still cannot change identity unnoticed — while
     * letting a client legitimately use more than one of them.
     *
     * The legacy single-file pin is retired rather than migrated. It
     * records no endpoint, so there is no way to tell which relay it was
     * for; copying it onto the current one would pin the wrong
     * fingerprint and produce exactly the false mismatch this change
     * exists to remove. Retiring it costs one TOFU prompt per relay. */
    QString serverPinDir() {
        QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        if (base.isEmpty()) base = QDir::tempPath();
        QString dir = base + "/SHROUD/pins";
        QDir().mkpath(dir);
        return dir;
    }

    QString serverPinPath() {
        QString endpoint = QString("%1_%2")
            .arg(QString::fromWCharArray(SERVER_HOST))
            .arg(SERVER_PORT);
        endpoint.replace(QRegularExpression("[^A-Za-z0-9_.-]"), "_");
        QString path = serverPinDir() + "/" + endpoint + ".pin";

        /* Retire the endpoint-less legacy pin (see note above). */
        QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        if (base.isEmpty()) base = QDir::tempPath();
        QString legacy = base + "/SHROUD/server.pin";
        if (QFile::exists(legacy)) QFile::remove(legacy);
        return path;
    }
    QString loadPinnedFingerprint() {
        QFile f(serverPinPath());
        if (!f.open(QIODevice::ReadOnly)) return QString();
        return QString::fromUtf8(f.readAll()).trimmed();
    }
    bool savePinnedFingerprint(const QString &fp) {
        QFile f(serverPinPath());
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
        f.write(fp.toUtf8()); return true;
    }
    /* Returns 0 = ok, 1 = first-pin saved, -1 = mismatch, -2 = endpoint missing */
    int verifyServerIdentity(QString *outFingerprint) {
        QByteArray resp = httpGet("/api/v1/server-identity");
        QJsonObject obj = QJsonDocument::fromJson(resp).object();
        QString fp = obj.value("fingerprint").toString();
        if (fp.isEmpty()) return -2;
        if (outFingerprint) *outFingerprint = fp;
        QString pinned = loadPinnedFingerprint();
        if (pinned.isEmpty()) { savePinnedFingerprint(fp); return 1; }
        if (pinned != fp) return -1;
        return 0;
    }

    /* ── Ratchet bundle publication (forward-secrecy bootstrap) ──── */
    QString ratchetKeyDir() {
        QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        if (base.isEmpty()) base = QDir::tempPath();
        QString dir = base + "/SHROUD/ratchet";
        QDir().mkpath(dir);
        return dir;
    }
    bool publishRatchetBundle(const QString &deviceId) {
        /* Idempotent — if the encrypted identity blob already exists we're done. */
        QString idPath = ratchetKeyDir() + "/identity.x25519";
        if (QFile::exists(idPath)) return true;

        BYTE idPriv[32], idPub[32];
        if (!ratchet_x25519_keygen(idPriv, idPub)) return false;

        /* Persist (priv || pub) DPAPI-wrapped so a stolen disk image is
           useless without the user's Windows credentials. */
        BYTE idBundle[64];
        memcpy(idBundle, idPriv, 32);
        memcpy(idBundle + 32, idPub, 32);
        std::wstring wIdPath = idPath.toStdWString();
        if (!storage_save_blob(wIdPath.c_str(), L"SHROUD Ratchet Identity", idBundle, 64)) return false;

        /* Generate 32 one-time prekeys; persist (prekey_id || priv) DPAPI-wrapped. */
        QJsonArray otps;
        BYTE otpBuf[32 * (4 + 32)];
        for (int i = 0; i < 32; i++) {
            BYTE pkPriv[32], pkPub[32];
            if (!ratchet_x25519_keygen(pkPriv, pkPub)) return false;
            DWORD off = i * (4 + 32);
            memcpy(otpBuf + off, &i, 4);
            memcpy(otpBuf + off + 4, pkPriv, 32);
            QJsonObject one;
            one["prekey_id"] = i;
            one["pub"] = QString::fromUtf8(crypto_hex_encode(pkPub, 32));
            otps.append(one);
        }
        std::wstring wOtpPath = (ratchetKeyDir() + "/one_time_prekeys.bin").toStdWString();
        if (!storage_save_blob(wOtpPath.c_str(), L"SHROUD Ratchet OTPs", otpBuf, sizeof(otpBuf))) return false;

        QByteArray body = jsonBody({
            {"device_id", deviceId},
            {"x25519_pub", QString::fromUtf8(crypto_hex_encode(idPub, 32))},
            {"one_time_prekeys", otps},
        });
        QByteArray resp = httpPost("/api/v1/ratchet/publish-key", body);
        return !jsonStr(resp, "published").isEmpty();
    }

    /* ── Image attachment storage ───────────────────────────────── */
    QString imagesDir() {
        QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        if (base.isEmpty()) base = QDir::tempPath();
        QString dir = base + "/SHROUD/images";
        QDir().mkpath(dir);
        return dir;
    }

    static bool isImageFileName(const QString &name) {
        QString n = name.toLower();
        return n.endsWith(".png") || n.endsWith(".jpg") || n.endsWith(".jpeg")
            || n.endsWith(".gif") || n.endsWith(".bmp") || n.endsWith(".webp");
    }

    /* Add an image message to a conversation. The image is shown inline
       (see ChatBrowser) wrapped in an anchor whose href encodes the
       file_id so anchorClicked can open the viewer. */
    void insertImageBubble(const QString &conv, const QString &fileId, const QString &localPath,
                           const QString &senderLabel, bool mine) {
        QImage img(localPath);
        ChatMsg m;
        m.from = senderLabel;
        m.mine = mine;
        m.timed = mine && timerOn();
        if (img.isNull()) {
            m.html = "<i>[image couldn't be displayed]</i>";
        } else {
            m_imagePaths[fileId] = localPath;
            m_imageCache.insert(fileId, img);
            m.imageId = fileId;
        }
        appendMessage(conv, m);
    }

    void onChatAnchorClicked(const QUrl &url) {
        if (url.scheme() != "shroud-img") return;
        QString fileId = url.host().isEmpty() ? url.path().mid(1) : url.host();
        if (fileId.isEmpty()) fileId = url.toString().section("//", 1, 1);
        QString path = m_imagePaths.value(fileId);
        if (path.isEmpty() || !QFileInfo::exists(path)) {
            QMessageBox::information(this, "Image", "This image is no longer available.");
            return;
        }
        openImageViewer(fileId, path);
    }

    void onChatContextMenu(const QPoint &pos) {
        QTextCursor cur = m_chatLog->cursorForPosition(pos);
        QString href = cur.charFormat().anchorHref();
        QMenu menu(this);
        if (href.startsWith("shroud-img://")) {
            QString fileId = href.mid(QString("shroud-img://").length());
            QAction *open = menu.addAction("Open Full Size");
            QAction *del = menu.addAction("Delete Image");
            menu.addSeparator();
            menu.addAction("Copy", [this]() { m_chatLog->copy(); });
            QAction *chosen = menu.exec(m_chatLog->mapToGlobal(pos));
            if (chosen == open) {
                QString path = m_imagePaths.value(fileId);
                if (!path.isEmpty()) openImageViewer(fileId, path);
            } else if (chosen == del) {
                if (QMessageBox::question(this, "Delete Image",
                    "Permanently delete this image for both you and the recipient?",
                    QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
                    deleteImage(fileId);
            }
        } else {
            menu.addAction("Copy", [this]() { m_chatLog->copy(); });
            menu.exec(m_chatLog->mapToGlobal(pos));
        }
    }

    /* Server delete + local cache delete + remove the bubble from chat. */
    void deleteImage(const QString &fileId) {
        HttpResponse *r = network_delete(
            QString("/api/v1/files/%1").arg(fileId).toUtf8().constData(),
            m_deviceId.toUtf8().constData());
        if (r) network_free_response(r);
        QString path = m_imagePaths.take(fileId);
        if (!path.isEmpty()) QFile::remove(path);
        replaceImageInChatLog(fileId);
    }

    /* After deletion, swap the image for a placeholder in whichever
       conversation holds it. */
    void replaceImageInChatLog(const QString &fileId) {
        m_imageCache.remove(fileId);
        bool touchedCurrent = false;
        for (auto it = m_conv.begin(); it != m_conv.end(); ++it) {
            for (ChatMsg &m : it.value()) {
                if (m.imageId != fileId) continue;
                m.imageId.clear();
                m.html = QString("<i style='color:%1'>image deleted</i>").arg(cN(gTheme.dim));
                if (it.key() == m_currentConv) touchedCurrent = true;
            }
        }
        if (touchedCurrent) renderConversation();
    }

    void openImageViewer(const QString &fileId, const QString &path) {
        ImageViewer *v = new ImageViewer(fileId, path, this);
        connect(v, &ImageViewer::deleteRequested, this, [this](const QString &fid) {
            if (QMessageBox::question(this, "Delete Image",
                "Permanently delete this image for both you and the recipient?",
                QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
                deleteImage(fid);
        });
        v->show();
    }

    void selectUsernameForChat(const QString &username) {
        QString did = resolveUsernameToDevice(username);
        if (!m_friends.contains(username) && !m_extraConvs.contains(username)) {
            m_extraConvs << username;
            if (!m_tabGroups) {
                auto *it = makeConvItem(username, username, false, QString());
                it->setToolTip("Not in your contacts. Right-click for options.");
                m_sideList->addItem(it);
            }
        }
        hideSearchResult();
        m_search->clear();
        openConversation(username, username, false, did);
        if (did.isEmpty())
            notify(QString("%1 has no active device right now, so messages can't be delivered yet.").arg(username));
    }

    /* Extract server-side error detail (FastAPI: {"detail":"..."}) safely. */
    QString jsonDetail(const QByteArray &resp, const QString &fallback) {
        QString d = QJsonDocument::fromJson(resp).object().value("detail").toString();
        return d.isEmpty() ? fallback : d;
    }

    void sendFriendRequest(const QString &username) {
        bool ok = false;
        QString reason = QInputDialog::getText(this, "Add friend",
            QString("Send %1 a friend request?\n\nAdd a short note so they know it's you (optional):").arg(username),
            QLineEdit::Normal, "", &ok);
        if (!ok) return;
        QByteArray body = jsonBody({
            {"device_id", m_deviceId}, {"target_username", username}, {"reason", reason}
        });
        QByteArray r = httpPost("/api/v1/friends/request", body);
        QJsonObject obj = QJsonDocument::fromJson(r).object();
        if (obj.contains("request_id")) {
            hideSearchResult();
            notify(QString("Friend request sent to %1. They'll appear in your contacts once they accept.").arg(username), 10000);
        } else {
            QMessageBox::warning(this, "Add friend", r.isEmpty()
                ? QString("Couldn't reach the relay, so the request wasn't sent.")
                : QString("The request to %1 wasn't sent: %2").arg(username, jsonDetail(r, "unknown error")));
        }
    }

    void inviteToGroup(const QString &username) {
        /* Pick one of the user's groups. */
        QByteArray r = httpGet(QString("/api/v1/groups/%1").arg(m_deviceId).toUtf8().constData());
        QJsonArray groups = QJsonDocument::fromJson(r).object().value("groups").toArray();
        QStringList names, ids;
        for (const QJsonValue &v : groups) {
            QJsonObject g = v.toObject();
            QString gid = g.value("id").toString();
            QString gname = g.value("name").toString();
            if (!gid.isEmpty()) { ids << gid; names << gname; }
        }
        if (names.isEmpty()) {
            QMessageBox::information(this, "Invite to a group",
                "You don't have any groups yet. Click \"+ New group\" at the bottom left to create one first.");
            return;
        }
        bool ok = false;
        QString chosen = QInputDialog::getItem(this, "Invite to a group",
            QString("Invite %1 to which group?").arg(username), names, 0, false, &ok);
        if (!ok || chosen.isEmpty()) return;
        QString gid = ids[names.indexOf(chosen)];
        QString reason = QInputDialog::getText(this, "Invite to a group",
            "Add a short note for them (optional):", QLineEdit::Normal, "", &ok);
        if (!ok) return;
        QByteArray body = jsonBody({
            {"device_id", m_deviceId}, {"group_id", gid},
            {"target_username", username}, {"reason", reason}
        });
        QByteArray rr = httpPost("/api/v1/groups/invite", body);
        QJsonObject obj = QJsonDocument::fromJson(rr).object();
        if (obj.contains("invite_id")) {
            notify(QString("Invited %1 to %2.").arg(username, chosen), 8000);
        } else {
            QMessageBox::warning(this, "Invite to a group", rr.isEmpty()
                ? QString("Couldn't reach the relay, so the invite wasn't sent.")
                : QString("The invite wasn't sent: %1").arg(jsonDetail(rr, "unknown error")));
        }
    }

    /* ── Requests dialog: pending friend requests + group invites. ── */
    void openRequestsDialog() {
        QDialog dlg(this);
        dlg.setWindowTitle("Requests");
        dlg.resize(540, 460);
        auto *lay = new QVBoxLayout(&dlg);
        auto *tabs = new QTabWidget;

        /* Friend requests tab */
        auto *fw = new QWidget; auto *fl = new QVBoxLayout(fw);
        auto *fList = new QListWidget; fl->addWidget(fList, 1);
        auto *frRow = new QHBoxLayout;
        auto *frAccept = new QPushButton("Accept");
        frAccept->setObjectName("primary");
        auto *frDeny = new QPushButton("Decline");
        frRow->addStretch(); frRow->addWidget(frAccept); frRow->addWidget(frDeny);
        fl->addLayout(frRow);
        fList->setIconSize(QSize(32, 32));
        tabs->addTab(fw, "Friend requests");

        /* Group invites tab */
        auto *gw = new QWidget; auto *gl = new QVBoxLayout(gw);
        auto *gList = new QListWidget; gl->addWidget(gList, 1);
        auto *giRow = new QHBoxLayout;
        auto *giAccept = new QPushButton("Join");
        giAccept->setObjectName("primary");
        auto *giDeny = new QPushButton("Decline");
        giRow->addStretch(); giRow->addWidget(giAccept); giRow->addWidget(giDeny);
        gl->addLayout(giRow);
        gList->setIconSize(QSize(32, 32));
        tabs->addTab(gw, "Group invites");

        lay->addWidget(tabs, 1);
        auto *closeRow = new QHBoxLayout;
        auto *closeBtn = new QPushButton("Close");
        connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
        closeRow->addStretch();
        closeRow->addWidget(closeBtn);
        lay->addLayout(closeRow);

        /* Holds (id, from, reason) per row so we can act on selection. */
        QList<QStringList> frData, giData;

        auto reloadFriends = [&]() {
            fList->clear(); frData.clear();
            QByteArray r = httpPost("/api/v1/friends/list", jsonBody({{"device_id", m_deviceId}}));
            QJsonArray incoming = QJsonDocument::fromJson(r).object().value("incoming").toArray();
            for (const QJsonValue &v : incoming) {
                QJsonObject o = v.toObject();
                QString id = o.value("id").toString();
                QString from = o.value("from").toString();
                QString reason = o.value("reason").toString();
                if (id.isEmpty()) continue;
                frData << QStringList{id, from, reason};
                auto *it = new QListWidgetItem(avatarIcon(from, 32),
                    reason.isEmpty() ? from : QString("%1\n\"%2\"").arg(from, reason));
                it->setSizeHint(QSize(0, 48));
                fList->addItem(it);
            }
            if (frData.isEmpty())
                fList->addItem(placeholderItem(r.isEmpty() ? "Couldn't load requests." : "No friend requests right now."));
            else fList->setCurrentRow(0);
            frAccept->setEnabled(!frData.isEmpty());
            frDeny->setEnabled(!frData.isEmpty());
            tabs->setTabText(0, frData.isEmpty() ? QString("Friend requests") : QString("Friend requests (%1)").arg(frData.size()));
            m_pendingFriendReqs = frData.size();
        };

        auto reloadInvites = [&]() {
            gList->clear(); giData.clear();
            QByteArray r = httpPost("/api/v1/groups/invites/list", jsonBody({{"device_id", m_deviceId}}));
            QJsonArray invites = QJsonDocument::fromJson(r).object().value("invites").toArray();
            for (const QJsonValue &v : invites) {
                QJsonObject o = v.toObject();
                QString id = o.value("id").toString();
                QString gname = o.value("group_name").toString();
                QString from = o.value("from").toString();
                QString reason = o.value("reason").toString();
                if (id.isEmpty()) continue;
                giData << QStringList{id, gname, from, reason};
                QString label = QString("%1 invited you to %2").arg(from, gname);
                if (!reason.isEmpty()) label += QString("\n\"%1\"").arg(reason);
                auto *it = new QListWidgetItem(avatarIcon(gname, 32, true), label);
                it->setSizeHint(QSize(0, 48));
                gList->addItem(it);
            }
            if (giData.isEmpty())
                gList->addItem(placeholderItem(r.isEmpty() ? "Couldn't load invites." : "No group invites right now."));
            else gList->setCurrentRow(0);
            giAccept->setEnabled(!giData.isEmpty());
            giDeny->setEnabled(!giData.isEmpty());
            tabs->setTabText(1, giData.isEmpty() ? QString("Group invites") : QString("Group invites (%1)").arg(giData.size()));
            m_pendingGroupInvites = giData.size();
        };

        auto respondFriend = [&](bool accept) {
            int row = fList->currentRow();
            if (row < 0 || row >= frData.size()) return;
            QString reason;
            if (!accept) {
                bool ok = false;
                reason = QInputDialog::getText(&dlg, "Decline", "Reason, if you want to give one (optional):", QLineEdit::Normal, "", &ok);
                if (!ok) return;
            }
            QByteArray body = jsonBody({
                {"device_id", m_deviceId}, {"request_id", frData[row][0]},
                {"accept", accept}, {"reason", reason}
            });
            QByteArray rr = httpPost("/api/v1/friends/respond", body);
            if (rr.isEmpty() || rr.contains("\"detail\"")) {
                QMessageBox::warning(&dlg, "Friend request", rr.isEmpty()
                    ? QString("Couldn't reach the relay. Nothing was changed.")
                    : QString("That didn't work: %1").arg(jsonDetail(rr, "unknown error")));
                return;
            }
            QString who = frData[row][1];
            reloadFriends();
            if (accept) {
                if (!m_tabGroups) loadContacts();
                notify(QString("%1 is now in your contacts.").arg(who));
            }
        };

        auto respondInvite = [&](bool accept) {
            int row = gList->currentRow();
            if (row < 0 || row >= giData.size()) return;
            QString reason;
            if (!accept) {
                bool ok = false;
                reason = QInputDialog::getText(&dlg, "Decline", "Reason, if you want to give one (optional):", QLineEdit::Normal, "", &ok);
                if (!ok) return;
            }
            QByteArray body = jsonBody({
                {"device_id", m_deviceId}, {"invite_id", giData[row][0]},
                {"accept", accept}, {"reason", reason}
            });
            QByteArray rr = httpPost("/api/v1/groups/invites/respond", body);
            if (rr.isEmpty() || rr.contains("\"detail\"")) {
                QMessageBox::warning(&dlg, "Group invite", rr.isEmpty()
                    ? QString("Couldn't reach the relay. Nothing was changed.")
                    : QString("That didn't work: %1").arg(jsonDetail(rr, "unknown error")));
                return;
            }
            reloadInvites();
            if (accept && m_tabGroups) loadGroups();
        };

        connect(frAccept, &QPushButton::clicked, [&]() { respondFriend(true); });
        connect(frDeny,   &QPushButton::clicked, [&]() { respondFriend(false); });
        connect(giAccept, &QPushButton::clicked, [&]() { respondInvite(true); });
        connect(giDeny,   &QPushButton::clicked, [&]() { respondInvite(false); });

        connect(fList, &QListWidget::itemDoubleClicked, [&]() { respondFriend(true); });
        connect(gList, &QListWidget::itemDoubleClicked, [&]() { respondInvite(true); });
        reloadFriends();
        reloadInvites();
        if (frData.isEmpty() && !giData.isEmpty()) tabs->setCurrentIndex(1);
        dlg.exec();
        refreshSidebarBadges();
        if (m_currentConv.isEmpty()) renderConversation();   /* welcome text counts requests */
    }

    void loadGroups() {
        m_sideList->clear();
        QByteArray r = httpGet(QString("/api/v1/groups/%1").arg(m_deviceId).toUtf8().constData());
        QJsonArray groups = QJsonDocument::fromJson(r).object().value("groups").toArray();
        for (const QJsonValue &v : groups) {
            QJsonObject g = v.toObject();
            QString gid = g.value("id").toString();
            QString name = g.value("name").toString();
            if (gid.isEmpty()) continue;
            if (name.isEmpty()) name = "Unnamed group";
            auto *it = makeConvItem("#" + gid, name, true, gid);
            it->setToolTip(QString("Group ID %1").arg(gid));
            m_sideList->addItem(it);
        }
        if (m_sideList->count() == 0) {
            m_sideList->addItem(placeholderItem(r.isEmpty()
                ? "Couldn't load your groups.\nCheck your connection."
                : "No groups yet.\n\nClick \"+ New group\" to start\none, then invite friends\nfrom the search box."));
        }
        refreshSidebarBadges();
    }

    void createGroup(const QString &name) {
        QVariantList members{ QVariantMap{
            {"device_id", m_deviceId}, {"encrypted_group_key", QString("demo")}
        }};
        QByteArray body = jsonBody({
            {"group_name", name.isEmpty() ? QString("New Group") : name},
            {"creator_device_id", m_deviceId},
            {"members", members}
        });
        httpPost("/api/v1/groups/create", body);
        loadGroups();
    }

    void sideSelect(QListWidgetItem *item) {
        if (!item) return;
        QString key = item->data(Qt::UserRole).toString();
        if (key.isEmpty()) return;                      /* placeholder row */
        if (key == m_currentConv && !m_selectedRecip.isEmpty()) return;
        QString name = item->data(Qt::UserRole + 1).toString();
        bool group = key.startsWith('#');
        QString recip;
        if (group) {
            recip = item->data(Qt::UserRole + 2).toString();
        } else {
            /* Sidebar items are usernames; resolve to a device_id for sending. */
            recip = resolveUsernameToDevice(name);
            if (recip.isEmpty())
                notify(QString("%1 has no active device right now, so messages can't be delivered yet.").arg(name));
        }
        openConversation(key, name, group, recip);
    }

    /* Right-click on a sidebar entry. */
    void onContactContextMenu(const QPoint &pos) {
        QListWidgetItem *item = m_sideList->itemAt(pos);
        if (!item) return;
        QString key = item->data(Qt::UserRole).toString();
        if (key.isEmpty()) return;
        QString name = item->data(Qt::UserRole + 1).toString();
        bool group = key.startsWith('#');

        QMenu menu(this);
        QAction *open = menu.addAction("Open conversation");
        QAction *verify = nullptr, *copy = nullptr, *add = nullptr;
        if (!group) {
            verify = menu.addAction("Verify safety number…");
            copy = menu.addAction("Copy username");
            if (!m_friends.contains(name)) add = menu.addAction("Send friend request…");
        } else {
            copy = menu.addAction("Copy group ID");
        }
        menu.addSeparator();
        QAction *clear = menu.addAction("Clear conversation on this PC");
        clear->setEnabled(!m_conv.value(key).isEmpty());
        QAction *chosen = menu.exec(m_sideList->mapToGlobal(pos));
        if (!chosen) return;
        if (chosen == open) sideSelect(item);
        else if (chosen == verify) showSafetyNumber(name);
        else if (chosen == copy) {
            QApplication::clipboard()->setText(group ? item->data(Qt::UserRole + 2).toString() : name);
            notify("Copied to clipboard.", 3000);
        }
        else if (chosen == add) sendFriendRequest(name);
        else if (chosen == clear) {
            m_conv.remove(key);
            m_unread.remove(key);
            if (key == m_currentConv) renderConversation();
            refreshSidebarBadges();
            updateWindowTitle();
        }
    }

    /* Pulls the contact's X25519 ratchet identity from the server,
     * combines it with ours, and shows the 30-digit number. Users
     * compare out-of-band to defeat MITM. */
    void showSafetyNumber(const QString &uname) {
        QString did = resolveUsernameToDevice(uname);
        if (did.isEmpty()) {
            QMessageBox::information(this, "Safety number",
                QString("%1 has no active device right now. Try again once they've been online.").arg(uname));
            return;
        }
        QByteArray b = httpGet(QString("/api/v1/ratchet/identity/%1").arg(did).toUtf8().constData());
        QString theirPubHex = jsonStr(b, "x25519_pub");
        if (theirPubHex.isEmpty()) {
            QMessageBox::information(this, "Safety number",
                QString("%1 is using an older SHROUD version that doesn't publish a safety number yet.").arg(uname));
            return;
        }
        QByteArray theirPub = QByteArray::fromHex(theirPubHex.toUtf8());
        if (theirPub.size() != 32) {
            QMessageBox::warning(this, "Safety number",
                "The relay returned a malformed key for this contact. Don't trust this conversation until it's resolved.");
            return;
        }

        /* Read our own X25519 pub from the DPAPI-wrapped identity blob. */
        BYTE myPriv[32], myPub[32];
        if (!loadMyX25519Identity(myPriv, myPub)) {
            QMessageBox::warning(this, "Safety number",
                "Your own encryption identity on this PC couldn't be read. Signing out and back in regenerates it.");
            return;
        }
        SecureZeroMemory(myPriv, sizeof(myPriv));

        char *fp = safety_number_compute(myPub, (const BYTE*)theirPub.constData());
        QString number = fp ? QString::fromUtf8(fp) : QString();
        free(fp);
        if (number.isEmpty()) {
            QMessageBox::warning(this, "Safety number", "Couldn't compute the safety number.");
            return;
        }

        QDialog dlg(this);
        dlg.setWindowTitle(QString("Verify %1").arg(uname));
        dlg.setMinimumWidth(460);
        auto *l = new QVBoxLayout(&dlg);
        l->setContentsMargins(24, 20, 24, 16);
        l->setSpacing(10);
        auto *hdr = new QLabel(QString("Safety number with <b>%1</b>").arg(uname.toHtmlEscaped()));
        hdr->setObjectName("subheading");
        l->addWidget(hdr);
        auto *num = new QLabel(number);
        num->setAlignment(Qt::AlignCenter);
        num->setWordWrap(true);
        num->setTextInteractionFlags(Qt::TextSelectableByMouse);
        num->setStyleSheet(QString("font-family: Consolas, monospace; font-size: 20pt; letter-spacing: 2px; "
                                   "color: %1; padding: 14px; border: 1px solid %2; border-radius: 10px;")
                               .arg(cN(gTheme.accent), cN(gTheme.border)));
        l->addWidget(num);
        auto *how = new QLabel(QString(
            "Compare this number with %1 in person, on a call, or over any other channel you trust. "
            "<br><br><b>Same number on both screens:</b> nobody is in the middle.<br>"
            "<b>Different numbers:</b> don't trust this conversation.").arg(uname.toHtmlEscaped()));
        how->setWordWrap(true);
        how->setObjectName("muted");
        l->addWidget(how);
        auto *btns = new QHBoxLayout;
        auto *copyBtn = new QPushButton("Copy number");
        auto *okBtn = new QPushButton("Done");
        okBtn->setObjectName("primary");
        okBtn->setDefault(true);
        btns->addWidget(copyBtn);
        btns->addStretch();
        btns->addWidget(okBtn);
        l->addLayout(btns);
        connect(copyBtn, &QPushButton::clicked, [number, copyBtn]() {
            QApplication::clipboard()->setText(number);
            copyBtn->setText("Copied");
        });
        connect(okBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
        dlg.exec();
    }

    /* ===============================================================
     *  DOUBLE RATCHET + X3DH — per-peer session management
     *
     * v2.2 upgrade: bootstrap now uses Signal's X3DH handshake instead
     * of the v2.1 static-static-DH. The first envelope of every session
     * carries a 40-byte X3DH preamble:
     *
     *     [4B  magic 'X3D1' LE = 0x31443358]
     *     [32B Alice's ephemeral X25519 pub (EK_A)]
     *     [4B  one-time-prekey id used (LE), or 0xFFFFFFFF if none]
     *     [   ...DR22 envelope continues...        ]
     *
     * Alice (sender, first message) flow:
     *   1. GET /api/v1/ratchet/bundle/{peer} — server atomically deletes
     *      one of peer's published one-time prekeys and returns its pub.
     *   2. Generate fresh ephemeral EK_A keypair (single-session).
     *   3. SK = ratchet_x3dh_alice(IK_A_priv, EK_A_priv, IK_B_pub, OPK_B_pub).
     *   4. ratchet_init_alice(state, SK, IK_B_pub) — DH chain starts.
     *   5. Persist EK_A pub + otp_id in a side-file so we can re-emit the
     *      preamble on retries until Bob actually replies.
     *
     * Bob (receiver, first message from this sender) flow:
     *   1. Detect X3D1 magic on the wire, lift EK_A pub + otp_id.
     *   2. Look up our OPK_B priv in local DPAPI store by id.
     *   3. SK = ratchet_x3dh_bob(IK_B_priv, OPK_B_priv, IK_A_pub, EK_A_pub).
     *   4. ratchet_init_bob(state, SK, IK_B_priv, IK_B_pub).
     *   5. Decrypt. On success, DELETE OPK_B from the on-disk OTP store —
     *      single-use, locks in forward secrecy.
     *
     * Alice keeps re-emitting the preamble on every outbound message
     * until her local state shows has_ckr=true (meaning she's received
     * and processed at least one reply from Bob). Once Bob replies, the
     * preamble is dropped and the side-file is cleared. Idempotent on
     * Bob's side — if he sees a preamble for a session he's already
     * bootstrapped, he just strips it and uses his existing state.
     *
     * Closes the v2.1 concurrent-first-send divergence: even if both
     * sides send simultaneously, each side's first message carries an
     * X3DH preamble and the receiver bootstraps a NEW state from it,
     * matching the sender. Each direction is an independent ratchet
     * chain bootstrapped from independent ephemerals.
     * =============================================================== */

    static constexpr quint32 X3DH_MAGIC      = 0x31443358u;   /* 'X3D1' LE */
    static constexpr int     X3DH_PREAMBLE_LEN = 40;          /* 4 + 32 + 4 */
    static constexpr quint32 X3DH_NO_OTP     = 0xFFFFFFFFu;

    QString peerRatchetPath(const QString &peerDeviceId) {
        return ratchetKeyDir() + "/peer_" + peerDeviceId + ".state";
    }
    QString peerX3dhSidePath(const QString &peerDeviceId) {
        return ratchetKeyDir() + "/peer_" + peerDeviceId + ".x3dh";
    }
    QString myOtpStorePath() {
        return ratchetKeyDir() + "/one_time_prekeys.bin";
    }

    /* Load this device's long-term X25519 ratchet identity from the
     * DPAPI-wrapped identity.x25519 blob written at login by
     * publishRatchetBundle(). */
    bool loadMyX25519Identity(BYTE priv_out[32], BYTE pub_out[32]) {
        std::wstring wIdPath = (ratchetKeyDir() + "/identity.x25519").toStdWString();
        BYTE *plain = nullptr; DWORD plainLen = 0;
        if (!storage_load_blob(wIdPath.c_str(), &plain, &plainLen) || plainLen < 64) {
            if (plain) free(plain);
            return false;
        }
        memcpy(priv_out, plain, 32);
        memcpy(pub_out,  plain + 32, 32);
        free(plain);
        return true;
    }

    /* Fetch a peer's published X25519 identity WITHOUT consuming an OTP.
     * Used by Bob to look up Alice's IK during X3DH bootstrap, and by
     * the safety-number UI. */
    bool fetchPeerX25519(const QString &peerDeviceId, BYTE peer_pub_out[32]) {
        QByteArray r = httpGet(
            QString("/api/v1/ratchet/identity/%1").arg(peerDeviceId).toUtf8().constData());
        QString hex = jsonStr(r, "x25519_pub");
        if (hex.isEmpty()) return false;
        QByteArray bin = QByteArray::fromHex(hex.toUtf8());
        if (bin.size() != 32) return false;
        memcpy(peer_pub_out, bin.constData(), 32);
        return true;
    }

    /* Fetch the full ratchet bundle for `peer`. The server CONSUMES one
     * of the peer's published one-time prekeys as part of this call (it's
     * deleted from their pool atomically), so this MUST only be called
     * by Alice on first-send for a session — never on every message. */
    struct PeerBundle {
        BYTE     ik_pub[32];
        BYTE     opk_pub[32];
        bool     has_opk;
        quint32  opk_id;
    };
    bool fetchPeerBundle(const QString &peerDeviceId, PeerBundle *out) {
        QByteArray r = httpGet(
            QString("/api/v1/ratchet/bundle/%1").arg(peerDeviceId).toUtf8().constData());
        if (r.isEmpty()) return false;
        QJsonObject obj = QJsonDocument::fromJson(r).object();
        QByteArray ik = QByteArray::fromHex(obj.value("x25519_pub").toString().toUtf8());
        if (ik.size() != 32) return false;
        memcpy(out->ik_pub, ik.constData(), 32);
        out->has_opk = false;
        out->opk_id  = X3DH_NO_OTP;
        QJsonValue otpV = obj.value("one_time_prekey");
        if (otpV.isObject()) {
            QJsonObject otp = otpV.toObject();
            QByteArray opk = QByteArray::fromHex(otp.value("pub").toString().toUtf8());
            if (opk.size() == 32) {
                memcpy(out->opk_pub, opk.constData(), 32);
                out->opk_id = (quint32)otp.value("prekey_id").toInt();
                out->has_opk = true;
            }
        }
        return true;
    }

    /* OTP local store: contiguous [4B prekey_id || 32B priv] entries
     * written DPAPI-wrapped by publishRatchetBundle(). Both halves of
     * lookup-and-delete are exposed separately so the caller can defer
     * deletion until AFTER state is safely persisted. */
    bool lookupMyOtpPriv(quint32 otp_id, BYTE priv_out[32]) {
        std::wstring wPath = myOtpStorePath().toStdWString();
        BYTE *plain = nullptr; DWORD plainLen = 0;
        if (!storage_load_blob(wPath.c_str(), &plain, &plainLen)) return false;
        constexpr DWORD entry = 4 + 32;
        if (plainLen == 0 || plainLen % entry != 0) { free(plain); return false; }
        bool found = false;
        for (DWORD i = 0; i < plainLen; i += entry) {
            quint32 id; memcpy(&id, plain + i, 4);
            if (id == otp_id) { memcpy(priv_out, plain + i + 4, 32); found = true; break; }
        }
        free(plain);
        return found;
    }
    bool deleteMyOtp(quint32 otp_id) {
        std::wstring wPath = myOtpStorePath().toStdWString();
        BYTE *plain = nullptr; DWORD plainLen = 0;
        if (!storage_load_blob(wPath.c_str(), &plain, &plainLen)) return false;
        constexpr DWORD entry = 4 + 32;
        if (plainLen == 0 || plainLen % entry != 0) { free(plain); return false; }
        DWORD writeOff = 0;
        BYTE *out = (BYTE*)malloc(plainLen);
        if (!out) { free(plain); return false; }
        for (DWORD i = 0; i < plainLen; i += entry) {
            quint32 id; memcpy(&id, plain + i, 4);
            if (id == otp_id) continue;
            memcpy(out + writeOff, plain + i, entry);
            writeOff += entry;
        }
        free(plain);
        bool ok = true;
        if (writeOff == 0) {
            /* No entries left — keep zero-byte file so next publish replaces. */
            ok = storage_save_blob(wPath.c_str(), L"SHROUD Ratchet OTPs", out, 0);
        } else {
            ok = storage_save_blob(wPath.c_str(), L"SHROUD Ratchet OTPs", out, writeOff);
        }
        free(out);
        return ok;
    }

    bool loadPeerRatchet(const QString &peerDeviceId, RatchetState *st) {
        std::wstring wPath = peerRatchetPath(peerDeviceId).toStdWString();
        BYTE *plain = nullptr; DWORD plainLen = 0;
        if (!storage_load_blob(wPath.c_str(), &plain, &plainLen)) return false;
        if (plainLen != sizeof(RatchetState)) { free(plain); return false; }
        memcpy(st, plain, sizeof(RatchetState));
        free(plain);
        return true;
    }
    bool savePeerRatchet(const QString &peerDeviceId, const RatchetState *st) {
        std::wstring wPath = peerRatchetPath(peerDeviceId).toStdWString();
        return storage_save_blob(wPath.c_str(),
                                 L"SHROUD Ratchet Peer State",
                                 reinterpret_cast<const BYTE*>(st),
                                 (DWORD)sizeof(*st));
    }

    /* X3DH side-file: [32B EK_A pub || 4B otp_id LE]. Stored only while
     * Alice is still waiting for Bob's first reply. Cleared as soon as
     * the inbound ratchet reply lands and has_ckr flips true. */
    bool loadX3dhSide(const QString &peerDeviceId, BYTE ek_pub_out[32], quint32 *otp_id_out) {
        std::wstring wPath = peerX3dhSidePath(peerDeviceId).toStdWString();
        BYTE *plain = nullptr; DWORD plainLen = 0;
        if (!storage_load_blob(wPath.c_str(), &plain, &plainLen) || plainLen != 36) {
            if (plain) free(plain);
            return false;
        }
        memcpy(ek_pub_out, plain, 32);
        memcpy(otp_id_out, plain + 32, 4);
        free(plain);
        return true;
    }
    bool saveX3dhSide(const QString &peerDeviceId, const BYTE ek_pub[32], quint32 otp_id) {
        std::wstring wPath = peerX3dhSidePath(peerDeviceId).toStdWString();
        BYTE buf[36];
        memcpy(buf, ek_pub, 32);
        memcpy(buf + 32, &otp_id, 4);
        return storage_save_blob(wPath.c_str(), L"SHROUD X3DH side",
                                 buf, sizeof(buf));
    }
    void deleteX3dhSide(const QString &peerDeviceId) {
        QString p = peerX3dhSidePath(peerDeviceId);
        if (QFile::exists(p)) QFile::remove(p);
    }

    /* Encrypt `plaintext` for `peerDeviceId`. On first send for a new
     * session, runs X3DH bootstrap as Alice and prepends the X3D1 wire
     * preamble; on subsequent sends until Bob replies, re-emits the
     * preamble (idempotent on Bob's side); after Bob's reply, emits a
     * bare DR22 envelope.
     *
     * Returns hex-encoded wire bytes on success, empty on failure. */
    QByteArray ratchetEncryptForPeer(const QString &peerDeviceId, const QByteArray &plaintext) {
        RatchetState st;
        bool bootstrapped_now = false;
        BYTE  ek_pub[32];
        quint32 otp_id = X3DH_NO_OTP;

        if (!loadPeerRatchet(peerDeviceId, &st)) {
            /* Brand-new session — run X3DH as Alice. */
            BYTE myIkPriv[32], myIkPub[32];
            if (!loadMyX25519Identity(myIkPriv, myIkPub)) return QByteArray();
            PeerBundle pb;
            if (!fetchPeerBundle(peerDeviceId, &pb)) return QByteArray();
            BYTE ekPriv[32];
            if (!ratchet_x25519_keygen(ekPriv, ek_pub)) return QByteArray();
            BYTE sk[32];
            if (!ratchet_x3dh_alice(myIkPriv, ekPriv, pb.ik_pub,
                                    pb.has_opk ? pb.opk_pub : nullptr, sk)) return QByteArray();
            if (!ratchet_init_alice(&st, sk, pb.ik_pub)) return QByteArray();
            otp_id = pb.has_opk ? pb.opk_id : X3DH_NO_OTP;
            if (!saveX3dhSide(peerDeviceId, ek_pub, otp_id)) return QByteArray();
            bootstrapped_now = true;
        }

        /* Decide whether to emit the X3DH preamble. We do so until Bob
         * has clearly replied (has_ckr) — covers message loss / retries. */
        bool emit_preamble = bootstrapped_now;
        if (!emit_preamble && !st.has_ckr) {
            if (loadX3dhSide(peerDeviceId, ek_pub, &otp_id)) emit_preamble = true;
        }

        DWORD cap = RATCHET_HEADER_LEN + RATCHET_NONCE_LEN
                  + (DWORD)plaintext.size() + RATCHET_GCM_TAG_LEN;
        QByteArray drEnv(cap, Qt::Uninitialized);
        DWORD got = cap;
        if (!ratchet_encrypt(&st,
                             reinterpret_cast<const BYTE*>(plaintext.constData()),
                             (DWORD)plaintext.size(),
                             nullptr, 0,
                             reinterpret_cast<BYTE*>(drEnv.data()), &got)) {
            return QByteArray();
        }
        drEnv.resize((int)got);
        if (!savePeerRatchet(peerDeviceId, &st)) return QByteArray();

        QByteArray full;
        if (emit_preamble) {
            full.resize(X3DH_PREAMBLE_LEN);
            const quint32 m = X3DH_MAGIC;
            memcpy(full.data(),     &m,     4);
            memcpy(full.data() + 4, ek_pub, 32);
            memcpy(full.data() + 36, &otp_id, 4);
            full.append(drEnv);
        } else {
            full = drEnv;
        }
        return full.toHex();
    }

    /* Inverse of ratchetEncryptForPeer. Detects an X3DH preamble; if
     * present and we have no state for this sender, runs X3DH as Bob,
     * bootstraps state, decrypts, and deletes the consumed OTP. If
     * present and we already have state, just strips it and continues. */
    QByteArray ratchetDecryptFromPeer(const QString &peerDeviceId, const QByteArray &envHex) {
        QByteArray env = QByteArray::fromHex(envHex);
        if (env.size() < (int)(RATCHET_HEADER_LEN + RATCHET_NONCE_LEN + RATCHET_GCM_TAG_LEN))
            return QByteArray();

        BYTE  peer_ek_pub[32];
        quint32 peer_otp_id = X3DH_NO_OTP;
        bool  has_preamble = false;
        if (env.size() >= X3DH_PREAMBLE_LEN + (int)(RATCHET_HEADER_LEN + RATCHET_NONCE_LEN + RATCHET_GCM_TAG_LEN)) {
            quint32 magic;
            memcpy(&magic, env.constData(), 4);
            if (magic == X3DH_MAGIC) {
                memcpy(peer_ek_pub, env.constData() + 4, 32);
                memcpy(&peer_otp_id, env.constData() + 36, 4);
                env = env.mid(X3DH_PREAMBLE_LEN);
                has_preamble = true;
            }
        }

        RatchetState st;
        bool   used_otp = false;
        bool   bootstrapped_now = false;
        if (!loadPeerRatchet(peerDeviceId, &st)) {
            if (!has_preamble) return QByteArray();  /* can't bootstrap from a bare DR22 */
            BYTE myIkPriv[32], myIkPub[32], peerIkPub[32];
            if (!loadMyX25519Identity(myIkPriv, myIkPub))      return QByteArray();
            if (!fetchPeerX25519(peerDeviceId, peerIkPub))     return QByteArray();
            BYTE myOpkPriv[32]; bool has_opk = false;
            if (peer_otp_id != X3DH_NO_OTP) {
                if (lookupMyOtpPriv(peer_otp_id, myOpkPriv)) {
                    has_opk  = true;
                    used_otp = true;
                }
                /* If we can't find the OTP locally it's either already
                 * been consumed (duplicate delivery) or never published.
                 * Either way, falling back to 2-DH would produce the
                 * wrong SK because Alice used the OPK, so just fail. */
                else { return QByteArray(); }
            }
            BYTE sk[32];
            if (!ratchet_x3dh_bob(myIkPriv, has_opk ? myOpkPriv : nullptr,
                                  peerIkPub, peer_ek_pub, sk)) return QByteArray();
            if (!ratchet_init_bob(&st, sk, myIkPriv, myIkPub)) return QByteArray();
            bootstrapped_now = true;
        }
        /* If state already exists and a preamble came along anyway,
         * silently ignore it — Alice's retry, we're already past it. */

        DWORD plainCap = (DWORD)env.size();
        QByteArray plain(plainCap, Qt::Uninitialized);
        DWORD got = plainCap;
        if (!ratchet_decrypt(&st,
                             reinterpret_cast<const BYTE*>(env.constData()),
                             (DWORD)env.size(),
                             nullptr, 0,
                             reinterpret_cast<BYTE*>(plain.data()), &got)) {
            /* Decrypt failed AFTER we consumed the OTP server-side. The
             * OTP is gone but our local store still has it — leave it
             * there so a retransmit of the same message can still work. */
            return QByteArray();
        }
        plain.resize((int)got);

        /* Persist state BEFORE deleting the OTP so a save failure can't
         * orphan our chain key. */
        bool state_saved = savePeerRatchet(peerDeviceId, &st);
        if (state_saved && bootstrapped_now && used_otp) {
            /* Lock in forward secrecy: shred the OTP priv. After this
             * point a disk compromise can't recover the SK. */
            deleteMyOtp(peer_otp_id);
        }

        /* If this side was Alice and the new ratchet step closed the
         * loop (has_ckr is now true), the X3DH preamble is no longer
         * needed and we can shred the side-file too. */
        if (state_saved && st.has_ckr) {
            deleteX3dhSide(peerDeviceId);
        }
        return plain;
    }

    /* ===============================================================
     *  MESSAGING
     * =============================================================== */
    void sendMessage() {
        QString body = m_msgInput->text().trimmed();
        if (body.isEmpty() || m_selectedRecip.isEmpty() || m_currentIsGroup || m_maintenanceMode) return;
        const QString conv = m_currentConv;

        qint64 ts = QDateTime::currentSecsSinceEpoch();
        QByteArray pl = jsonBody({
            {"body", body}, {"name", m_username}, {"sender", m_deviceId}, {"ts", ts}
        });

        /* Prefer the Double Ratchet path. Falls back to the legacy
         * static-AES envelope if either side hasn't published a ratchet
         * identity yet (e.g. peer is still running v1.5 or earlier). */
        QByteArray ratchetHex = ratchetEncryptForPeer(m_selectedRecip, pl);
        QVariantMap env;
        if (!ratchetHex.isEmpty()) {
            /* Ratchet envelope. Server still requires nonce/sig/sender/ts
             * keys to exist on the JSON — stuff the ratchet wire bytes
             * into "ciphertext" and tag with ratchet:1. The nonce is the
             * 12-byte one already inside the ratchet header; we duplicate
             * it here only to satisfy the server-side schema check. */
            BYTE sig[32];
            QByteArray bin = QByteArray::fromHex(ratchetHex);
            crypto_sha256(reinterpret_cast<const BYTE*>(bin.constData()),
                          (DWORD)bin.size(), sig);
            char *sh = crypto_hex_encode(sig, 32);
            env = QVariantMap{
                {"ratchet", 1},
                {"sender", m_deviceId}, {"ts", ts},
                {"nonce", QString(24, '0')},  /* unused for ratchet path */
                {"ciphertext", QString::fromUtf8(ratchetHex)},
                {"tag", QString(32, '0')},    /* unused for ratchet path */
                {"sig", QString::fromUtf8(sh)},
            };
            free(sh);
        } else {
            /* Legacy AES-GCM path — kept for backwards-compatibility with
             * pre-v1.6 peers. Same code as before. */
            BYTE sk[32];
            if (storage_exists()) {
                DeviceConfig cfg;
                if (storage_load_config(&cfg)) {
                    crypto_sha256(cfg.identity_key.pub.data, cfg.identity_key.pub.len, sk);
                }
            }
            BYTE iv[12], ct[5000], tag[16];
            crypto_random_bytes(iv, 12);
            crypto_aes_gcm_encrypt(sk, (const BYTE*)pl.constData(), pl.size(), iv, ct, tag);
            char *ih = crypto_hex_encode(iv, 12);
            char *ch = crypto_hex_encode(ct, pl.size());
            char *th = crypto_hex_encode(tag, 16);
            BYTE sig[32]; crypto_sha256(ct, pl.size(), sig);
            char *sh = crypto_hex_encode(sig, 32);
            env = QVariantMap{
                {"sender", m_deviceId}, {"ts", ts},
                {"nonce", QString::fromUtf8(ih)}, {"ciphertext", QString::fromUtf8(ch)},
                {"tag", QString::fromUtf8(th)}, {"sig", QString::fromUtf8(sh)}
            };
            free(ih); free(ch); free(th); free(sh);
        }

        QByteArray expHdr;
        if (gDisappearEnabled && gDisappearSeconds > 0) {
            expHdr = QByteArray("X-Expires-In: ") + QByteArray::number(gDisappearSeconds);
        }

        /* Rule 1 + Rule 2: seal the whole legacy envelope inside an
         * anonymous one so the relay sees only opaque bytes and a
         * per-pair routing tag — no sender or recipient device id. Falls
         * back to the identified path only when the peer has published
         * no ratchet bundle. */
        if (m_anonRouting) {
            shroud::RoutingContext ctx;
            if (buildRoutingContext(m_selectedRecip, ctx)) {
                QByteArray inner = jsonBody({{"envelope", env}, {"ts", ts}});
                shroud::AnonClient ac = makeAnonClient();
                bool sent = ac.sendSealed(ctx, (const BYTE *)inner.constData(),
                                          (DWORD)inner.size(),
                                          (gDisappearEnabled && gDisappearSeconds > 0)
                                              ? gDisappearSeconds : 0);
                SecureZeroMemory(&ctx, sizeof(ctx));
                if (sent) {
                    ChatMsg m; m.from = "You"; m.mine = true; m.timed = timerOn();
                    m.html = mdToHtml(body);
                    appendMessage(conv, m);
                    m_msgInput->clear();
                    return;
                }
                /* Sealed send failed (relay down / 5xx). Fall through to
                 * the legacy path rather than silently losing the
                 * message — the user still gets delivery, and the status
                 * bar records that this one was not anonymous. */
                notify("Anonymous delivery failed, so this message was retried on the older, less private path.", 10000);
            }
        }

        QByteArray jb = jsonBody({
            {"sender_device_id", m_deviceId}, {"recipient_device_id", m_selectedRecip},
            {"envelope", envelopeString(env)}
        });
        QByteArray sendResp = httpPost("/api/v1/messages/send", jb, expHdr);
        /* Fast-path: server gates sends behind setting_get("maintenance_mode")
         * and replies 503 {"detail":"maintenance"}. Catch it here so the UI
         * flips red even if the heartbeat poll hasn't fired yet. */
        if (sendResp.contains("\"detail\":\"maintenance\"")) {
            setMaintenanceMode(true);
            notify("Not sent: the relay is in maintenance. Your text is still in the box.");
            return;
        }

        ChatMsg m; m.from = "You"; m.mine = true; m.timed = timerOn();
        m.html = mdToHtml(body);
        m.failed = !sendResp.contains("\"message_id\"");
        appendMessage(conv, m);
        if (m.failed)
            notify(sendResp.isEmpty()
                ? QString("Couldn't reach the relay; the message was not delivered.")
                : QString("The relay didn't accept the message: %1").arg(jsonDetail(sendResp, "unknown error")), 12000);
        m_msgInput->clear();
    }

    /* /messages/send takes the envelope as a JSON *string* (the relay
     * json.loads() it, and Android sends env.toString()). Posting it as
     * a nested object made the relay answer 400 "Invalid message
     * envelope format" to every legacy send, while the UI showed the
     * message as sent. */
    static QString envelopeString(const QVariantMap &env) {
        return QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(env))
                                 .toJson(QJsonDocument::Compact));
    }

    /* Fetch a sender device's public-key blob (hex) and derive the symmetric
       file key as SHA-256(pubkey_blob), matching how the sender encrypted. */
    bool senderFileKey(const QString &senderDeviceId, BYTE key_out[32]) {
        QByteArray r = httpGet(QString("/api/v1/devices/%1/pubkey").arg(senderDeviceId).toUtf8().constData());
        if (r.isEmpty()) return false;
        QString pubHex = QJsonDocument::fromJson(r).object().value("public_key").toString();
        if (pubHex.isEmpty()) return false;
        BYTE pub[PUBLIC_KEY_MAX]; DWORD pubLen = 0;
        if (!crypto_hex_decode(pubHex.toUtf8().constData(), pub, &pubLen)) return false;
        return crypto_sha256(pub, pubLen, key_out);
    }

    QJsonObject decryptEnvelope(const QJsonObject &env, const QString &senderDeviceId) {
        /* Ratchet-flagged envelopes carry the full Double Ratchet wire
         * payload hex-encoded in "ciphertext". The legacy nonce/tag
         * fields are present only to keep the server-side schema check
         * happy and are ignored here. */
        if (env.value("ratchet").toInt() == 1) {
            QByteArray ctHex = env.value("ciphertext").toString().toUtf8();
            QByteArray plain = ratchetDecryptFromPeer(senderDeviceId, ctHex);
            if (plain.isEmpty()) return QJsonObject();
            return QJsonDocument::fromJson(plain).object();
        }

        /* Legacy AES-GCM path — sender-derived static key. */
        BYTE sk[32];
        if (!senderFileKey(senderDeviceId, sk)) return QJsonObject();
        BYTE nonce[12], tag[16];
        DWORD nl = 12, tl = 16;
        crypto_hex_decode(env.value("nonce").toString().toUtf8().constData(), nonce, &nl);
        crypto_hex_decode(env.value("tag").toString().toUtf8().constData(), tag, &tl);
        QByteArray ctHex = env.value("ciphertext").toString().toUtf8();
        DWORD clen = (DWORD)(ctHex.size() / 2);
        if (clen == 0 || clen > 8192) return QJsonObject();
        QVector<BYTE> ct(clen), pt(clen);
        DWORD got = clen;
        if (!crypto_hex_decode(ctHex.constData(), ct.data(), &got)) return QJsonObject();
        if (!crypto_aes_gcm_decrypt(sk, nonce, ct.data(), clen, tag, pt.data())) return QJsonObject();
        return QJsonDocument::fromJson(QByteArray(reinterpret_cast<const char*>(pt.data()), (int)clen)).object();
    }

    QString downloadAndDecryptImage(const QString &fileId, const QString &senderDeviceId,
                                     const QString &originalName) {
        BYTE sk[32];
        if (!senderFileKey(senderDeviceId, sk)) return QString();
        BYTE *enc = nullptr; DWORD elen = 0;
        network_download_file(QString("/api/v1/files/%1").arg(fileId).toUtf8().constData(),
                              m_deviceId.toUtf8().constData(), &enc, &elen);
        if (!enc || elen < 28) { if (enc) free(enc); return QString(); }
        BYTE *plain = nullptr; DWORD plen = 0;
        bool ok = crypto_decrypt_file_data(sk, enc, elen, &plain, &plen);
        free(enc);
        if (!ok || !plain) { if (plain) free(plain); return QString(); }
        QString ext = QFileInfo(originalName).suffix().toLower();
        if (ext.isEmpty()) ext = "png";
        QString localPath = QString("%1/%2.%3").arg(imagesDir(), fileId, ext);
        QFile out(localPath);
        if (out.open(QIODevice::WriteOnly)) {
            out.write(reinterpret_cast<const char*>(plain), plen);
            out.close();
        }
        free(plain);
        return localPath;
    }

    /* Rule 2: poll by per-pair routing tag instead of device id, so the
     * relay never learns which mailbox is ours. Runs alongside the
     * legacy fetch — peers still on the old path keep being delivered. */
    void fetchAnonMessages() {
        if (!m_anonRouting || m_friends.isEmpty()) return;
        BYTE myPriv[32], myPub[32];
        if (!loadAnonIdentity(myPriv, myPub)) return;

        std::vector<std::pair<std::vector<BYTE>, std::vector<BYTE>>> contacts;
        for (const QString &uname : m_friends) {
            QString did = resolveUsernameToDevice(uname);
            if (did.isEmpty()) continue;
            QByteArray peerPub = peerX25519Pub(did);
            if (peerPub.size() != 32) continue;
            BYTE root[32];
            if (!ratchet_x25519_dh(myPriv, (const BYTE *)peerPub.constData(), root)) continue;
            contacts.emplace_back(
                std::vector<BYTE>((const BYTE *)peerPub.constData(),
                                  (const BYTE *)peerPub.constData() + 32),
                std::vector<BYTE>(root, root + 32));
            SecureZeroMemory(root, sizeof(root));
        }
        if (contacts.empty()) { SecureZeroMemory(myPriv, sizeof(myPriv)); return; }

        std::vector<shroud::IncomingAnon> in;
        shroud::AnonClient ac = makeAnonClient();
        ac.fetchMessages(myPriv, myPub, contacts, in);
        SecureZeroMemory(myPriv, sizeof(myPriv));

        for (const auto &msg : in) {
            QJsonObject outer = QJsonDocument::fromJson(
                QByteArray((const char *)msg.plaintext.data(),
                           (int)msg.plaintext.size())).object();
            QJsonObject env = outer.value("envelope").toObject();
            if (env.isEmpty()) continue;
            QString sender = env.value("sender").toString();
            QJsonObject plain = decryptEnvelope(env, sender);
            if (plain.isEmpty()) { reportUndecryptable(); continue; }
            QString senderName = senderLabelFor(plain, sender);
            QString body = plain.value("body").toString();
            if (!body.isEmpty()) {
                ChatMsg cm; cm.from = senderName; cm.html = mdToHtml(body);
                appendMessage(senderName, cm);
            }
        }
    }

    void fetchMessages() {
        if (m_deviceId.isEmpty()) return;
        fetchAnonMessages();
        QByteArray r = httpPost("/api/v1/messages/fetch", jsonBody({{"device_id", m_deviceId}}));
        QJsonObject root = QJsonDocument::fromJson(r).object();
        QJsonArray msgs = root.value("messages").toArray();
        for (const QJsonValue &mv : msgs) {
            QJsonObject m = mv.toObject();
            QString sender = m.value("sender_device_id").toString();
            QJsonObject env = m.value("envelope").toObject();
            QJsonObject plain = decryptEnvelope(env, sender);
            if (plain.isEmpty()) { reportUndecryptable(); continue; }
            QString senderName = senderLabelFor(plain, sender);
            QString body = plain.value("body").toString();
            QString type = plain.value("type").toString();
            QString fileId = plain.value("file_id").toString();
            bool isImage = plain.value("is_image").toBool() || type == "image";
            if (isImage && !fileId.isEmpty()) {
                QString localPath = downloadAndDecryptImage(fileId, sender, plain.value("name").toString());
                if (!localPath.isEmpty()) {
                    insertImageBubble(senderName, fileId, localPath, senderName, false);
                    continue;
                }
            }
            if (!body.isEmpty()) {
                ChatMsg cm; cm.from = senderName; cm.html = mdToHtml(body);
                appendMessage(senderName, cm);
            }
        }
    }

    /* ===============================================================
     *  FILE ATTACH
     * =============================================================== */
    void attachFile(QString path = QString()) {
        if (m_selectedRecip.isEmpty() || m_currentIsGroup || m_maintenanceMode) return;
        const QString conv = m_currentConv;
        if (path.isEmpty())
            path = QFileDialog::getOpenFileName(this, QString("Send a file to %1 (encrypted)").arg(m_currentName),
                QString(), "All files (*.*);;Images (*.png *.jpg *.jpeg *.gif *.bmp *.webp)");
        if (path.isEmpty()) return;

        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) {
            notify(QString("Couldn't open %1: %2").arg(QFileInfo(path).fileName(), f.errorString()));
            return;
        }
        QByteArray data = f.readAll();
        f.close();

        QString fname = QFileInfo(path).fileName();
        bool isImage = isImageFileName(fname);

        BYTE sk[32];
        DeviceConfig cfg;
        if (storage_load_config(&cfg))
            crypto_sha256(cfg.identity_key.pub.data, cfg.identity_key.pub.len, sk);

        BYTE *enc = nullptr; DWORD elen = 0;
        if (!crypto_encrypt_file_data(sk, (const BYTE*)data.constData(), data.size(), &enc, &elen)) {
            notify("Couldn't encrypt that file, so nothing was sent.");
            return;
        }

        QString mime = isImage ? QString("image/") + QFileInfo(path).suffix().toLower() : QString();
        QByteArray meta = jsonBody({
            {"name", fname}, {"size", (qint64)data.size()},
            {"mime", mime}, {"is_image", isImage}
        });

        notify(QString("Encrypting and uploading %1…").arg(fname), 0);
        QApplication::setOverrideCursor(Qt::BusyCursor);
        QApplication::processEvents();

        HttpResponse *ur = network_upload_file("/api/v1/files/upload", enc, elen,
            m_deviceId.toUtf8().constData(), m_selectedRecip.toUtf8().constData(),
            meta.constData());
        free(enc);
        QApplication::restoreOverrideCursor();

        QString fileId;
        if (ur && ur->len > 0) {
            QByteArray ub(ur->data, (int)ur->len);
            fileId = QJsonDocument::fromJson(ub).object().value("file_id").toString();
            network_free_response(ur);
        }
        if (fileId.isEmpty()) {
            notify(QString("Upload of %1 failed. Check your connection and try again.").arg(fname), 12000);
            return;
        }

        /* Cache plaintext locally so the sender can view + the viewer can
           open it from disk later. */
        QString localPath;
        if (isImage) {
            QString ext = QFileInfo(path).suffix().toLower();
            localPath = QString("%1/%2.%3").arg(imagesDir(), fileId, ext);
            QFile out(localPath);
            if (out.open(QIODevice::WriteOnly)) { out.write(data); out.close(); }
        }

        qint64 ts = QDateTime::currentSecsSinceEpoch();
        QByteArray plb = jsonBody({
            {"type", QString(isImage ? "image" : "file")}, {"file_id", fileId},
            {"name", fname}, {"size", (qint64)data.size()},
            {"mime", mime}, {"is_image", isImage},
            {"body", isImage
                ? QString("Sent image: %1").arg(fname)
                : QString("Sent file: %1 (%2 bytes)").arg(fname).arg(data.size())}
        });

        BYTE iv[12], ct[5000], tag[16];
        crypto_random_bytes(iv, 12);
        crypto_aes_gcm_encrypt(sk, (const BYTE*)plb.constData(), plb.size(), iv, ct, tag);
        char *ih = crypto_hex_encode(iv, 12);
        char *ch = crypto_hex_encode(ct, plb.size());
        char *th = crypto_hex_encode(tag, 16);
        BYTE sig[32]; crypto_sha256(ct, plb.size(), sig);
        char *sh = crypto_hex_encode(sig, 32);

        QVariantMap env{
            {"sender", m_deviceId}, {"ts", ts},
            {"nonce", QString::fromUtf8(ih)}, {"ciphertext", QString::fromUtf8(ch)},
            {"tag", QString::fromUtf8(th)}, {"sig", QString::fromUtf8(sh)}
        };
        free(ih); free(ch); free(th); free(sh);

        QByteArray jb = jsonBody({
            {"sender_device_id", m_deviceId}, {"recipient_device_id", m_selectedRecip},
            {"envelope", envelopeString(env)}
        });
        QByteArray expHdr2;
        if (gDisappearEnabled && gDisappearSeconds > 0) {
            expHdr2 = QByteArray("X-Expires-In: ") + QByteArray::number(gDisappearSeconds);
        }
        QByteArray imgResp = httpPost("/api/v1/messages/send", jb, expHdr2);
        if (imgResp.contains("\"detail\":\"maintenance\"")) {
            setMaintenanceMode(true);
            notify("Not sent: the relay is in maintenance.");
            return;
        }
        bool delivered = imgResp.contains("\"message_id\"");

        if (isImage && !localPath.isEmpty() && delivered) {
            insertImageBubble(conv, fileId, localPath, "You", true);
        } else {
            ChatMsg m; m.from = "You"; m.mine = true; m.timed = timerOn(); m.failed = !delivered;
            m.html = QString("📄 <b>%1</b> <span style='color:%2'>(%3)</span>")
                .arg(fname.toHtmlEscaped(), cN(gTheme.dim), QLocale::system().formattedDataSize(data.size()));
            appendMessage(conv, m);
        }
        notify(delivered
            ? QString("%1 sent: %2").arg(isImage ? "Image" : "File", fname)
            : QString("%1 was uploaded but the notice to %2 wasn't delivered: %3")
                  .arg(fname, m_currentName, jsonDetail(imgResp, "no response from the relay")), 12000);
    }

    /* ===============================================================
     *  MULTI-DEVICE LINKING (sealed-Sesame style)
     *
     *  Primary's flow:
     *    1. ratchet_x25519_keygen → (ekP_priv, ekP_pub)
     *    2. POST /devices/link/init {device_id, primary_pubkey_hex=ekP_pub}
     *    3. Server returns link_id. Show "link_id:ekP_pub" as the code.
     *    4. Poll /devices/link/{id} for secondary_pubkey_hex.
     *    5. When it appears: shared = X25519(ekP_priv, ekS_pub).
     *       AES-256-GCM-encrypt {username, contacts:[…]} under
     *       HKDF-SHA512(shared, "SHROUD-DEVLINK-v1"). POST the
     *       12-byte nonce ‖ 16-byte tag ‖ ciphertext to /payload.
     *
     *  Secondary's flow:
     *    1. User pastes link code; parse link_id, ekP_pub.
     *    2. ratchet_x25519_keygen → (ekS_priv, ekS_pub).
     *    3. POST /secondary {secondary_pubkey_hex=ekS_pub}.
     *    4. Poll /payload until it returns 200 with the blob.
     *    5. shared = X25519(ekS_priv, ekP_pub); decrypt; import.
     *
     *  Server only sees ephemeral pubkeys and an opaque blob; the symmetric
     *  key never crosses the wire and the payload is wiped after pickup.
     * =============================================================== */
    QString  m_linkPrimaryId;
    BYTE     m_linkPrimaryPriv[32];
    QTimer  *m_linkPrimaryPoll = nullptr;
    QString  m_linkSecondaryId;
    BYTE     m_linkSecondaryPriv[32];
    BYTE     m_linkSecondaryPeerPub[32];
    QTimer  *m_linkSecondaryPoll = nullptr;

    static QByteArray hkdfDevlink(const BYTE shared[32]) {
        BYTE salt[64] = {0};
        BYTE out[32];
        static const BYTE info[] = "SHROUD-DEVLINK-v1";
        if (!ratchet_hkdf_sha512(salt, 64, shared, 32, info, sizeof(info) - 1, out, 32))
            return QByteArray();
        return QByteArray((const char*)out, 32);
    }

    void linkStartPrimary(QPlainTextEdit *codeOut, QLabel *status) {
        if (m_linkPrimaryPoll) { m_linkPrimaryPoll->stop(); m_linkPrimaryPoll = nullptr; }
        BYTE pub[32];
        if (!ratchet_x25519_keygen(m_linkPrimaryPriv, pub)) {
            status->setText("Could not generate ephemeral key."); return;
        }
        char hexbuf[65] = {0};
        for (int i = 0; i < 32; i++) sprintf(hexbuf + i*2, "%02x", pub[i]);
        QByteArray body = jsonBody({
            {"device_id", m_deviceId},
            {"primary_pubkey_hex", QString::fromUtf8(hexbuf)}
        });
        QByteArray r = httpPost("/api/v1/devices/link/init", body);
        QString linkId = jsonStr(r, "link_id");
        if (linkId.isEmpty()) {
            status->setText("Server rejected the link request.");
            return;
        }
        m_linkPrimaryId = linkId;
        QString code = linkId + ":" + QString::fromUtf8(hexbuf);
        codeOut->setPlainText(code);
        status->setText("Waiting for the other device to enter this code (5 min)…");

        m_linkPrimaryPoll = new QTimer(this);
        m_linkPrimaryPoll->setInterval(2000);
        int *ticks = new int(0);
        connect(m_linkPrimaryPoll, &QTimer::timeout, this, [=]() {
            (*ticks)++;
            if (*ticks > 150) {  /* 5 min @ 2s */
                m_linkPrimaryPoll->stop();
                status->setText("Link code expired. Generate a new one to try again.");
                delete ticks; return;
            }
            QByteArray lr = httpGet(QString("/api/v1/devices/link/%1").arg(m_linkPrimaryId).toUtf8().constData());
            QString secHex = jsonStr(lr, "secondary_pubkey_hex");
            if (secHex.isEmpty() || secHex == "null") return;
            BYTE peer_pub[32];
            for (int i = 0; i < 32; i++) {
                bool ok = false; peer_pub[i] = (BYTE)QStringView(secHex).mid(i*2, 2).toUInt(&ok, 16);
                if (!ok) { status->setText("Other device sent malformed key."); m_linkPrimaryPoll->stop(); delete ticks; return; }
            }
            BYTE shared[32];
            if (!ratchet_x25519_dh(m_linkPrimaryPriv, peer_pub, shared)) {
                status->setText("ECDH failed."); m_linkPrimaryPoll->stop(); delete ticks; return;
            }
            QByteArray key = hkdfDevlink(shared);
            if (key.size() != 32) {
                status->setText("Key derivation failed."); m_linkPrimaryPoll->stop(); delete ticks; return;
            }
            QByteArray friendsResp = httpPost("/api/v1/friends/list", jsonBody({{"device_id", m_deviceId}}));
            QJsonObject bundle{
                {"v", 1},
                {"username", m_username},
                {"primary_device_id", m_deviceId},
                {"friends", QJsonDocument::fromJson(friendsResp).object().value("friends").toArray()},
                {"note", "SHROUD device-link snapshot. Import-only; does not grant credentials."},
            };
            QByteArray plain = QJsonDocument(bundle).toJson(QJsonDocument::Compact);
            BYTE iv[12]; crypto_random_bytes(iv, 12);
            QByteArray ct(plain.size(), 0); BYTE tag[16];
            if (!crypto_aes_gcm_encrypt((const BYTE*)key.constData(),
                                        (const BYTE*)plain.constData(), (DWORD)plain.size(),
                                        iv, (BYTE*)ct.data(), tag)) {
                status->setText("Encrypt failed."); m_linkPrimaryPoll->stop(); delete ticks; return;
            }
            QByteArray blob;
            blob.append((const char*)iv, 12);
            blob.append((const char*)tag, 16);
            blob.append(ct);
            HttpResponse *pr = network_post_bytes(
                QString("/api/v1/devices/link/%1/payload").arg(m_linkPrimaryId).toUtf8().constData(),
                (const BYTE*)blob.constData(), (DWORD)blob.size(), "application/octet-stream");
            if (pr) network_free_response(pr);
            m_linkPrimaryPoll->stop();
            status->setText(QString("Linked. Sent %1-byte encrypted bundle. The other device "
                                    "will pick it up; this code is no longer reusable.").arg(blob.size()));
            delete ticks;
        });
        m_linkPrimaryPoll->start();
    }

    void linkAcceptSecondary(const QString &code, QLabel *status) {
        if (m_linkSecondaryPoll) { m_linkSecondaryPoll->stop(); m_linkSecondaryPoll = nullptr; }
        int sep = code.indexOf(':');
        if (sep < 0 || sep != 32 || code.size() != 32 + 1 + 64) {
            status->setText("That doesn't look like a link code. Expected 32 hex chars, a colon, then 64 hex chars.");
            return;
        }
        QString linkId = code.left(32);
        QString primaryHex = code.mid(33);
        for (int i = 0; i < 32; i++) {
            bool ok = false; m_linkSecondaryPeerPub[i] = (BYTE)QStringView(primaryHex).mid(i*2, 2).toUInt(&ok, 16);
            if (!ok) { status->setText("Malformed primary key in code."); return; }
        }
        BYTE pub[32];
        if (!ratchet_x25519_keygen(m_linkSecondaryPriv, pub)) {
            status->setText("Could not generate ephemeral key."); return;
        }
        char hexbuf[65] = {0};
        for (int i = 0; i < 32; i++) sprintf(hexbuf + i*2, "%02x", pub[i]);
        QByteArray body = jsonBody({{"secondary_pubkey_hex", QString::fromUtf8(hexbuf)}});
        QByteArray r = httpPost(QString("/api/v1/devices/link/%1/secondary").arg(linkId).toUtf8().constData(), body);
        if (!r.contains("\"ok\":true")) {
            status->setText("Server rejected the link code (expired or already consumed)."); return;
        }
        m_linkSecondaryId = linkId;
        status->setText("Waiting for the other device to send the bundle…");

        m_linkSecondaryPoll = new QTimer(this);
        m_linkSecondaryPoll->setInterval(2000);
        int *ticks = new int(0);
        connect(m_linkSecondaryPoll, &QTimer::timeout, this, [=]() {
            (*ticks)++;
            if (*ticks > 150) {
                m_linkSecondaryPoll->stop();
                status->setText("Timed out waiting for the bundle.");
                delete ticks; return;
            }
            BYTE *blob = NULL; DWORD blobLen = 0;
            network_download_file(
                QString("/api/v1/devices/link/%1/payload").arg(m_linkSecondaryId).toUtf8().constData(),
                m_deviceId.toUtf8().constData(), &blob, &blobLen);
            if (!blob || blobLen < 12 + 16 + 1) { if (blob) free(blob); return; }
            BYTE shared[32];
            if (!ratchet_x25519_dh(m_linkSecondaryPriv, m_linkSecondaryPeerPub, shared)) {
                free(blob); status->setText("ECDH failed."); m_linkSecondaryPoll->stop(); delete ticks; return;
            }
            QByteArray key = hkdfDevlink(shared);
            if (key.size() != 32) { free(blob); status->setText("Key derivation failed."); m_linkSecondaryPoll->stop(); delete ticks; return; }
            DWORD ctLen = blobLen - 12 - 16;
            QByteArray plain(ctLen, 0);
            BOOL ok = crypto_aes_gcm_decrypt((const BYTE*)key.constData(),
                                             blob, blob + 12, ctLen, blob + 12 + 16,
                                             (BYTE*)plain.data());
            free(blob);
            if (!ok) { status->setText("Bundle decrypt failed (auth tag mismatch)."); m_linkSecondaryPoll->stop(); delete ticks; return; }
            QJsonObject bundle = QJsonDocument::fromJson(plain).object();
            int imported = bundle.value("friends").toArray().size();
            QString fromUser = bundle.value("username").toString();
            status->setText(QString("Imported %1 contacts from <b>%2</b>'s primary device. "
                                    "Conversation keys stay device-local for forward secrecy.")
                            .arg(imported).arg(fromUser.toHtmlEscaped()));
            m_linkSecondaryPoll->stop();
            delete ticks;
        });
        m_linkSecondaryPoll->start();
    }

    /* ===============================================================
     *  SETTINGS
     * =============================================================== */
    void openSettings(int initialTab = 0) {
        QDialog dlg(this);
        dlg.setWindowTitle("SHROUD Settings");
        dlg.resize(660, 580);
        dlg.setMinimumSize(560, 480);
        auto *lay = new QVBoxLayout(&dlg);
        auto *tabs = new QTabWidget;

        /* ──────────── Appearance tab ──────────── */
        auto *ap = new QWidget; auto *al = new QVBoxLayout(ap);

        auto *themeRow = new QHBoxLayout;
        themeRow->addWidget(new QLabel("Theme:"));
        auto *themeCombo = new QComboBox;
        for (const Theme &t : THEME_PRESETS) themeCombo->addItem(t.name);
        themeCombo->addItem("Custom");
        int cur = themeCombo->findText(gTheme.name);
        if (cur < 0) cur = themeCombo->findText("Custom");
        themeCombo->setCurrentIndex(cur);
        themeRow->addWidget(themeCombo, 1);
        al->addLayout(themeRow);

        /* Live swatch row */
        auto *swatchBox = new QGroupBox("Palette");
        auto *swatchGrid = new QGridLayout(swatchBox);
        struct Slot { QString label; QString field; };
        QList<Slot> swatchSlots = {
            {"Background", "bg"}, {"Surface", "surface"}, {"Input", "input"},
            {"Border", "border"}, {"Text", "text"}, {"Dim text", "dim"},
            {"Accent", "accent"}, {"Link", "link"}, {"Danger", "danger"},
        };
        QHash<QString, QPushButton*> swatchBtns;
        for (int i = 0; i < swatchSlots.size(); i++) {
            const Slot &s = swatchSlots[i];
            auto *btn = new QPushButton; btn->setFixedSize(110, 28);
            swatchBtns[s.field] = btn;
            swatchGrid->addWidget(new QLabel(s.label), i / 3, (i % 3) * 2);
            swatchGrid->addWidget(btn, i / 3, (i % 3) * 2 + 1);
        }
        al->addWidget(swatchBox);

        auto refreshSwatches = [swatchBtns]() {
            auto setSwatch = [&](const QString &k, const QColor &c) {
                QPushButton *b = swatchBtns[k];
                b->setText(c.name(QColor::HexRgb));
                b->setStyleSheet(QString("QPushButton { background-color: %1; color: %2; border: 1px solid #555; }")
                    .arg(c.name(QColor::HexRgb),
                         (c.red()*299 + c.green()*587 + c.blue()*114) / 1000 > 160 ? "#1a1a1a" : "#ffffff"));
            };
            setSwatch("bg", gTheme.bg); setSwatch("surface", gTheme.surface);
            setSwatch("input", gTheme.input); setSwatch("border", gTheme.border);
            setSwatch("text", gTheme.text); setSwatch("dim", gTheme.dim);
            setSwatch("accent", gTheme.accent); setSwatch("link", gTheme.link);
            setSwatch("danger", gTheme.danger);
        };
        refreshSwatches();

        auto applyTheme = [refreshSwatches]() {
            qApp->setStyleSheet(themeQSS(gTheme));
            refreshSwatches();
        };

        connect(themeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            [=](int idx) {
                QString name = themeCombo->itemText(idx);
                if (name == "Custom") {
                    /* keep current colors; user edits via swatch buttons */
                    gTheme.name = "Custom";
                } else if (idx >= 0 && idx < THEME_PRESETS.size()) {
                    gTheme = THEME_PRESETS[idx];
                }
                applyTheme();
            });

        auto openColor = [this, &dlg, themeCombo, applyTheme](QColor *target) {
            QColor c = QColorDialog::getColor(*target, &dlg, "Pick a color",
                QColorDialog::ShowAlphaChannel);
            if (c.isValid()) {
                *target = c;
                /* Switch into Custom mode the moment any color is hand-picked. */
                if (gTheme.name != "Custom") {
                    gTheme.name = "Custom";
                    int idx = themeCombo->findText("Custom");
                    if (idx >= 0) {
                        QSignalBlocker block(themeCombo);
                        themeCombo->setCurrentIndex(idx);
                    }
                }
                applyTheme();
            }
        };
        connect(swatchBtns["bg"],      &QPushButton::clicked, [=]() { openColor(&gTheme.bg); });
        connect(swatchBtns["surface"], &QPushButton::clicked, [=]() { openColor(&gTheme.surface); });
        connect(swatchBtns["input"],   &QPushButton::clicked, [=]() { openColor(&gTheme.input); });
        connect(swatchBtns["border"],  &QPushButton::clicked, [=]() { openColor(&gTheme.border); });
        connect(swatchBtns["text"],    &QPushButton::clicked, [=]() { openColor(&gTheme.text); });
        connect(swatchBtns["dim"],     &QPushButton::clicked, [=]() { openColor(&gTheme.dim); });
        connect(swatchBtns["accent"],  &QPushButton::clicked, [=]() { openColor(&gTheme.accent); });
        connect(swatchBtns["link"],    &QPushButton::clicked, [=]() { openColor(&gTheme.link); });
        connect(swatchBtns["danger"],  &QPushButton::clicked, [=]() { openColor(&gTheme.danger); });

        auto *resetRow = new QHBoxLayout;
        auto *resetBtn = new QPushButton("Reset to default");
        connect(resetBtn, &QPushButton::clicked, [=]() {
            gTheme = THEME_PRESETS[0];
            QSignalBlocker block(themeCombo);
            themeCombo->setCurrentIndex(0);
            applyTheme();
        });
        resetRow->addStretch(); resetRow->addWidget(resetBtn);
        al->addLayout(resetRow);
        al->addStretch();
        tabs->addTab(ap, "Appearance");

        /* ──────────── Messages tab ──────────── */
        auto *ms = new QWidget; auto *mlv = new QVBoxLayout(ms);

        auto *disBox = new QGroupBox("Disappearing messages");
        auto *disLayout = new QVBoxLayout(disBox);
        auto *disChk = new QCheckBox("Delete the messages I send after a set time");
        disChk->setChecked(gDisappearEnabled);
        disLayout->addWidget(disChk);
        auto *timerRow = new QHBoxLayout;
        auto *minSpin = new QSpinBox; minSpin->setRange(0, 1440); minSpin->setSuffix(" min");
        auto *secSpin = new QSpinBox; secSpin->setRange(0, 59);   secSpin->setSuffix(" sec");
        minSpin->setValue(gDisappearSeconds / 60);
        secSpin->setValue(gDisappearSeconds % 60);
        minSpin->setEnabled(gDisappearEnabled);
        secSpin->setEnabled(gDisappearEnabled);
        timerRow->addWidget(new QLabel("After:"));
        timerRow->addWidget(minSpin);
        timerRow->addWidget(secSpin);
        timerRow->addStretch();
        disLayout->addLayout(timerRow);
        connect(disChk, &QCheckBox::toggled, [=](bool c) {
            gDisappearEnabled = c;
            minSpin->setEnabled(c); secSpin->setEnabled(c);
        });
        auto syncSecs = [=]() {
            gDisappearSeconds = minSpin->value() * 60 + secSpin->value();
            if (gDisappearSeconds <= 0) gDisappearSeconds = 30;
        };
        connect(minSpin, QOverload<int>::of(&QSpinBox::valueChanged), syncSecs);
        connect(secSpin, QOverload<int>::of(&QSpinBox::valueChanged), syncSecs);
        mlv->addWidget(disBox);

        auto *rtBox = new QGroupBox("Composition");
        auto *rtL = new QVBoxLayout(rtBox);
        auto *rtChk = new QCheckBox("Render Markdown (**bold**, *italic*, `code`, links) in received messages");
        rtChk->setChecked(gRichText);
        connect(rtChk, &QCheckBox::toggled, [](bool c) { gRichText = c; });
        rtL->addWidget(rtChk);
        auto *emojiTip = new QLabel("Tip: press Win + . to open the Windows emoji panel while typing.");
        emojiTip->setObjectName("hint");
        rtL->addWidget(emojiTip);
        auto *emojiBtn = new QPushButton("Open emoji panel now");
        connect(emojiBtn, &QPushButton::clicked, [this]() {
            INPUT in[4] = {};
            in[0].type = INPUT_KEYBOARD; in[0].ki.wVk = VK_LWIN;
            in[1].type = INPUT_KEYBOARD; in[1].ki.wVk = VK_OEM_PERIOD;
            in[2].type = INPUT_KEYBOARD; in[2].ki.wVk = VK_OEM_PERIOD; in[2].ki.dwFlags = KEYEVENTF_KEYUP;
            in[3].type = INPUT_KEYBOARD; in[3].ki.wVk = VK_LWIN;       in[3].ki.dwFlags = KEYEVENTF_KEYUP;
            SendInput(4, in, sizeof(INPUT));
        });
        rtL->addWidget(emojiBtn);
        mlv->addWidget(rtBox);

        auto *ntBox = new QGroupBox("Notifications");
        auto *ntL = new QVBoxLayout(ntBox);
        auto *flashChk = new QCheckBox("Flash the taskbar button when a message arrives");
        flashChk->setChecked(gFlashOnMessage);
        connect(flashChk, &QCheckBox::toggled, [](bool c) { gFlashOnMessage = c; });
        ntL->addWidget(flashChk);
        auto *ntNote = new QLabel("SHROUD never shows message text in Windows notifications, "
                                  "so nothing leaks onto the lock screen or into Action Center.");
        ntNote->setObjectName("hint");
        ntNote->setWordWrap(true);
        ntL->addWidget(ntNote);
        mlv->addWidget(ntBox);
        mlv->addStretch();
        tabs->addTab(ms, "Messages");

        /* ──────────── Network (transport) tab ────────────
         * Mutually-exclusive radio group: Direct / Tor.
         *
         * SHROUD's anonymity story is the *protocol*: end-to-end Double
         * Ratchet encryption (server never sees plaintext), padded envelopes
         * (server can't fingerprint by size), RSA-3072 blind-signature
         * anonymous credentials (server rate-limits without tying actions to
         * an identity), and no PII collection (a username is the only handle
         * and the user picks it). This tab only covers the *network layer* —
         * specifically, the IP↔username linkability that TLS-over-clearnet
         * still leaves on the wire. Tor closes that one gap; everything else
         * is already done at the protocol level whether Tor is on or off. */
        auto *nw = new QWidget; auto *nlv = new QVBoxLayout(nw);

        auto *tBox = new QGroupBox("Transport");
        auto *tLay = new QVBoxLayout(tBox);
        auto *rbDirect = new QRadioButton("Direct (clearnet)");
        auto *rbTor    = new QRadioButton("Tor (SOCKS5 → local tor daemon)");
        rbDirect->setChecked(gTransport == Transport::Direct);
        rbTor->setChecked(gTransport == Transport::Tor);
        auto *bg = new QButtonGroup(tBox);
        bg->addButton(rbDirect, (int)Transport::Direct);
        bg->addButton(rbTor,    (int)Transport::Tor);
        tLay->addWidget(rbDirect);
        tLay->addWidget(rbTor);
        nlv->addWidget(tBox);

        auto *torBox = new QGroupBox("Tor settings");
        auto *torLay = new QVBoxLayout(torBox);
        auto *torRow = new QHBoxLayout;
        torRow->addWidget(new QLabel("SOCKS5 endpoint:"));
        auto *torEdit = new QLineEdit(gTorProxy);
        torEdit->setPlaceholderText("127.0.0.1:9050");
        torRow->addWidget(torEdit, 1);
        torLay->addLayout(torRow);
        auto *torNote = new QLabel(
            "<b>127.0.0.1:9050</b> for stock tor / tor-expert-bundle, "
            "<b>127.0.0.1:9150</b> for Tor Browser. Fails closed — if tor "
            "isn't running, requests error out, never fall back to clearnet. "
            "See <code>docs/tor.md</code> for the server-side hidden-service config."
        );
        torNote->setWordWrap(true);
        torNote->setTextFormat(Qt::RichText);
        torLay->addWidget(torNote);
        nlv->addWidget(torBox);

        nlv->addStretch();

        auto syncTransport = [=]() {
            int id = bg->checkedId();
            if (id == (int)Transport::Tor) gTransport = Transport::Tor;
            else                            gTransport = Transport::Direct;
            QString tp = torEdit->text().trimmed(); if (!tp.isEmpty()) gTorProxy = tp;
            applyTransport();
        };
        connect(bg, &QButtonGroup::idClicked, syncTransport);
        connect(torEdit, &QLineEdit::editingFinished, syncTransport);
        tabs->addTab(nw, "Network");

        /* ──────────── Devices (multi-device linking) tab ──────────── */
        auto *dv = new QWidget; auto *dvL = new QVBoxLayout(dv);
        auto *linkBox = new QGroupBox("Link another device to this account");
        auto *linkLay = new QVBoxLayout(linkBox);
        linkLay->addWidget(new QLabel(
            "Use this from the device that's already logged in. Generate a code, "
            "then enter it on the new device. The exchange is end-to-end "
            "encrypted via ephemeral X25519 — the server only sees opaque "
            "ciphertext and forgets it once the new device picks it up. "
            "5-minute TTL."));
        auto *genBtn  = new QPushButton("Generate link code");
        linkLay->addWidget(genBtn);
        auto *codeOut = new QPlainTextEdit;
        codeOut->setReadOnly(true);
        codeOut->setMaximumHeight(70);
        codeOut->setPlaceholderText("Click \"Generate link code\" to start.");
        linkLay->addWidget(codeOut);
        auto *linkStatus = new QLabel("");
        linkStatus->setWordWrap(true);
        linkLay->addWidget(linkStatus);
        dvL->addWidget(linkBox);

        auto *acceptBox = new QGroupBox("Accept a link code from another device");
        auto *acceptLay = new QVBoxLayout(acceptBox);
        acceptLay->addWidget(new QLabel(
            "Use this on the new device. Paste the code from the existing "
            "device — the contact list and friend graph get imported "
            "automatically. Conversation keys stay local to each device for "
            "forward secrecy."));
        auto *codeIn = new QLineEdit;
        codeIn->setPlaceholderText("Paste link code here");
        acceptLay->addWidget(codeIn);
        auto *acceptBtn = new QPushButton("Accept code");
        acceptLay->addWidget(acceptBtn);
        auto *acceptStatus = new QLabel("");
        acceptStatus->setWordWrap(true);
        acceptLay->addWidget(acceptStatus);
        dvL->addWidget(acceptBox);
        dvL->addStretch();

        connect(genBtn,    &QPushButton::clicked, [=]() { linkStartPrimary(codeOut, linkStatus); });
        connect(acceptBtn, &QPushButton::clicked, [=]() { linkAcceptSecondary(codeIn->text().trimmed(), acceptStatus); });
        tabs->addTab(dv, "Devices");

        /* ──────────── Password tab ──────────── */
        auto *pw = new QWidget; auto *pl = new QVBoxLayout(pw);
        auto *pwIntro = new QLabel("Change the password for <b>" + m_username.toHtmlEscaped() + "</b>. "
                                   "Your other devices will need the new password next time they sign in.");
        pwIntro->setWordWrap(true);
        pl->addWidget(pwIntro);
        auto *oldPw = new QLineEdit; oldPw->setEchoMode(QLineEdit::Password); oldPw->setPlaceholderText("Current password");
        auto *newPw = new QLineEdit; newPw->setEchoMode(QLineEdit::Password); newPw->setPlaceholderText("New password (12+ chars)");
        auto *cfmPw = new QLineEdit; cfmPw->setEchoMode(QLineEdit::Password); cfmPw->setPlaceholderText("Confirm new password");
        attachPasswordReveal(oldPw); attachPasswordReveal(newPw); attachPasswordReveal(cfmPw);
        pl->addWidget(oldPw); pl->addWidget(newPw); pl->addWidget(cfmPw);
        auto *chBtn = new QPushButton("Change password");
        chBtn->setObjectName("primary");
        connect(chBtn, &QPushButton::clicked, [=, &dlg]() {
            if (newPw->text().length() < 12) {
                QMessageBox::warning(&dlg, "Change password", "The new password needs at least 12 characters."); return;
            }
            if (newPw->text() != cfmPw->text()) {
                QMessageBox::warning(&dlg, "Change password", "The new password and its confirmation don't match."); return;
            }
            QByteArray b = jsonBody({
                {"username", m_username},
                {"old_password", oldPw->text()},
                {"new_password", newPw->text()}
            });
            QByteArray r = httpPost("/api/v1/change-password", b);
            if (r.contains("\"changed\":true")) {
                oldPw->clear(); newPw->clear(); cfmPw->clear();
                QMessageBox::information(&dlg, "Change password", "Your password has been changed.");
            } else {
                QMessageBox::warning(&dlg, "Change password", r.isEmpty()
                    ? QString("Couldn't reach the relay. Your password was not changed.")
                    : QString("Your password was not changed: %1").arg(jsonDetail(r, "the relay refused the request.")));
            }
        });
        pl->addWidget(chBtn); pl->addStretch();
        tabs->addTab(pw, "Password");

        /* ──────────── Help tab ──────────── */
        auto *hp = new QWidget; auto *hl = new QVBoxLayout(hp);
        auto *help = new QTextBrowser;
        help->setOpenExternalLinks(true);
        QString lk = cN(gTheme.link);
        help->setHtml(QString(R"HTMLDOC(
<h2 style='color:%1'>SHROUD — Quick Reference</h2>

<h3 style='color:%1'>How conversations work</h3>
<p>Every message you send is encrypted on your device <b>before</b> it ever
touches the server. SHROUD uses post-quantum hybrid handshakes
(ECDH&nbsp;P-384 &nbsp;+&nbsp; ML-KEM-1024) when liboqs.dll is available, and
falls back to classical ECDH otherwise. Sealed-sender, disappearing
messages, and rotating pickup tokens hide message metadata from the
server as well.</p>

<h3 style='color:%1'>Verifying you're talking to the right person</h3>
<ul>
<li>Open a conversation and click <b>🛡 Verify</b> in its header (or
right-click the contact → <i>Verify safety number…</i>). A 30-digit
number appears. Read it out to your contact in
person, on a phone call, or any trusted channel. Same number on both
sides → no man-in-the-middle. Different number → do not trust the
conversation, and rotate the server's identity if you administer it.</li>
<li>The server itself is pinned by fingerprint the first time you log
in. If the server's fingerprint changes you'll see a critical alert and
the client will refuse to authenticate.</li>
</ul>

<h3 style='color:%1'>Disappearing messages</h3>
<p>Click the <b>⏱</b> timer in a conversation's header and pick how long
the messages you send should live, or set a custom time in
<b>Settings → Messages</b>. Outgoing messages carry an <code>X-Expires-In</code>
header; the server's background sweep deletes them after the timer.
Default is OFF. Setting the timer to zero disables the feature even if
the checkbox stays on.</p>

<h3 style='color:%1'>Emoji + rich text</h3>
<p>Use <b>Win + .</b> (period) to open Windows' emoji panel while
typing. With <i>Render Markdown</i> enabled, received messages support
<code>**bold**</code>, <code>*italic*</code>, <code>`code`</code>, and
clickable links.</p>

<h3 style='color:%1'>Theme</h3>
<p><b>Settings → Appearance</b>. Pick from twelve presets including
SHROUD&nbsp;Dark, Solarized, Nord, Dracula, Monokai, One Dark, Tokyo
Night, Gruvbox, Cobalt, and High Contrast. Click any swatch to override
a single color — the theme switches to <i>Custom</i> automatically and
remembers your edits.</p>

<h3 style='color:%1'>Linking a second device</h3>
<p>The flow uses an ephemeral X25519 handshake with the server acting
only as a relay. The new device shows a short code; the existing device
scans/types it; both derive a shared key and the existing device
uploads its identity bundle encrypted to that shared key. 5-minute TTL;
the payload is auto-purged after pickup.</p>

<h3 style='color:%1'>Panic + self-destruct</h3>
<p>Five wrong-password proofs against your account in a row will trigger
the server-side cascade wipe: devices, messages, files, prekeys,
friend graph. There is no recovery. If you suspect coercion, you can
also call the panic endpoint manually — the server returns a generic
200 either way so a coercer can't tell whether it succeeded.</p>

<h3 style='color:%1'>Files &amp; images</h3>
<p>Drag a file onto the window, or click the 📎 paperclip. Encrypted client-side with AES-256-GCM, the
key derived from the sender's public-key blob so the recipient can
decrypt without any extra handshake. Images appear inline; click for
full-screen view. Either sender or recipient can delete an image — the
delete cascades to the server.</p>

<h3 style='color:%1'>Troubleshooting</h3>
<ul>
<li><b>Key exchange failed</b> — server is unreachable. Check that the
server is running and reachable on port 58443.</li>
<li><b>Key derivation failed</b> — fixed in v2.0.0+. Update the client.</li>
<li><b>Server identity changed</b> — either the operator rotated the
identity (verify out of band) or you're being MITM'd. Delete that relay's
pin file in <code>%APPDATA%\SHROUD\SHROUD\pins\</code> and try again only if
you've confirmed the rotation is legitimate.</li>
<li><b>Server is in onion-only mode</b> — the operator restricted
connections to Tor hidden services. Connect via the .onion address.</li>
</ul>

<h3 style='color:%1'>More</h3>
<p>Source &amp; releases: <a href='https://github.com/ExposingTheBadge/Shroud'>github.com/ExposingTheBadge/Shroud</a></p>
)HTMLDOC").arg(lk));
        hl->addWidget(help);
        tabs->addTab(hp, "Help");

        /* ──────────── Danger tab ──────────── */
        auto *dz = new QWidget; auto *dlay = new QVBoxLayout(dz);
        auto *dzInfo = new QLabel(
            "<b>Erase SHROUD from this PC.</b><br><br>"
            "This deletes your keys, settings and SHROUD's data on this computer, then "
            "closes the app. Nothing it deletes can be recovered. Use it if you think "
            "this device is about to be taken or inspected.");
        dzInfo->setWordWrap(true);
        dlay->addWidget(dzInfo);
        auto *nukeBtn = new QPushButton("Erase everything on this PC");
        nukeBtn->setObjectName("danger");
        connect(nukeBtn, &QPushButton::clicked, [&dlg]() {
            if (QMessageBox::warning(&dlg, "Erase everything?",
                "Delete ALL SHROUD data on this PC and close the app?\n\nThis cannot be undone.",
                QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel) == QMessageBox::Yes) {
                storage_delete_all();
                QApplication::quit();
            }
        });
        dlay->addWidget(nukeBtn); dlay->addStretch();
        tabs->addTab(dz, "Danger");

        lay->addWidget(tabs);
        tabs->setCurrentIndex(qBound(0, initialTab, tabs->count() - 1));
        auto *closeRow = new QHBoxLayout;
        auto *saveNote = new QLabel("Changes apply immediately.");
        saveNote->setObjectName("hint");
        auto *closeBtn = new QPushButton("Done");
        closeBtn->setObjectName("primary");
        closeBtn->setDefault(true);
        connect(closeBtn, &QPushButton::clicked, [&dlg]() { saveUserPrefs(); dlg.accept(); });
        closeRow->addWidget(saveNote);
        closeRow->addStretch();
        closeRow->addWidget(closeBtn);
        lay->addLayout(closeRow);
        dlg.exec();
        saveUserPrefs();   /* save again even if window is X'd */
        /* Theme and timer changes bake into rendered content. */
        if (m_chatLog) {
            onThemeChanged();
            updateChatHeader();
        }
    }
};

/* ===================================================================
 *  CryptoSplash — animated boot splash. Lattice-themed to mirror the
 *  app icon. Drawn entirely with QPainter, no external assets.
 * =================================================================== */
class CryptoSplash : public QWidget {
    Q_OBJECT
public:
    explicit CryptoSplash(int holdMs = 2000)
        : QWidget(nullptr, Qt::SplashScreen | Qt::FramelessWindowHint)
        , m_holdMs(holdMs)
    {
        setAttribute(Qt::WA_TranslucentBackground);
        setFixedSize(600, 380);
        QScreen *scr = QGuiApplication::primaryScreen();
        if (scr) {
            QRect g = scr->availableGeometry();
            move(g.center() - rect().center());
        }
        m_phases = {
            "Initializing CNG provider",
            "Generating ECDH P-384 keypair",
            "Loading ML-KEM-1024 lattice",
            "Detecting TPM 2.0 module",
            "Running FIPS 140-2 self-test",
            "Establishing secure channel",
        };
        m_anim = new QTimer(this);
        connect(m_anim, &QTimer::timeout, this, [this]() {
            m_tick++;
            int pct = (int)(100.0 * m_tick / qMax(1, m_holdMs / 33));
            m_progress = qMin(100, pct);
            int idx = qMin((int)m_phases.size() - 1,
                           (int)(m_progress * m_phases.size() / 100));
            m_phaseIdx = idx;
            update();
        });
        m_anim->start(33);
    }

    int holdMs() const { return m_holdMs; }

protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const QRectF r = rect();
        const qreal radius = 16.0;

        /* ── Background card ────────────────────────────────────── */
        QLinearGradient bg(r.topLeft(), r.bottomLeft());
        bg.setColorAt(0.0, QColor(8, 14, 28));
        bg.setColorAt(1.0, QColor(16, 26, 48));
        QPainterPath card;
        card.addRoundedRect(r.adjusted(1, 1, -1, -1), radius, radius);
        p.fillPath(card, bg);

        /* ── Hex lattice background ─────────────────────────────── */
        p.save();
        p.setClipPath(card);
        QPen latPen(QColor(255, 140, 30, 40));
        latPen.setWidthF(1.0);
        p.setPen(latPen);
        const qreal hr = 18.0;
        const qreal hx = hr * 1.5;
        const qreal hy = hr * std::sqrt(3.0);
        qreal drift = (m_tick * 0.4);
        for (qreal y = -hy; y < r.height() + hy; y += hy) {
            for (qreal x = -hx; x < r.width() + hx; x += hx) {
                qreal cx = x + std::fmod(drift, hx);
                qreal cy = y + ((int)((x - drift) / hx) % 2 ? hy * 0.5 : 0);
                drawHex(p, cx, cy, hr, 0);
            }
        }
        p.restore();

        /* ── Central crypto core: layered hex cluster ───────────── */
        const QPointF center(r.width() * 0.28, r.height() * 0.5);
        const qreal R = 44.0;
        const qreal spacing = R * std::sqrt(3.0) * 1.0;

        /* Lines from outer hexes to center, animated phase pulse */
        QPen linePen(QColor(255, 160, 50,
                            120 + (int)(60 * std::sin(m_tick * 0.08))));
        linePen.setWidthF(1.5);
        p.setPen(linePen);
        for (int i = 0; i < 6; i++) {
            qreal a = qDegreesToRadians(60.0 * i - 30.0);
            QPointF o(center.x() + spacing * std::cos(a),
                      center.y() + spacing * std::sin(a));
            p.drawLine(center, o);
        }

        /* Outer six hexes — rotate slowly */
        qreal rot = m_tick * 0.5;
        for (int i = 0; i < 6; i++) {
            qreal a = qDegreesToRadians(60.0 * i - 30.0 + rot);
            QPointF o(center.x() + spacing * std::cos(a),
                      center.y() + spacing * std::sin(a));
            QPen op(QColor(255, 160, 50, 220));
            op.setWidthF(2.0);
            p.setPen(op);
            p.setBrush(Qt::NoBrush);
            drawHex(p, o.x(), o.y(), R * 0.42, 30);
            p.setBrush(QColor(255, 180, 70, 230));
            p.setPen(Qt::NoPen);
            p.drawEllipse(o, 4.0, 4.0);
        }

        /* Central hex — bright core with mint key glyph */
        QColor coreBorder = QColor(255, 140, 30);
        QPen cp(coreBorder);
        cp.setWidthF(3.0);
        p.setPen(cp);
        p.setBrush(QColor(40, 20, 8, 230));
        drawHex(p, center.x(), center.y(), R, 30);

        qreal inner = R * 0.42;
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(255, 210, 100));
        p.drawRect(QRectF(center.x() - inner * 0.5, center.y() - inner * 0.5,
                          inner, inner));
        p.drawRect(QRectF(center.x() + inner * 0.5 - inner * 0.12,
                          center.y() - inner * 0.15,
                          inner * 0.30, inner * 0.30));

        /* Pulsing glow ring around the core */
        qreal pulse = 0.5 + 0.5 * std::sin(m_tick * 0.10);
        QPen glowP(QColor(255, 140, 30, (int)(60 + pulse * 80)));
        glowP.setWidthF(2.0 + pulse * 2.0);
        p.setPen(glowP);
        p.setBrush(Qt::NoBrush);
        p.drawEllipse(center, R + 18 + pulse * 6, R + 18 + pulse * 6);

        /* ── Title block (right side) ───────────────────────────── */
        const qreal textX = r.width() * 0.5;
        const qreal textW = r.width() - textX - 32;

        QFont titleFont("Segoe UI", 28, QFont::Black);
        titleFont.setLetterSpacing(QFont::AbsoluteSpacing, 6.0);
        p.setFont(titleFont);
        p.setPen(QColor(255, 170, 60));
        p.drawText(QRectF(textX, 96, textW, 44),
                   Qt::AlignLeft | Qt::AlignVCenter, "SHROUD");

        /* Underline accent */
        p.setPen(QPen(QColor(255, 140, 30, 230), 2.0));
        p.drawLine(QPointF(textX, 148), QPointF(textX + 180, 148));

        /* Crypto specs */
        QFont specFont("Consolas", 9);
        p.setFont(specFont);
        p.setPen(QColor(230, 165, 80));
        p.drawText(QRectF(textX, 158, textW, 18),
                   Qt::AlignLeft | Qt::AlignVCenter,
                   "AES-256-GCM  ·  ECDH P-384  ·  ML-KEM-1024");
        p.setPen(QColor(180, 120, 55));
        p.drawText(QRectF(textX, 174, textW, 16),
                   Qt::AlignLeft | Qt::AlignVCenter,
                   "FIPS 140-2  ·  TPM 2.0  ·  Zero metadata");

        /* ── Progress bar ───────────────────────────────────────── */
        const qreal barY = r.height() - 70;
        const qreal barH = 4;
        QRectF barBg(textX, barY, textW, barH);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(50, 30, 14));
        p.drawRoundedRect(barBg, 2, 2);
        QRectF barFill(textX, barY, textW * m_progress / 100.0, barH);
        QLinearGradient barG(barFill.topLeft(), barFill.topRight());
        barG.setColorAt(0.0, QColor(255, 110, 20));
        barG.setColorAt(1.0, QColor(255, 200, 80));
        p.setBrush(barG);
        p.drawRoundedRect(barFill, 2, 2);

        /* Phase label */
        QFont phaseFont("Consolas", 9);
        p.setFont(phaseFont);
        p.setPen(QColor(255, 160, 40));
        QString tag = QString("[%1]").arg(m_progress, 3, 10, QChar('0'));
        p.drawText(QRectF(textX, barY + 12, 50, 18),
                   Qt::AlignLeft | Qt::AlignVCenter, tag);
        p.setPen(QColor(245, 200, 130));
        QString phase = m_phases.value(m_phaseIdx) + "...";
        p.drawText(QRectF(textX + 50, barY + 12, textW - 50, 18),
                   Qt::AlignLeft | Qt::AlignVCenter, phase);

        /* Version watermark */
        QFont vFont("Consolas", 8);
        p.setFont(vFont);
        p.setPen(QColor(140, 95, 50));
        p.drawText(QRectF(r.width() - 80, r.height() - 22, 70, 16),
                   Qt::AlignRight | Qt::AlignVCenter,
                   QString("v") + CLIENT_VERSION);

        /* ── Outer border highlight ─────────────────────────────── */
        p.setPen(QPen(QColor(255, 140, 30, 180), 1.5));
        p.setBrush(Qt::NoBrush);
        p.drawRoundedRect(r.adjusted(1, 1, -1, -1), radius, radius);
    }

private:
    static void drawHex(QPainter &p, qreal cx, qreal cy, qreal radius, qreal rotDeg) {
        QPolygonF poly;
        for (int i = 0; i < 6; i++) {
            qreal a = qDegreesToRadians(60.0 * i + rotDeg);
            poly << QPointF(cx + radius * std::cos(a), cy + radius * std::sin(a));
        }
        p.drawPolygon(poly);
    }

    QTimer *m_anim;
    int m_tick = 0;
    int m_progress = 0;
    int m_phaseIdx = 0;
    int m_holdMs;
    QStringList m_phases;
};

#include "main.moc"

/* Operator diagnostics X25519 pubkey (32 bytes).
 * Live operator key. Anonymous error reports sealed with this pubkey
 * land in the operator's diagnostics inbox; only the operator's
 * private key (held offline, never on a relay) can decrypt them.
 * To rotate: regenerate via `python -m tools.diagnostics_inbox keygen`,
 * replace the bytes here AND in MainActivity.kt + ShroudApp.swift,
 * ship a new release, retire the old key file.
 *
 * Pubkey hex:
 *   7191a786437e38ebe616b9508b3110afb1a635e08ac034a330093acca708fd54 */
static const BYTE g_operator_diag_pubkey[32] = {
    0x71, 0x91, 0xa7, 0x86, 0x43, 0x7e, 0x38, 0xeb,
    0xe6, 0x16, 0xb9, 0x50, 0x8b, 0x31, 0x10, 0xaf,
    0xb1, 0xa6, 0x35, 0xe0, 0x8a, 0xc0, 0x34, 0xa3,
    0x30, 0x09, 0x3a, 0xcc, 0xa7, 0x08, 0xfd, 0x54
};

/* SHA-256 pin of the operator's manifest-signing Ed25519 pubkey.
 * Clients fetch the signed manifest on first launch, verify its
 * Ed25519 signature with the published pubkey, and require
 * SHA-256(pubkey) == this pin before accepting any field
 * (relay URL, diag pubkey, federation roster, sticker CDN).
 * Rotation requires shipping a release with a new pin. */
static const char g_manifest_pin[] =
    "2fb11de360a0cf6baa35d6785c3945658ae6d64823041729798a2b689ce00ca0";

/* Default-on Tor preference. The operator manifest (v2+) also
 * publishes prefer_tor_by_default = true. Clients honor it unless
 * the user explicitly disables Tor in Settings. Windows pipes traffic
 * through a local SOCKS5 proxy (127.0.0.1:9050) when reachable; if Tor
 * isn't running the client falls back to the clearnet endpoint. */
static const bool g_prefer_tor_default = true;

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("SHROUD");
    app.setApplicationVersion(CLIENT_VERSION);
    app.setWindowIcon(QIcon(":/shroud.png"));

    /* Install the anonymous crash reporter as early as possible so SEH
     * faults during window construction get captured. The pubkey is
     * checked for non-zero inside install(); zero pubkey means the
     * filter is wired but submission is skipped. */
#ifndef SHROUD_UI_PREVIEW
    error_reporter_install(g_operator_diag_pubkey,
                           "https://100.30.51.8:58443");
#endif

    CryptoSplash splash;
    splash.show();
    app.processEvents();

    /* Construct main window synchronously (crypto/network/TPM init runs here).
       The splash stays visible while the constructor runs, then for the
       remainder of the hold time. */
    ShroudWindow w;
    w.setWindowIcon(QIcon(":/shroud.png"));

    QTimer::singleShot(splash.holdMs(), &splash, [&]() {
        w.show();
        w.raise();
        w.activateWindow();
        splash.close();
    });

    return app.exec();
}
