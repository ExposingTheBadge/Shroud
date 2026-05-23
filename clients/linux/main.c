/*
 * GHOSTLINK Linux Client — GTK3, OpenSSL, libcurl
 * Compile: gcc -O2 -o ghostlink main.c `pkg-config --cflags --libs gtk+-3.0 openssl libcurl`
 */
#include <gtk/gtk.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVER_URL    "http://150.195.114.185:58443"
#define APP_VERSION   "1.0.0"
#define CONFIG_DIR    ".ghostlink"
#define DOWNLOAD_DIR  "Downloads/GHOSTLINK"
#define AES_KEY_LEN   32
#define AES_IV_LEN    12
#define AES_TAG_LEN   16
#define SHA256_LEN    32

/* ── Globals ──────────────────────────────────────────────────────── */
static GtkWidget *main_window, *main_stack;
static GtkWidget *reg_username, *reg_password, *reg_devname, *reg_status;
static GtkWidget *chat_list, *chat_input, *chat_recipient, *chat_name, *chat_note;
static GtkWidget *sidebar_list, *sidebar_search, *sidebar_tabs;
static char device_id[65], username[65], device_name[65];
static char identity_pub[2048], identity_priv[4096];
static int registered = 0, tab_groups = 0;
static char selected_recipient[128];

/* ── HTTP Response ────────────────────────────────────────────────── */
struct response { char *data; size_t len; };
static size_t curl_write_cb(void *ptr, size_t sz, size_t nmemb, void *ud) {
    struct response *r = ud;
    size_t total = sz * nmemb;
    r->data = realloc(r->data, r->len + total + 1);
    memcpy(r->data + r->len, ptr, total);
    r->len += total;
    r->data[r->len] = 0;
    return total;
}

static char* http_post(const char *path, const char *body) {
    CURL *c = curl_easy_init();
    if (!c) return NULL;
    char url[512]; snprintf(url, 512, "%s%s", SERVER_URL, path);
    struct response r = {0};
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &r);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
    curl_easy_perform(c);
    curl_easy_cleanup(c);
    return r.data;
}

static char* http_get(const char *path) {
    CURL *c = curl_easy_init();
    if (!c) return NULL;
    char url[512]; snprintf(url, 512, "%s%s", SERVER_URL, path);
    struct response r = {0};
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &r);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
    curl_easy_perform(c);
    curl_easy_cleanup(c);
    return r.data;
}

/* ── JSON Helper ──────────────────────────────────────────────────── */
static char* json_str(const char *j, const char *k) {
    char search[128]; snprintf(search, 128, "\"%s\":\"", k);
    char *s = strstr((char*)j, search);
    if (!s) return NULL;
    s += strlen(search);
    char *e = strchr(s, '"');
    if (!e) return NULL;
    int len = e - s;
    char *v = malloc(len + 1);
    strncpy(v, s, len); v[len] = 0;
    return v;
}

/* ── Crypto ───────────────────────────────────────────────────────── */
static void crypto_init(void) { OpenSSL_add_all_algorithms(); RAND_poll(); }

static void gen_keypair(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp384r1);
    EC_KEY_generate_key(key);
    const EC_POINT *pt = EC_KEY_get0_public_key(key);
    const EC_GROUP *grp = EC_KEY_get0_group(key);
    int pub_len = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED, (unsigned char*)identity_pub, 2048, NULL);
    identity_pub[pub_len] = 0;
    /* Export private key */
    const BIGNUM *priv = EC_KEY_get0_private_key(key);
    BN_bn2hex(priv);
    EC_KEY_free(key);
}

static void aes_gcm_encrypt(const unsigned char *key, const unsigned char *plain, int len,
                             unsigned char *iv_out, unsigned char *ct_out, unsigned char *tag_out) {
    RAND_bytes(iv_out, AES_IV_LEN);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv_out);
    int outlen;
    EVP_EncryptUpdate(ctx, ct_out, &outlen, plain, len);
    EVP_EncryptFinal_ex(ctx, ct_out + outlen, &outlen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag_out);
    EVP_CIPHER_CTX_free(ctx);
}

static void sha256(const unsigned char *d, int len, unsigned char *out) {
    SHA256_CTX ctx; SHA256_Init(&ctx); SHA256_Update(&ctx, d, len); SHA256_Final(out, &ctx);
}

static char* hex_encode(const unsigned char *d, int len) {
    char *h = malloc(len * 2 + 1);
    for (int i = 0; i < len; i++) sprintf(h + i * 2, "%02x", d[i]);
    h[len * 2] = 0;
    return h;
}

static int hex_decode(const char *h, unsigned char *out) {
    int len = strlen(h) / 2;
    for (int i = 0; i < len; i++) sscanf(h + i * 2, "%2hhx", &out[i]);
    return len;
}

/* ── Storage ──────────────────────────────────────────────────────── */
static char cfg_path[512];
static void storage_init(void) {
    char *home = getenv("HOME");
    snprintf(cfg_path, 512, "%s/%s", home, CONFIG_DIR);
    mkdir(cfg_path, 0700);
}

static void storage_save(void) {
    char p[512]; snprintf(p, 512, "%s/config", cfg_path);
    FILE *f = fopen(p, "w");
    if (f) { fprintf(f, "%s\n%s\n%s\n%s\n%s\n", device_id, username, device_name, identity_pub, identity_priv); fclose(f); }
}

static int storage_load(void) {
    char p[512]; snprintf(p, 512, "%s/config", cfg_path);
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    if (fscanf(f, "%64s\n%64s\n%64s\n%2048s\n%4096s\n", device_id, username, device_name, identity_pub, identity_priv) < 5) {
        fclose(f); return 0;
    }
    fclose(f);
    return device_id[0] != 0;
}

/* ── Registration ─────────────────────────────────────────────────── */
static void on_register(GtkWidget *btn, gpointer data) {
    const char *uname = gtk_entry_get_text(GTK_ENTRY(reg_username));
    const char *pass = gtk_entry_get_text(GTK_ENTRY(reg_password));
    const char *dname = gtk_entry_get_text(GTK_ENTRY(reg_devname));
    int is_login = GPOINTER_TO_INT(data);

    if (strlen(uname) < 3 || strlen(pass) < 12) {
        gtk_label_set_text(GTK_LABEL(reg_status), "Username 3+ chars, password 12+ chars");
        return;
    }

    gtk_label_set_text(GTK_LABEL(reg_status), "Generating ECDH P-384 keypair...");
    while (gtk_events_pending()) gtk_main_iteration();
    gen_keypair();

    unsigned char pub_der[2048];
    int pub_len = hex_decode(identity_pub, pub_der);
    char *pub_hex = hex_encode(pub_der, pub_len);

    /* Register user if new account */
    if (!is_login) {
        char body[512];
        snprintf(body, 512, "{\"username\":\"%s\",\"password\":\"%s\"}", uname, pass);
        char *r = http_post("/api/v1/register", body);
        if (r) free(r);
    }

    /* Register device */
    char body[2048];
    snprintf(body, 2048, "{\"username\":\"%s\",\"password\":\"%s\",\"device_name\":\"%s\","
             "\"platform\":\"linux\",\"public_key\":\"%s\",\"hwid\":\"\"}",
             uname, pass, dname, pub_hex);
    free(pub_hex);

    char *resp = http_post("/api/v1/devices", body);
    if (resp) {
        char *did = json_str(resp, "device_id");
        if (did) {
            strncpy(device_id, did, 64); device_id[64] = 0;
            strncpy(username, uname, 64); username[64] = 0;
            strncpy(device_name, dname, 64); device_name[64] = 0;
            storage_save();
            registered = 1;
            gtk_stack_set_visible_child_name(GTK_STACK(main_stack), "chat");
            free(did);
        } else {
            char *detail = json_str(resp, "detail");
            gtk_label_set_text(GTK_LABEL(reg_status), detail ? detail : "Server rejected");
            if (detail) free(detail);
        }
        free(resp);
    } else {
        gtk_label_set_text(GTK_LABEL(reg_status), "Server unreachable");
    }
}

/* ── Chat ─────────────────────────────────────────────────────────── */
static void on_send(GtkWidget *btn, gpointer data) {
    const char *body = gtk_entry_get_text(GTK_ENTRY(chat_input));
    if (!body[0] || !selected_recipient[0]) return;

    unsigned char key[32], iv[12], ct[4096], tag[16];
    unsigned char pub[2048]; int plen = hex_decode(identity_pub, pub);
    sha256(pub, plen, key);

    char payload[4600];
    snprintf(payload, 4600, "{\"body\":\"%s\",\"name\":\"%s\",\"note\":\"%s\",\"sender\":\"%s\",\"ts\":%ld}",
             body, gtk_entry_get_text(GTK_ENTRY(chat_name)),
             gtk_entry_get_text(GTK_ENTRY(chat_note)), device_id, time(NULL));

    aes_gcm_encrypt(key, (unsigned char*)payload, strlen(payload), iv, ct, tag);
    char *iv_hex = hex_encode(iv, 12);
    char *ct_hex = hex_encode(ct, strlen(payload));
    char *tag_hex = hex_encode(tag, 16);
    unsigned char sig[32]; sha256(ct, strlen(payload), sig);
    char *sig_hex = hex_encode(sig, 32);

    char env[9000], jbody[9500];
    snprintf(env, 9000, "{\"sender\":\"%s\",\"ts\":%ld,\"nonce\":\"%s\",\"ciphertext\":\"%s\",\"tag\":\"%s\",\"sig\":\"%s\"}",
             device_id, time(NULL), iv_hex, ct_hex, tag_hex, sig_hex);
    snprintf(jbody, 9500, "{\"sender_device_id\":\"%s\",\"recipient_device_id\":\"%s\",\"envelope\":%s}",
             device_id, selected_recipient, env);

    free(iv_hex); free(ct_hex); free(tag_hex); free(sig_hex);
    char *r = http_post("/api/v1/messages/send", jbody);
    if (r) free(r);
    gtk_entry_set_text(GTK_ENTRY(chat_input), "");

    /* Add to local display */
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(chat_list));
    GtkTextIter end; gtk_text_buffer_get_end_iter(buf, &end);
    char line[4700]; snprintf(line, 4700, "[ME -> %.12s] %s\n", selected_recipient, body);
    gtk_text_buffer_insert(buf, &end, line, -1);
}

/* ── Build UI ─────────────────────────────────────────────────────── */
static void build_registration(void) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_start(box, 40); gtk_widget_set_margin_end(box, 40);
    gtk_widget_set_margin_top(box, 40);

    GtkWidget *title = gtk_label_new("<big><b>GHOSTLINK Setup</b></big>");
    gtk_label_set_use_markup(GTK_LABEL(title), TRUE);
    gtk_box_pack_start(GTK_BOX(box), title, FALSE, FALSE, 8);

    reg_username = gtk_entry_new(); gtk_entry_set_placeholder_text(GTK_ENTRY(reg_username), "Username");
    gtk_box_pack_start(GTK_BOX(box), reg_username, FALSE, FALSE, 0);

    reg_password = gtk_entry_new(); gtk_entry_set_placeholder_text(GTK_ENTRY(reg_password), "Password (12+ chars)");
    gtk_entry_set_visibility(GTK_ENTRY(reg_password), FALSE);
    gtk_box_pack_start(GTK_BOX(box), reg_password, FALSE, FALSE, 0);

    reg_devname = gtk_entry_new(); gtk_entry_set_placeholder_text(GTK_ENTRY(reg_devname), "Device Name");
    gtk_entry_set_text(GTK_ENTRY(reg_devname), "Linux-PC");
    gtk_box_pack_start(GTK_BOX(box), reg_devname, FALSE, FALSE, 0);

    GtkWidget *btn_box = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_button_box_set_layout(GTK_BUTTON_BOX(btn_box), GTK_BUTTONBOX_EXPAND);
    GtkWidget *reg_btn = gtk_button_new_with_label("Create Account");
    g_signal_connect(reg_btn, "clicked", G_CALLBACK(on_register), GINT_TO_POINTER(0));
    gtk_container_add(GTK_CONTAINER(btn_box), reg_btn);
    GtkWidget *login_btn = gtk_button_new_with_label("Login & Add Device");
    g_signal_connect(login_btn, "clicked", G_CALLBACK(on_register), GINT_TO_POINTER(1));
    gtk_container_add(GTK_CONTAINER(btn_box), login_btn);
    gtk_box_pack_start(GTK_BOX(box), btn_box, FALSE, FALSE, 8);

    reg_status = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(box), reg_status, FALSE, FALSE, 0);

    gtk_stack_add_named(GTK_STACK(main_stack), box, "register");
}

static void build_chat(void) {
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);

    /* Sidebar */
    GtkWidget *sidebar = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_size_request(sidebar, 220, -1);
    sidebar_tabs = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_button_box_set_layout(GTK_BUTTON_BOX(sidebar_tabs), GTK_BUTTONBOX_EXPAND);
    GtkWidget *t1 = gtk_button_new_with_label("Contacts");
    GtkWidget *t2 = gtk_button_new_with_label("Groups");
    gtk_container_add(GTK_CONTAINER(sidebar_tabs), t1);
    gtk_container_add(GTK_CONTAINER(sidebar_tabs), t2);
    gtk_box_pack_start(GTK_BOX(sidebar), sidebar_tabs, FALSE, FALSE, 0);

    sidebar_search = gtk_entry_new(); gtk_entry_set_placeholder_text(GTK_ENTRY(sidebar_search), "Search...");
    gtk_box_pack_start(GTK_BOX(sidebar), sidebar_search, FALSE, FALSE, 0);

    sidebar_list = gtk_list_box_new();
    gtk_box_pack_start(GTK_BOX(sidebar), sidebar_list, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(hbox), sidebar, FALSE, FALSE, 0);

    /* Chat area */
    GtkWidget *chat_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_start(chat_box, 8); gtk_widget_set_margin_end(chat_box, 8);

    chat_recipient = gtk_entry_new(); gtk_editable_set_editable(GTK_EDITABLE(chat_recipient), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(chat_recipient), "Select a contact");
    gtk_box_pack_start(GTK_BOX(chat_box), chat_recipient, FALSE, FALSE, 0);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    chat_list = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(chat_list), FALSE);
    gtk_container_add(GTK_CONTAINER(scroll), chat_list);
    gtk_box_pack_start(GTK_BOX(chat_box), scroll, TRUE, TRUE, 0);

    GtkWidget *name_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    chat_name = gtk_entry_new(); gtk_entry_set_placeholder_text(GTK_ENTRY(chat_name), "Display Name");
    gtk_box_pack_start(GTK_BOX(name_box), chat_name, FALSE, FALSE, 0);
    chat_note = gtk_entry_new(); gtk_entry_set_placeholder_text(GTK_ENTRY(chat_note), "Note / Comment");
    gtk_box_pack_start(GTK_BOX(name_box), chat_note, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(chat_box), name_box, FALSE, FALSE, 0);

    GtkWidget *input_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    chat_input = gtk_entry_new(); gtk_entry_set_placeholder_text(GTK_ENTRY(chat_input), "Type a message...");
    gtk_box_pack_start(GTK_BOX(input_box), chat_input, TRUE, TRUE, 0);
    GtkWidget *send_btn = gtk_button_new_with_label("Send");
    g_signal_connect(send_btn, "clicked", G_CALLBACK(on_send), NULL);
    gtk_box_pack_start(GTK_BOX(input_box), send_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(chat_box), input_box, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(hbox), chat_box, TRUE, TRUE, 0);

    gtk_stack_add_named(GTK_STACK(main_stack), hbox, "chat");
}

/* ── Main ─────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    gtk_init(&argc, &argv);
    curl_global_init(CURL_GLOBAL_ALL);
    crypto_init();
    storage_init();

    main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_window), "GHOSTLINK Secure Messenger");
    gtk_window_set_default_size(GTK_WINDOW(main_window), 850, 600);
    g_signal_connect(main_window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    /* Dark theme */
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css,
        "* { background-color: #1a1a1a; color: #cccccc; }"
        "entry { background-color: #2d2d2d; color: #cccccc; border: 1px solid #3d3d3d; padding: 6px; }"
        "button { background-color: #2d2d2d; color: #cccccc; border: 1px solid #3d3d3d; padding: 6px 12px; }"
        "button:hover { background-color: #3d3d3d; }"
        "textview { background-color: #1a1a1a; color: #cccccc; }"
        "textview text { background-color: #1a1a1a; color: #cccccc; }"
        "list { background-color: #242424; }"
        "list row { padding: 4px; }"
        , -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    main_stack = gtk_stack_new();
    gtk_container_add(GTK_CONTAINER(main_window), main_stack);

    build_registration();
    build_chat();

    /* Load saved config */
    if (storage_load()) {
        registered = 1;
        gtk_stack_set_visible_child_name(GTK_STACK(main_stack), "chat");
    }

    gtk_widget_show_all(main_window);
    gtk_main();

    curl_global_cleanup();
    return 0;
}
