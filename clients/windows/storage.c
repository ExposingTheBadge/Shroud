/*
 * GHOSTLINK Windows Storage — DPAPI-protected key storage
 */
#include "client.h"

BOOL storage_save_keypair(const char *device_id, KeyPair *kp) {
    /* Export private key */
    BYTE keyBlob[4096];
    DWORD blobLen = sizeof(keyBlob);

    SECURITY_STATUS s = NCryptExportKey(kp->handle, NULL, BCRYPT_ECCPRIVATE_BLOB,
                         NULL, keyBlob, blobLen, &blobLen, 0);
    if (!BCRYPT_SUCCESS(s)) return FALSE;

    /* DPAPI encrypt */
    DATA_BLOB inBlob = { blobLen, keyBlob };
    DATA_BLOB outBlob = {0};
    if (!CryptProtectData(&inBlob, L"GHOSTLINK Identity Key", NULL, NULL, NULL,
                          0, &outBlob))
        return FALSE;

    /* Write to %APPDATA%\GHOSTLINK\identity.key */
    WCHAR path[MAX_PATH];
    if (!GetEnvironmentVariableW(L"APPDATA", path, MAX_PATH)) return FALSE;
    wcscat_s(path, MAX_PATH, L"\\GHOSTLINK");
    CreateDirectoryW(path, NULL);

    WCHAR filepath[MAX_PATH];
    wsprintfW(filepath, L"%s\\identity.key", path);
    HANDLE hFile = CreateFileW(filepath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { LocalFree(outBlob.pbData); return FALSE; }

    DWORD written;
    WriteFile(hFile, outBlob.pbData, outBlob.cbData, &written, NULL);
    CloseHandle(hFile);
    LocalFree(outBlob.pbData);
    return TRUE;
}

BOOL storage_load_keypair(const char *device_id, KeyPair *kp) {
    WCHAR path[MAX_PATH];
    if (!GetEnvironmentVariableW(L"APPDATA", path, MAX_PATH)) return FALSE;
    wcscat_s(path, MAX_PATH, L"\\GHOSTLINK");

    WCHAR filepath[MAX_PATH];
    wsprintfW(filepath, L"%s\\identity.key", path);

    HANDLE hFile = CreateFileW(filepath, GENERIC_READ, 0, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *encrypted = malloc(fileSize);
    DWORD read;
    ReadFile(hFile, encrypted, fileSize, &read, NULL);
    CloseHandle(hFile);

    DATA_BLOB inBlob = { read, encrypted };
    DATA_BLOB outBlob = {0};
    /* Try user-scoped first, then machine-scoped for old keys */
    if (!CryptUnprotectData(&inBlob, NULL, NULL, NULL, NULL, 0, &outBlob)) {
        if (!CryptUnprotectData(&inBlob, NULL, NULL, NULL, NULL,
                                 CRYPTPROTECT_LOCAL_MACHINE, &outBlob)) {
            free(encrypted); return FALSE;
        }
    }
    free(encrypted);

    /* Import private key back into CNG */
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
    SECURITY_STATUS s = NCryptImportKey(hProv, NULL, BCRYPT_ECCPRIVATE_BLOB,
                         NULL, &kp->handle, outBlob.pbData, outBlob.cbData, 0);
    NCryptFreeObject(hProv);
    LocalFree(outBlob.pbData);
    if (!BCRYPT_SUCCESS(s)) return FALSE;

    /* Export public key */
    kp->pub.len = PUBLIC_KEY_MAX;
    NCryptExportKey(kp->handle, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL,
                    kp->pub.data, PUBLIC_KEY_MAX, &kp->pub.len, 0);
    return TRUE;
}

BOOL storage_save_config(DeviceConfig *cfg) {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\GHOSTLINK", 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return FALSE;
    RegSetValueExA(hKey, "DeviceID", 0, REG_SZ, (BYTE*)cfg->id, (DWORD)strlen(cfg->id) + 1);
    RegSetValueExA(hKey, "Username", 0, REG_SZ, (BYTE*)cfg->username, (DWORD)strlen(cfg->username) + 1);
    RegSetValueExA(hKey, "DeviceName", 0, REG_SZ, (BYTE*)cfg->device_name, (DWORD)strlen(cfg->device_name) + 1);
    RegCloseKey(hKey);
    return TRUE;
}

BOOL storage_load_config(DeviceConfig *cfg) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\GHOSTLINK", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    DWORD size = sizeof(cfg->id);
    RegQueryValueExA(hKey, "DeviceID", NULL, NULL, (BYTE*)cfg->id, &size);
    size = sizeof(cfg->username);
    RegQueryValueExA(hKey, "Username", NULL, NULL, (BYTE*)cfg->username, &size);
    size = sizeof(cfg->device_name);
    RegQueryValueExA(hKey, "DeviceName", NULL, NULL, (BYTE*)cfg->device_name, &size);
    RegCloseKey(hKey);
    return TRUE;
}

BOOL storage_exists(void) {
    HKEY hKey;
    BOOL exists = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\GHOSTLINK", 0, KEY_READ, &hKey) == ERROR_SUCCESS;
    if (exists) RegCloseKey(hKey);
    return exists;
}

/* Get or create persistent app instance ID (stays same across launches) */
void app_instance_id(char *out, int outSize) {
    HKEY hKey;
    DWORD size = outSize;
    /* Try to read existing */
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\GHOSTLINK", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "AppInstanceID", NULL, NULL, (BYTE*)out, &size) == ERROR_SUCCESS && out[0]) {
            RegCloseKey(hKey);
            return;
        }
        RegCloseKey(hKey);
    }
    /* Generate new UUID-style ID */
    BYTE rand[16];
    crypto_random_bytes(rand, 16);
    wsprintfA(out, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        rand[0],rand[1],rand[2],rand[3],rand[4],rand[5],rand[6],rand[7],
        rand[8],rand[9],rand[10],rand[11],rand[12],rand[13],rand[14],rand[15]);
    out[outSize-1] = 0;
    /* Save */
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\GHOSTLINK", 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "AppInstanceID", 0, REG_SZ, (BYTE*)out, (DWORD)strlen(out)+1);
        RegCloseKey(hKey);
    }
}

void storage_delete_all(void) {
    /* Delete registry key */
    RegDeleteKeyA(HKEY_CURRENT_USER, "SOFTWARE\\GHOSTLINK");

    /* Delete identity key file */
    WCHAR path[MAX_PATH];
    if (GetEnvironmentVariableW(L"APPDATA", path, MAX_PATH)) {
        wcscat_s(path, MAX_PATH, L"\\GHOSTLINK");
        WCHAR filepath[MAX_PATH];
        wsprintfW(filepath, L"%s\\identity.key", path);
        DeleteFileW(filepath);
        RemoveDirectoryW(path);
    }

    /* Clear message cache */
    DeleteFileA(MSG_CACHE_FILE);
}
