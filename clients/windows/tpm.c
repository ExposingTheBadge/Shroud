/*
 * SHROUD Windows TPM 2.0 — Detection, Status, and Key Sealing
 */
#include "client.h"
#include <tbs.h>

#pragma comment(lib, "tbs.lib")

#ifndef CRYPTPROTECT_SYSTEM
#define CRYPTPROTECT_SYSTEM 0x20000000
#endif

static BOOL gTpmAvailable = FALSE;
static BOOL gTpm20 = FALSE;
static char gTpmManufacturer[64] = "";
static DWORD gTpmSpecVersion = 0;

/* ── TPM Detection ────────────────────────────────────────────────── */
BOOL tpm_detect(void) {
    /* Try to open TPM Base Services context */
    TBS_HCONTEXT hTbs = 0;
    TBS_CONTEXT_PARAMS2 params = {0};
    params.version = TBS_CONTEXT_VERSION_TWO;

    HRESULT hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &hTbs);
    if (hr == TBS_SUCCESS && hTbs) {
        Tbsip_Context_Close(hTbs);
        gTpmAvailable = TRUE;
    }

    /* Registry-based fallback detection */
    if (!gTpmAvailable) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            gTpmAvailable = TRUE;
            RegCloseKey(hKey);
        }
    }

    /* Check TPM version from registry */
    if (gTpmAvailable) {
        HKEY hKey;
        DWORD specVer = 0, size = sizeof(specVer);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Admin",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            if (RegQueryValueExA(hKey, "TPMSpecVersion", NULL, NULL,
                (BYTE*)&specVer, &size) == ERROR_SUCCESS) {
                gTpmSpecVersion = specVer;
            }

            char vendor[64] = "";
            DWORD vsize = sizeof(vendor);
            if (RegQueryValueExA(hKey, "ManufacturerId", NULL, NULL,
                (BYTE*)vendor, &vsize) == ERROR_SUCCESS) {
                strncpy(gTpmManufacturer, vendor, 63);
            }
            RegCloseKey(hKey);
        }

        gTpm20 = (gTpmSpecVersion >= 0x00020000);
    }

    return gTpmAvailable;
}

BOOL tpm_is_available(void) { return gTpmAvailable; }
BOOL tpm_is_20(void) { return gTpm20; }
DWORD tpm_spec_version(void) { return gTpmSpecVersion; }
const char* tpm_manufacturer(void) {
    return gTpmManufacturer[0] ? gTpmManufacturer : "Unknown";
}

/* ── TPM-Sealed Key Storage ───────────────────────────────────────── */
BOOL tpm_seal_key(const BYTE *keyData, DWORD keyLen, const char *label) {
    /* Use NCrypt with platform key storage (backed by TPM if available) */
    NCRYPT_PROV_HANDLE hProv = NULL;
    SECURITY_STATUS s = NCryptOpenStorageProvider(&hProv,
        MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
    if (BCRYPT_SUCCESS(s)) {
        /* Create a TPM-backed persistent key */
        NCRYPT_KEY_HANDLE hKey = NULL;
        s = NCryptCreatePersistedKey(hProv, &hKey,
            BCRYPT_RSA_ALGORITHM, L"SHROUD_TPM_SEAL", 0,
            NCRYPT_OVERWRITE_KEY_FLAG);
        if (BCRYPT_SUCCESS(s)) {
            s = NCryptFinalizeKey(hKey, 0);
            if (BCRYPT_SUCCESS(s)) {
                /* Store the key data as a property on the TPM key */
                s = NCryptSetProperty(hKey, NCRYPT_USER_CERTSTORE_PROPERTY,
                    (PBYTE)keyData, keyLen, 0);
            }
            NCryptDeleteKey(hKey, 0);
        }
        NCryptFreeObject(hProv);
        if (BCRYPT_SUCCESS(s)) return TRUE;
    }

    /* Fallback: DPAPI with machine-level protection */
    DATA_BLOB inBlob = { keyLen, (BYTE*)keyData };
    DATA_BLOB outBlob = {0};

    if (!CryptProtectData(&inBlob, L"SHROUD TPM Seal",
        NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE, &outBlob))
        return FALSE;

    WCHAR filepath[MAX_PATH];
    if (!GetEnvironmentVariableW(L"APPDATA", filepath, MAX_PATH)) {
        LocalFree(outBlob.pbData); return FALSE;
    }
    wcscat_s(filepath, MAX_PATH, L"\\SHROUD");
    CreateDirectoryW(filepath, NULL);

    WCHAR fullPath[MAX_PATH];
    wsprintfW(fullPath, L"%s\\tpm_sealed.dat", filepath);

    HANDLE hFile = CreateFileW(fullPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LocalFree(outBlob.pbData); return FALSE;
    }
    DWORD written;
    WriteFile(hFile, outBlob.pbData, outBlob.cbData, &written, NULL);
    CloseHandle(hFile);
    LocalFree(outBlob.pbData);
    return TRUE;
}

BOOL tpm_unseal_key(BYTE **keyData, DWORD *keyLen, const char *label) {
    WCHAR filepath[MAX_PATH];
    if (!GetEnvironmentVariableW(L"APPDATA", filepath, MAX_PATH)) return FALSE;
    wcscat_s(filepath, MAX_PATH, L"\\SHROUD");

    WCHAR fullPath[MAX_PATH];
    wsprintfW(fullPath, L"%s\\tpm_sealed.dat", filepath);

    HANDLE hFile = CreateFileW(fullPath, GENERIC_READ, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *encrypted = malloc(fileSize);
    if (!encrypted) { CloseHandle(hFile); return FALSE; }

    DWORD read;
    ReadFile(hFile, encrypted, fileSize, &read, NULL);
    CloseHandle(hFile);

    DATA_BLOB inBlob = { read, encrypted };
    DATA_BLOB outBlob = {0};

    if (!CryptUnprotectData(&inBlob, NULL, NULL, NULL, NULL, 0, &outBlob)) {
        free(encrypted); return FALSE;
    }

    *keyData = malloc(outBlob.cbData);
    if (!*keyData) { LocalFree(outBlob.pbData); free(encrypted); return FALSE; }

    memcpy(*keyData, outBlob.pbData, outBlob.cbData);
    *keyLen = outBlob.cbData;

    LocalFree(outBlob.pbData);
    free(encrypted);
    return TRUE;
}

/* ── TPM Status String ────────────────────────────────────────────── */
void tpm_status_string(char *buf, int bufSize) {
    if (!gTpmAvailable) {
        wsprintfA(buf, "TPM: None");
    } else if (gTpm20) {
        DWORD major = (gTpmSpecVersion >> 16) & 0xFFFF;
        DWORD minor = gTpmSpecVersion & 0xFFFF;
        if (gTpmManufacturer[0])
            wsprintfA(buf, "TPM 2.0 (%s)", gTpmManufacturer);
        else
            wsprintfA(buf, "TPM 2.0");
    } else {
        wsprintfA(buf, "TPM 1.2");
    }
}
