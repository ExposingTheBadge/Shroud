/*
 * SHROUD anonymous error reporter — Windows client.
 *
 * Hooks SetUnhandledExceptionFilter (for SEH / hardware exceptions)
 * and a small Qt log-message handler (for assert / qFatal). Builds a
 * PII-scrubbed report, seals it to the operator's diagnostics pubkey
 * via anon_routing.c, and POSTs to /api/v1/diagnostics/report through
 * WinHTTP.
 *
 * Wire format matches crypto/error_reporting.py.
 */
#ifndef SHROUD_ERROR_REPORTER_H
#define SHROUD_ERROR_REPORTER_H

#include "client.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the global error reporter. Call once at app start, AFTER
 * the user has configured their relay URL + pinned the operator
 * manifest.
 *
 *   operator_diag_pubkey : 32 bytes
 *   relay_base_url       : null-terminated UTF-8, e.g. "https://44.202.225.57:58443"
 */
void error_reporter_install(const BYTE operator_diag_pubkey[32],
                            const char *relay_base_url);

/* Non-fatal log submission. Returns TRUE if the report was queued.
 * extra_json may be NULL. */
BOOL error_reporter_log(const char *message,
                        const char *extra_json);

#ifdef __cplusplus
}
#endif

#endif /* SHROUD_ERROR_REPORTER_H */
