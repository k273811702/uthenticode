#ifndef _PH_VERIFY_H
#define _PH_VERIFY_H
#define  PHLIBAPI
#include <Windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <WinCrypt.h>
#include <string>

#define PH_VERIFY_DEFAULT_SIZE_LIMIT (32 * 1024 * 1024)

#define STATUS_SUCCESS 0

typedef enum _VERIFY_RESULT
{
    VrUnknown = 0,
    VrNoSignature,
    VrTrusted,
    VrExpired,
    VrRevoked,
    VrDistrust,
    VrSecuritySettings,
    VrBadSignature
} VERIFY_RESULT, *PVERIFY_RESULT;

#define PH_VERIFY_PREVENT_NETWORK_ACCESS 0x1
#define PH_VERIFY_VIEW_PROPERTIES 0x2

typedef struct _PH_VERIFY_FILE_INFO
{
    PCWSTR FileName;
    ULONG Flags; // PH_VERIFY_*

    ULONG FileSizeLimitForHash; // 0 for PH_VERIFY_DEFAULT_SIZE_LIMIT, -1 for unlimited
    ULONG NumberOfCatalogFileNames;
    PWSTR *CatalogFileNames;

    HWND hWnd; // for PH_VERIFY_VIEW_PROPERTIES
} PH_VERIFY_FILE_INFO, *PPH_VERIFY_FILE_INFO;

#define PhVerify_PE_SING    1
#define PhVerify_CAT_SING   2

PHLIBAPI
VERIFY_RESULT
NTAPI
PhVerifyFile(
    _In_ PCWSTR FileName,
    std::wstring& SignerName,
    DWORD SignMask = PhVerify_PE_SING| PhVerify_CAT_SING);

VOID PhpVerifyInitialization(VOID);

PHLIBAPI
NTSTATUS
NTAPI
PhVerifyFileEx(
    _In_ PPH_VERIFY_FILE_INFO Information,
    _Out_ VERIFY_RESULT* VerifyResult,
    _Out_opt_ PCERT_CONTEXT** Signatures,
    _Out_opt_ PULONG NumberOfSignatures,
    DWORD SignMask
);

PHLIBAPI
VOID
NTAPI
PhFreeVerifySignatures(
    _In_ PCERT_CONTEXT* Signatures,
    _In_ ULONG NumberOfSignatures
);

PHLIBAPI
std::wstring
NTAPI
PhGetSignerNameFromCertificate(
    _In_ PCERT_CONTEXT Certificate
);

#endif
