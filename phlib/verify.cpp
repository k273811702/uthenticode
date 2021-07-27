///*
// * Process Hacker -
// *   image verification
// *
// * Copyright (C) 2009-2013 wj32
// *
// * This file is part of Process Hacker.
// *
// * Process Hacker is free software; you can redistribute it and/or modify
// * it under the terms of the GNU General Public License as published by
// * the Free Software Foundation, either version 3 of the License, or
// * (at your option) any later version.
// *
// * Process Hacker is distributed in the hope that it will be useful,
// * but WITHOUT ANY WARRANTY; without even the implied warranty of
// * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// * GNU General Public License for more details.
// *
// * You should have received a copy of the GNU General Public License
// * along with Process Hacker.  If not, see <http://www.gnu.org/licenses/>.
// */
//
//#define PH_ENABLE_VERIFY_CACHE
////#include <ph.h>
////#include <appresolver.h>
#include "verify.h"
#include "verifyp.h"

_CryptCATAdminCalcHashFromFileHandle CryptCATAdminCalcHashFromFileHandle = nullptr;
_CryptCATAdminCalcHashFromFileHandle2 CryptCATAdminCalcHashFromFileHandle2 = nullptr;
_CryptCATAdminAcquireContext CryptCATAdminAcquireContext = nullptr;
_CryptCATAdminAcquireContext2 CryptCATAdminAcquireContext2 = nullptr;
_CryptCATAdminEnumCatalogFromHash CryptCATAdminEnumCatalogFromHash =nullptr;
_CryptCATCatalogInfoFromContext CryptCATCatalogInfoFromContext = nullptr;
_CryptCATAdminReleaseCatalogContext CryptCATAdminReleaseCatalogContext =nullptr;
_CryptCATAdminReleaseContext CryptCATAdminReleaseContext = nullptr;
_WTHelperProvDataFromStateData WTHelperProvDataFromStateData_I =nullptr;
_WTHelperGetProvSignerFromChain WTHelperGetProvSignerFromChain_I = nullptr;
_WinVerifyTrust WinVerifyTrust_I = nullptr;
_CertNameToStr CertNameToStr_I = nullptr;
_CertDuplicateCertificateContext CertDuplicateCertificateContext_I = nullptr;
_CertFreeCertificateContext CertFreeCertificateContext_I = nullptr;

static GUID WinTrustActionGenericVerifyV2 = WINTRUST_ACTION_GENERIC_VERIFY_V2;
static GUID DriverActionVerify = DRIVER_ACTION_VERIFY;

VOID PhpVerifyInitialization(VOID)
{
    HMODULE wintrust;
    HMODULE crypt32;
    if (CryptCATAdminCalcHashFromFileHandle)
    {
        return;
    }
    wintrust = LoadLibrary(L"wintrust.dll");
    crypt32 = LoadLibrary(L"crypt32.dll");

    if (wintrust)
    {
        CryptCATAdminCalcHashFromFileHandle = reinterpret_cast<decltype(CryptCATAdminCalcHashFromFileHandle)> (GetProcAddress(wintrust, "CryptCATAdminCalcHashFromFileHandle"));
        CryptCATAdminCalcHashFromFileHandle2 = reinterpret_cast<decltype(CryptCATAdminCalcHashFromFileHandle2)>(GetProcAddress(wintrust, "CryptCATAdminCalcHashFromFileHandle2"));
        CryptCATAdminAcquireContext = reinterpret_cast<decltype(CryptCATAdminAcquireContext)>(GetProcAddress(wintrust, "CryptCATAdminAcquireContext"));
        CryptCATAdminAcquireContext2 = reinterpret_cast<decltype(CryptCATAdminAcquireContext2)>(GetProcAddress(wintrust, "CryptCATAdminAcquireContext2"));
        CryptCATAdminEnumCatalogFromHash = reinterpret_cast<decltype(CryptCATAdminEnumCatalogFromHash)>(GetProcAddress(wintrust, "CryptCATAdminEnumCatalogFromHash"));
        CryptCATCatalogInfoFromContext = reinterpret_cast<decltype(CryptCATCatalogInfoFromContext)>(GetProcAddress(wintrust, "CryptCATCatalogInfoFromContext"));
        CryptCATAdminReleaseCatalogContext = reinterpret_cast<decltype(CryptCATAdminReleaseCatalogContext)>(GetProcAddress(wintrust, "CryptCATAdminReleaseCatalogContext"));
        CryptCATAdminReleaseContext = reinterpret_cast<decltype(CryptCATAdminReleaseContext)>(GetProcAddress(wintrust, "CryptCATAdminReleaseContext"));
        WTHelperProvDataFromStateData_I = reinterpret_cast<decltype(WTHelperProvDataFromStateData_I)>(GetProcAddress(wintrust, "WTHelperProvDataFromStateData"));
        WTHelperGetProvSignerFromChain_I = reinterpret_cast<decltype(WTHelperGetProvSignerFromChain_I)>(GetProcAddress(wintrust, "WTHelperGetProvSignerFromChain"));
        WinVerifyTrust_I = reinterpret_cast<decltype(WinVerifyTrust_I)>(GetProcAddress(wintrust, "WinVerifyTrust"));
    }

    if (crypt32)
    {
        CertNameToStr_I = reinterpret_cast<decltype(CertNameToStr_I)>(GetProcAddress(crypt32, "CertNameToStrW"));
        CertDuplicateCertificateContext_I = reinterpret_cast<decltype(CertDuplicateCertificateContext_I)>(GetProcAddress(crypt32, "CertDuplicateCertificateContext"));
        CertFreeCertificateContext_I = reinterpret_cast<decltype(CertFreeCertificateContext_I)>(GetProcAddress(crypt32, "CertFreeCertificateContext"));
    }
}

VERIFY_RESULT PhpStatusToVerifyResult(
    _In_ LONG Status
)
{
    switch (Status)
    {
    case 0:
        return VrTrusted;
    case TRUST_E_NOSIGNATURE:
        return VrNoSignature;
    case CERT_E_EXPIRED:
        return VrExpired;
    case CERT_E_REVOKED:
        return VrRevoked;
    case TRUST_E_EXPLICIT_DISTRUST:
        return VrDistrust;
    case CRYPT_E_SECURITY_SETTINGS:
        return VrSecuritySettings;
    case TRUST_E_BAD_DIGEST:
        return VrBadSignature;
    default:
        return VrSecuritySettings;
    }
}

BOOLEAN PhpGetSignaturesFromStateData(
    _In_ HANDLE StateData,
    _Out_ PCERT_CONTEXT **Signatures,
    _Out_ PULONG NumberOfSignatures
    )
{
    PCRYPT_PROVIDER_DATA provData;
    PCRYPT_PROVIDER_SGNR sgnr;
    PCERT_CONTEXT *signatures;
    ULONG i;
    ULONG numberOfSignatures;
    ULONG index;

    provData = WTHelperProvDataFromStateData_I(StateData);

    if (!provData)
    {
        *Signatures = NULL;
        *NumberOfSignatures = 0;
        return FALSE;
    }

    i = 0;
    numberOfSignatures = 0;

    while (sgnr = WTHelperGetProvSignerFromChain_I(provData, i, FALSE, 0))
    {
        if (sgnr->csCertChain != 0)
            numberOfSignatures++;

        i++;
    }

    if (numberOfSignatures != 0)
    {
        signatures = (PCERT_CONTEXT*)malloc(numberOfSignatures * sizeof(PCERT_CONTEXT));
        i = 0;
        index = 0;

        while (sgnr = WTHelperGetProvSignerFromChain_I(provData, i, FALSE, 0))
        {
            if (sgnr->csCertChain != 0)
                signatures[index++] = (PCERT_CONTEXT)CertDuplicateCertificateContext_I(sgnr->pasCertChain[0].pCert);

            i++;
        }
    }
    else
    {
        signatures = NULL;
    }

    *Signatures = signatures;
    *NumberOfSignatures = numberOfSignatures;

    return TRUE;
}

//VOID PhpViewSignerInfo(
//    _In_ PPH_VERIFY_FILE_INFO Information,
//    _In_ HANDLE StateData
//    )
//{
//    
//    static _CryptUIDlgViewSignerInfo cryptUIDlgViewSignerInfo;
//
//    if (PhBeginInitOnce(&initOnce))
//    {
//        HMODULE cryptui = LoadLibrary(L"cryptui.dll");
//
//        cryptUIDlgViewSignerInfo = PhGetDllBaseProcedureAddress(cryptui, "CryptUIDlgViewSignerInfoW", 0);
//        PhEndInitOnce(&initOnce);
//    }
//
//    if (cryptUIDlgViewSignerInfo)
//    {
//        CRYPTUI_VIEWSIGNERINFO_STRUCT viewSignerInfo = { sizeof(CRYPTUI_VIEWSIGNERINFO_STRUCT) };
//        PCRYPT_PROVIDER_DATA provData;
//        PCRYPT_PROVIDER_SGNR sgnr;
//
//        if (!(provData = WTHelperProvDataFromStateData_I(StateData)))
//            return;
//        if (!(sgnr = WTHelperGetProvSignerFromChain_I(provData, 0, FALSE, 0)))
//            return;
//
//        viewSignerInfo.hwndParent = Information->hWnd;
//        viewSignerInfo.pSignerInfo = sgnr->psSigner;
//        viewSignerInfo.hMsg = provData->hMsg;
//        viewSignerInfo.pszOID = szOID_PKIX_KP_CODE_SIGNING;
//        cryptUIDlgViewSignerInfo(&viewSignerInfo);
//    }
//}

VERIFY_RESULT PhpVerifyFile(
    _In_ PPH_VERIFY_FILE_INFO Information,
    _In_ ULONG UnionChoice,
    _In_ PVOID UnionData,
    _In_ GUID* ActionId,
    _In_opt_ PVOID PolicyCallbackData,
    _Out_ PCERT_CONTEXT **Signatures,
    _Out_ PULONG NumberOfSignatures
    )
{
    LONG status;
    WINTRUST_DATA trustData = { 0 };

    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = PolicyCallbackData;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = UnionChoice;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    trustData.pFile = (decltype(trustData.pFile))UnionData;

    if (UnionChoice == WTD_CHOICE_CATALOG)
        trustData.pCatalog = (decltype(trustData.pCatalog))UnionData;

    if (Information->Flags & PH_VERIFY_PREVENT_NETWORK_ACCESS)
    {
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
    }

    status = WinVerifyTrust_I(INVALID_HANDLE_VALUE, ActionId, &trustData);
    PhpGetSignaturesFromStateData(trustData.hWVTStateData, Signatures, NumberOfSignatures);

    //if (status == 0 && (Information->Flags & PH_VERIFY_VIEW_PROPERTIES))
    //    PhpViewSignerInfo(Information, trustData.hWVTStateData);

    // Close the state data.
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust_I(INVALID_HANDLE_VALUE, ActionId, &trustData);

    return PhpStatusToVerifyResult(status);
}

BOOLEAN PhpCalculateFileHash(
    _In_ HANDLE FileHandle,
    _In_ PWSTR HashAlgorithm,
    _Out_ PUCHAR* FileHash,
    _Out_ PULONG FileHashLength,
    _Out_ HANDLE* CatAdminHandle
)
{
    HANDLE catAdminHandle;
    PUCHAR fileHash;
    ULONG fileHashLength;

    if (CryptCATAdminAcquireContext2)
    {
        if (!CryptCATAdminAcquireContext2(&catAdminHandle, &DriverActionVerify, HashAlgorithm, NULL, 0))
            return FALSE;
    }
    else
    {
        if (!CryptCATAdminAcquireContext(&catAdminHandle, &DriverActionVerify, 0))
            return FALSE;
    }

    fileHashLength = 32;
    fileHash = new UCHAR[fileHashLength];

    if (CryptCATAdminCalcHashFromFileHandle2)
    {
        if (!CryptCATAdminCalcHashFromFileHandle2(catAdminHandle, FileHandle, &fileHashLength, fileHash, 0))
        {
            delete fileHash;
            fileHash = new UCHAR[fileHashLength];

            if (!CryptCATAdminCalcHashFromFileHandle2(catAdminHandle, FileHandle, &fileHashLength, fileHash, 0))
            {
                CryptCATAdminReleaseContext(catAdminHandle, 0);
                delete fileHash;
                return FALSE;
            }
        }
    }
    else
    {
        if (!CryptCATAdminCalcHashFromFileHandle(FileHandle, &fileHashLength, fileHash, 0))
        {
            delete fileHash;
            fileHash = new UCHAR[fileHashLength];

            if (!CryptCATAdminCalcHashFromFileHandle(FileHandle, &fileHashLength, fileHash, 0))
            {
                CryptCATAdminReleaseContext(catAdminHandle, 0);
                delete fileHash;
                return FALSE;
            }
        }
    }

    *FileHash = fileHash;
    *FileHashLength = fileHashLength;
    *CatAdminHandle = catAdminHandle;

    return TRUE;
}

VERIFY_RESULT PhpVerifyFileFromCatalog(
    _In_ PPH_VERIFY_FILE_INFO Information,
    _In_ HANDLE FileHandle,
    _In_opt_ PWSTR HashAlgorithm,
    _Out_ PCERT_CONTEXT **Signatures,
    _Out_ PULONG NumberOfSignatures
    )
{
    VERIFY_RESULT verifyResult = VrNoSignature;
    PCERT_CONTEXT *signatures;
    ULONG numberOfSignatures;
    WINTRUST_CATALOG_INFO catalogInfo = { 0 };
    LARGE_INTEGER fileSize;
    ULONG fileSizeLimit;
    PUCHAR fileHash;
    ULONG fileHashLength;
    std::wstring fileHashTag;
    HANDLE catAdminHandle;
    HANDLE catInfoHandle;
    ULONG i;

    *Signatures = NULL;
    *NumberOfSignatures = 0;

    fileSize.LowPart = GetFileSize(FileHandle, (DWORD*)&fileSize.HighPart);
    if (fileSize.QuadPart == 0)
        return VrNoSignature;

    signatures = NULL;
    numberOfSignatures = 0;

    if (Information->FileSizeLimitForHash != -1)
    {
        fileSizeLimit = PH_VERIFY_DEFAULT_SIZE_LIMIT;

        if (Information->FileSizeLimitForHash != 0)
            fileSizeLimit = Information->FileSizeLimitForHash;

        if (fileSize.QuadPart > fileSizeLimit)
            return VrNoSignature;
    }

    if (PhpCalculateFileHash(FileHandle, HashAlgorithm, &fileHash, &fileHashLength, &catAdminHandle))
    {
        //fileHashTag = PhBufferToHexStringEx(fileHash, fileHashLength, TRUE);

        // Search the system catalogs.

        catInfoHandle = CryptCATAdminEnumCatalogFromHash(
            catAdminHandle,
            fileHash,
            fileHashLength,
            0,
            NULL
            );

        if (catInfoHandle)
        {
            CATALOG_INFO ci = { 0 };
            DRIVER_VER_INFO verInfo = { 0 };

            if (CryptCATCatalogInfoFromContext(catInfoHandle, &ci, 0))
            {
                // Disable OS version checking by passing in a DRIVER_VER_INFO structure.
                verInfo.cbStruct = sizeof(DRIVER_VER_INFO);

                catalogInfo.cbStruct = sizeof(catalogInfo);
                catalogInfo.pcwszCatalogFilePath = ci.wszCatalogFile;
                catalogInfo.pcwszMemberFilePath = Information->FileName;
                catalogInfo.hMemberFile = FileHandle;
                catalogInfo.pcwszMemberTag = fileHashTag.c_str();
                catalogInfo.pbCalculatedFileHash = fileHash;
                catalogInfo.cbCalculatedFileHash = fileHashLength;
                //catalogInfo.hCatAdmin = catAdminHandle;
                verifyResult = PhpVerifyFile(Information, WTD_CHOICE_CATALOG, &catalogInfo, &DriverActionVerify, &verInfo, &signatures, &numberOfSignatures);

                if (verInfo.pcSignerCertContext)
                    CertFreeCertificateContext_I(verInfo.pcSignerCertContext);
            }

            CryptCATAdminReleaseCatalogContext(catAdminHandle, catInfoHandle, 0);
        }
        else
        {
            // Search any user-supplied catalogs.

            for (i = 0; i < Information->NumberOfCatalogFileNames; i++)
            {
                PhFreeVerifySignatures(signatures, numberOfSignatures);

                catalogInfo.cbStruct = sizeof(catalogInfo);
                catalogInfo.pcwszCatalogFilePath = Information->CatalogFileNames[i];
                catalogInfo.pcwszMemberFilePath = Information->FileName;
                catalogInfo.hMemberFile = FileHandle;
                catalogInfo.pcwszMemberTag = fileHashTag.c_str();
                catalogInfo.pbCalculatedFileHash = fileHash;
                catalogInfo.cbCalculatedFileHash = fileHashLength;
                //catalogInfo.hCatAdmin = catAdminHandle;
                verifyResult = PhpVerifyFile(Information, WTD_CHOICE_CATALOG, &catalogInfo, &WinTrustActionGenericVerifyV2, NULL, &signatures, &numberOfSignatures);

                if (verifyResult == VrTrusted)
                    break;
            }
        }
        
        delete fileHash;
        CryptCATAdminReleaseContext(catAdminHandle, 0);
    }

    *Signatures = signatures;
    *NumberOfSignatures = numberOfSignatures;

    return verifyResult;
}

NTSTATUS PhVerifyFileEx(
    _In_ PPH_VERIFY_FILE_INFO Information,
    _Out_ VERIFY_RESULT *VerifyResult,
    _Out_opt_ PCERT_CONTEXT **Signatures,
    _Out_opt_ PULONG NumberOfSignatures,
    DWORD SignMask
    )
{
    NTSTATUS status;
    HANDLE fileHandle;
    VERIFY_RESULT verifyResult = VrNoSignature;
    PCERT_CONTEXT *signatures = nullptr;
    ULONG numberOfSignatures = 0;
    WINTRUST_FILE_INFO fileInfo = { 0 }; 

    // Make sure we have successfully imported the required functions.
    if (
        !CryptCATAdminCalcHashFromFileHandle ||
        !CryptCATAdminAcquireContext ||
        !CryptCATAdminEnumCatalogFromHash ||
        !CryptCATCatalogInfoFromContext ||
        !CryptCATAdminReleaseCatalogContext ||
        !CryptCATAdminReleaseContext ||
        !WinVerifyTrust_I ||
        !WTHelperProvDataFromStateData_I ||
        !WTHelperGetProvSignerFromChain_I ||
        !CertNameToStr_I ||
        !CertDuplicateCertificateContext_I ||
        !CertFreeCertificateContext_I
        )
        return -1;

    fileHandle = CreateFile(Information->FileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = Information->FileName;
    fileInfo.hFile = fileHandle;

    if (SignMask & PhVerify_PE_SING)
    {
        verifyResult = PhpVerifyFile(Information, WTD_CHOICE_FILE, &fileInfo, &WinTrustActionGenericVerifyV2, NULL, &signatures, &numberOfSignatures);
    }
    if (SignMask & PhVerify_CAT_SING)
    {
        if (verifyResult == VrNoSignature)
        {
            if (CryptCATAdminAcquireContext2 && CryptCATAdminCalcHashFromFileHandle2)
            {
                PhFreeVerifySignatures(signatures, numberOfSignatures);
                verifyResult = PhpVerifyFileFromCatalog(Information, fileHandle, BCRYPT_SHA256_ALGORITHM, &signatures, &numberOfSignatures);
            }

            if (verifyResult != VrTrusted)
            {
                PhFreeVerifySignatures(signatures, numberOfSignatures);
                verifyResult = PhpVerifyFileFromCatalog(Information, fileHandle, NULL, &signatures, &numberOfSignatures);
            }
        }
    }

    *VerifyResult = verifyResult;

    if (Signatures)
        *Signatures = signatures;
    else
        PhFreeVerifySignatures(signatures, numberOfSignatures);

    if (NumberOfSignatures)
        *NumberOfSignatures = numberOfSignatures;

    CloseHandle(fileHandle);

    return STATUS_SUCCESS;
}

VOID PhFreeVerifySignatures(
    _In_ PCERT_CONTEXT* Signatures,
    _In_ ULONG NumberOfSignatures
)
{
    ULONG i;

    if (Signatures)
    {
        for (i = 0; i < NumberOfSignatures; i++)
            CertFreeCertificateContext_I(Signatures[i]);

        free(Signatures);
    }
}

std::wstring PhpGetCertNameString(
    _In_ PCERT_NAME_BLOB Blob
    )
{
    std::wstring string;
    ULONG bufferSize;

    // CertNameToStr doesn't give us the correct buffer size unless we don't provide a buffer at
    // all.
    bufferSize = CertNameToStr_I(
        X509_ASN_ENCODING,
        Blob,
        CERT_X500_NAME_STR,
        NULL,
        0
        );
    string.reserve(bufferSize+1);
    
    CertNameToStr_I(
        X509_ASN_ENCODING,
        Blob,
        CERT_X500_NAME_STR,
        (LPWSTR)string.data(),
        bufferSize
        );        
    string = string.data();
    return string;
}

std::wstring PhpGetX500Value(
    _In_ std::wstring& String,
    _In_ const std::wstring& KeyName
    )
{
    std::wstring value;
    size_t pos = String.find(KeyName);
    do 
    {
        if (pos == std::wstring::npos)
        {
            break;
        }
        pos += KeyName.length();
        size_t end_pos = String.find(L",", pos);
        value = String.substr(pos, end_pos - pos);
    } while (false);
    
    return value;
}

std::wstring PhGetSignerNameFromCertificate(
    _In_ PCERT_CONTEXT Certificate
    )
{
    PCERT_INFO certInfo;
    std::wstring keyName;
    std::wstring name;
    std::wstring value;

    // Cert context -> Cert info

    certInfo = Certificate->pCertInfo;

    if (!certInfo)
        return value;

    // Cert info subject -> Subject X.500 string

    name = PhpGetCertNameString(&certInfo->Subject);

    // Subject X.500 string -> CN or OU value
    
    value = PhpGetX500Value(name, L"CN=");

    if (value.empty())
    {        
        value = PhpGetX500Value(name, L"OU=");
    }
    
    return value;
}

///**
// * Verifies a file's digital signature.
// *
// * \param FileName A file name.
// * \param SignerName A variable which receives a pointer to a string containing the signer name. You
// * must free the string using PhDereferenceObject() when you no longer need it. Note that the signer
// * name may be NULL if it is not valid.
// *
// * \return A VERIFY_RESULT value.
// */
VERIFY_RESULT PhVerifyFile(
    _In_ PCWSTR FileName,
    _Out_opt_  std::wstring& SignerName,
    DWORD SignMask
)
{
    
    PH_VERIFY_FILE_INFO info = { 0 };
    VERIFY_RESULT verifyResult;
    PCERT_CONTEXT* signatures;
    ULONG numberOfSignatures;

    info.FileName = FileName;
    info.Flags = PH_VERIFY_PREVENT_NETWORK_ACCESS;

    if ((PhVerifyFileEx(&info, &verifyResult, &signatures, &numberOfSignatures, SignMask)) >= 0)
    {
        if (numberOfSignatures != 0)
            SignerName = PhGetSignerNameFromCertificate(signatures[0]);
        
        PhFreeVerifySignatures(signatures, numberOfSignatures);
        return verifyResult;
    }
    else
    {       

        return VrNoSignature;
    }
}
