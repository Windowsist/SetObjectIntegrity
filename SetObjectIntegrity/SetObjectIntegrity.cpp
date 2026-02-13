#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <iostream>
#include <string>

// 函数声明
BOOL SetObjectIntegrityLevel(
    LPCWSTR objectPath,
    SE_OBJECT_TYPE objectType,
    LPCWSTR integrityLevel,
    BOOL bEnable,                     // 是否启用完整性级别
    byte inheritance  // 继承属性
);
BOOL EnablePrivilege(LPCWSTR privilegeName);
void PrintUsage();
BOOL ConvertSidToString(PSID pSid, std::wstring& strSid);

int wmain(int argc, wchar_t* argv[]) {
    // 解析命令行参数，现在需要至少5个参数（包括继承属性）
    if (argc < 5) {
        PrintUsage();
        return 1;
    }

    std::wstring objectTypeStr = argv[1];
    std::wstring objectPath = argv[2];
    std::wstring integrityLevel = argv[3];

    BOOL bEnable = FALSE; // 默认禁用
    if (wcscmp(argv[4], L"enable") == 0) {
        bEnable = TRUE;
    }
    else if (wcscmp(argv[4], L"disable") == 0) {
        bEnable = FALSE;
    }
    else {
        std::wcerr << L"Invalid enable/disable option. Use 'enable' or 'disable'" << std::endl;
        PrintUsage();
        return 1;
    }

    // 解析继承属性（第5个参数）
    byte inheritance = NO_INHERITANCE;
    if (argc > 5) {
        std::wstring inheritStr = argv[5];
        if (inheritStr == L"container") {
            inheritance = CONTAINER_INHERIT_ACE;
        }
        else if (inheritStr == L"object") {
            inheritance = OBJECT_INHERIT_ACE;
        }
        else if (inheritStr == L"both") {
            inheritance = (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE);
        }
        else if (inheritStr == L"none") {
            inheritance = NO_INHERITANCE;
        }
        else {
            std::wcerr << L"Invalid inheritance option. Use: none, container, object, or both" << std::endl;
            PrintUsage();
            return 1;
        }
    }

    // 解析对象类型
    SE_OBJECT_TYPE objectType;
    if (objectTypeStr == L"file" || objectTypeStr == L"FILE") {
        objectType = SE_FILE_OBJECT;
    }
    else if (objectTypeStr == L"registry" || objectTypeStr == L"REGISTRY" ||
        objectTypeStr == L"reg" || objectTypeStr == L"REG") {
        objectType = SE_REGISTRY_KEY;
    }
    else if (objectTypeStr == L"service" || objectTypeStr == L"SERVICE") {
        objectType = SE_SERVICE;
    }
    else if (objectTypeStr == L"printer" || objectTypeStr == L"PRINTER") {
        objectType = SE_PRINTER;
    }
    else if (objectTypeStr == L"kernel" || objectTypeStr == L"KERNEL") {
        objectType = SE_KERNEL_OBJECT;
    }
    else if (objectTypeStr == L"window" || objectTypeStr == L"WINDOW") {
        objectType = SE_WINDOW_OBJECT;
    }
    else if (objectTypeStr == L"ds" || objectTypeStr == L"DS" ||
        objectTypeStr == L"directory" || objectTypeStr == L"DIRECTORY") {
        objectType = SE_DS_OBJECT;
    }
    else {
        std::wcerr << L"Unknown object type: " << objectTypeStr << std::endl;
        PrintUsage();
        return 1;
    }

    // 执行设置命令
    std::wcout << L"Setting integrity level for: " << objectPath << std::endl;
    std::wcout << L"Object type: " << objectTypeStr << std::endl;
    std::wcout << L"Integrity level: " << integrityLevel << std::endl;
    std::wcout << L"Enable: " << (bEnable ? L"true" : L"false") << std::endl;

    // 这里需要实现一个支持继承和启用的SetObjectIntegrityLevelEx函数
    // 由于原SetObjectIntegrityLevel不支持这些功能，我们需要假设有一个新版本
    // 以下是伪代码/调用示例：
    /*
    BOOL result = SetObjectIntegrityLevelEx(
        objectPath.c_str(),
        objectType,
        integrityLevel.c_str(),
        bEnable,
        inheritance
    );
    */

    // 临时使用原函数并输出提示
    std::wcout << L"[NOTE: Actual implementation should use SetObjectIntegrityLevelEx]" << std::endl;
    BOOL result = SetObjectIntegrityLevel(objectPath.c_str(), objectType, integrityLevel.c_str(), bEnable, inheritance);

    if (result) {
        std::wcout << L"\nSUCCESS: Integrity level set operation completed!" << std::endl;

        // 验证设置（仅对支持的对象类型）
        if (objectType == SE_REGISTRY_KEY || objectType == SE_FILE_OBJECT) {
            std::wcout << L"\nVerifying integrity level..." << std::endl;

            PSECURITY_DESCRIPTOR pSD = NULL;
            PSID pOwner = NULL;
            PSID pGroup = NULL;
            PACL pDacl = NULL;
            PACL pSacl = NULL;

            DWORD dwError = GetNamedSecurityInfoW(
                (LPWSTR)objectPath.c_str(),
                objectType,
                LABEL_SECURITY_INFORMATION,
                &pOwner,
                &pGroup,
                &pDacl,
                &pSacl,
                &pSD
            );

            if (dwError == ERROR_SUCCESS && pSacl) {
                LPVOID pAce = NULL;
                if (GetAce(pSacl, 0, &pAce)) {
                    PSYSTEM_MANDATORY_LABEL_ACE pLabelAce = (PSYSTEM_MANDATORY_LABEL_ACE)pAce;
                    if (pLabelAce->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
                        PSID pVerifySid = (PSID)LocalAlloc(LPTR, GetLengthSid(&pLabelAce->SidStart));
                        if (pVerifySid) {
                            CopySid(GetLengthSid(&pLabelAce->SidStart), pVerifySid, &pLabelAce->SidStart);

                            std::wstring verifySidStr;
                            if (ConvertSidToString(pVerifySid, verifySidStr)) {
                                std::wcout << L"Verified integrity level: " << verifySidStr << std::endl;
                                if (verifySidStr == integrityLevel) {
                                    std::wcout << L"VERIFICATION: SID matches expected value!" << std::endl;
                                }
                                else {
                                    std::wcout << L"WARNING: SID doesn't match expected value!" << std::endl;
                                }
                            }
                            LocalFree(pVerifySid);
                        }
                    }
                }
                LocalFree(pSD);
            }
            else {
                std::wcout << L"Note: Could not verify integrity level (error code: " << dwError << L")" << std::endl;
            }
        }
    }
    else {
        std::wcerr << L"\nFAILED: Failed to set integrity level" << std::endl;
        return 1;
    }

    return 0;
}

// 新增函数：设置对象的完整性级别及其继承属性
BOOL SetObjectIntegrityLevel(
    LPCWSTR objectPath,
    SE_OBJECT_TYPE objectType,
    LPCWSTR integrityLevel,
    BOOL bEnable,                     // 是否启用完整性级别
    byte inheritance  // 继承属性
) {
    // 初始化所有指针为NULL
    PSID pIntegritySid = NULL;
    PSYSTEM_MANDATORY_LABEL_ACE pAce = NULL;
    PACL pNewSacl = NULL;

    DWORD dwError = 0;
    DWORD dwAceSize = 0;
    DWORD dwNewSaclSize = 0;
    BOOL bResult = FALSE;

    DWORD aceMask = bEnable ? SYSTEM_MANDATORY_LABEL_NO_WRITE_UP : 0; // 如果不启用，则设置Mask为0

    // 创建完整性级别SID
    if (!ConvertStringSidToSidW(integrityLevel, &pIntegritySid)) {
        std::wcerr << L"ConvertStringSidToSid failed for: " << integrityLevel << std::endl;
        goto cleanup;
    }

    // 根据是否启用完整性级别来设置ACE的Mask

    // 创建 ACE
    dwAceSize = sizeof(SYSTEM_MANDATORY_LABEL_ACE) + GetLengthSid(pIntegritySid) - sizeof(DWORD);
    pAce = (PSYSTEM_MANDATORY_LABEL_ACE)LocalAlloc(LPTR, dwAceSize);
    if (!pAce) {
        std::wcerr << L"LocalAlloc failed for ACE" << std::endl;
        goto cleanup;
    }

    pAce->Header.AceType = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
    // 根据继承属性设置AceFlags
    pAce->Header.AceFlags = inheritance;
    pAce->Header.AceSize = (WORD)dwAceSize;
    pAce->Mask = aceMask;  // 使用新的aceMask
    CopySid(GetLengthSid(pIntegritySid), &pAce->SidStart, pIntegritySid);

    // 创建 SACL
    dwNewSaclSize = sizeof(ACL) + dwAceSize;
    pNewSacl = (PACL)LocalAlloc(LPTR, dwNewSaclSize);
    if (!pNewSacl) {
        std::wcerr << L"LocalAlloc failed for new SACL" << std::endl;
        goto cleanup;
    }

    if (!InitializeAcl(pNewSacl, dwNewSaclSize, ACL_REVISION)) {
        std::wcerr << L"InitializeAcl failed" << std::endl;
        goto cleanup;
    }

    if (!AddAce(pNewSacl, ACL_REVISION, 0, (LPVOID)pAce, dwAceSize)) {
        std::wcerr << L"AddAce failed" << std::endl;
        goto cleanup;
    }

    // 使用 SetNamedSecurityInfoW 设置 SACL
    dwError = SetNamedSecurityInfoW(
        (LPWSTR)objectPath,
        objectType,
        LABEL_SECURITY_INFORMATION,
        NULL, // 所有者
        NULL, // 组
        NULL, // DACL
        pNewSacl // SACL
    );

    if (dwError == ERROR_SUCCESS) {
        bResult = TRUE;
    }
    else {
        std::wcerr << L"SetNamedSecurityInfoW failed with error: " << dwError << std::endl;
    }

cleanup:
    if (pAce) LocalFree(pAce);
    if (pNewSacl) LocalFree(pNewSacl);
    if (pIntegritySid) LocalFree(pIntegritySid);

    return bResult;
}


// 启用指定的权限
BOOL EnablePrivilege(LPCWSTR privilegeName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);

    return result;
}

// 将SID转换为字符串
BOOL ConvertSidToString(PSID pSid, std::wstring& strSid) {
    LPWSTR sidString = NULL;
    if (ConvertSidToStringSidW(pSid, &sidString)) {
        strSid = sidString;
        LocalFree(sidString);
        return TRUE;
    }
    return FALSE;
}
// 打印使用说明
void PrintUsage() {
    std::wcout << L"\n=== Object Integrity Level Tool ===" << std::endl;
    std::wcout << L"\nUsage:" << std::endl;
    std::wcout << L" SetObjectIntegrity.exe <ObjectType> <ObjectPath> <IntegrityLevel> <enable|disable> [inheritance]" << std::endl;
    std::wcout << L"\nObject types:" << std::endl;
    std::wcout << L" file - File or directory (SE_FILE_OBJECT)" << std::endl;
    std::wcout << L" registry - Registry key (SE_REGISTRY_KEY)" << std::endl;
    std::wcout << L" service - Windows service (SE_SERVICE)" << std::endl;
    std::wcout << L" printer - Printer (SE_PRINTER)" << std::endl;
    std::wcout << L" kernel - Kernel object (SE_KERNEL_OBJECT)" << std::endl;
    std::wcout << L" window - Window station/desktop (SE_WINDOW_OBJECT)" << std::endl;
    std::wcout << L" ds - Directory service object (SE_DS_OBJECT)" << std::endl;
    std::wcout << L"\nIntegrity levels:" << std::endl;
    std::wcout << L" S-1-16-0 (Untrusted)" << std::endl;
    std::wcout << L" S-1-16-4096 (Low)" << std::endl;
    std::wcout << L" S-1-16-8192 (Medium)" << std::endl;
    std::wcout << L" S-1-16-12288 (High)" << std::endl;
    std::wcout << L" S-1-16-16384 (System)" << std::endl;
    std::wcout << L"\nEnable/Disable:" << std::endl;
    std::wcout << L" enable - Enable IntegrityLevel" << std::endl;
    std::wcout << L" disable - Disable IntegrityLevel" << std::endl;
    std::wcout << L"\nInheritance options (optional):" << std::endl;
    std::wcout << L" none - no inherit" << std::endl;
    std::wcout << L" container - container inherit" << std::endl;
    std::wcout << L" object - object inherit" << std::endl;
    std::wcout << L" both - container inherit and object inherit" << std::endl;
    std::wcout << L"\nExamples:" << std::endl;
    std::wcout << L" SetObjectIntegrity.exe file C:\\Temp\\test.txt S-1-16-4096 enable none" << std::endl;
    std::wcout << L" SetObjectIntegrity.exe registry CURRENT_USER\\Software\\MyApp S-1-16-8192 disable container" << std::endl;
    std::wcout << L" SetObjectIntegrity.exe service MyService S-1-16-12288 enable both" << std::endl;
    std::wcout << L"=================================================================\n" << std::endl;
}