#include "pch.h"

int Main();
VOID PrintUsage(HANDLE hConsole);


// 自定义入口点
VOID Entry()
{
	ExitProcess(Main());
}

int Main() {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hConsole == INVALID_HANDLE_VALUE) {
		return 1;
	}

	LPWSTR* argv;
	INT argc;

	// 获取命令行参数
	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argv == NULL) {
		WriteConsoleW(hConsole, L"Failed to parse command line\n", 28, NULL, NULL);
		return 1;
	}

	// 解析命令行参数，现在需要至少5个参数（包括继承属性）
	if (argc < 5) {
		PrintUsage(hConsole);
		LocalFree(argv);
		return 1;
	}

	LPCWSTR objectTypeStr = argv[1];
	LPCWSTR objectPath = argv[2];
	LPCWSTR integrityLevel = argv[3];

	BOOL bEnable = FALSE; // 默认禁用
	if (wcscmp(argv[4], L"enable") == 0) {
		bEnable = TRUE;
	}
	else if (wcscmp(argv[4], L"disable") == 0) {
		bEnable = FALSE;
	}
	else {
		WriteConsoleW(hConsole, L"Invalid enable/disable option. Use 'enable' or 'disable'\n", 58, NULL, NULL);
		PrintUsage(hConsole);
		LocalFree(argv);
		return 1;
	}

	// 解析继承属性（第5个参数）
	BYTE inheritance = NO_INHERITANCE;
	if (argc > 5) {
		LPCWSTR inheritStr = argv[5];
		if (wcscmp(inheritStr, L"container") == 0) {
			inheritance = CONTAINER_INHERIT_ACE;
		}
		else if (wcscmp(inheritStr, L"object") == 0) {
			inheritance = OBJECT_INHERIT_ACE;
		}
		else if (wcscmp(inheritStr, L"both") == 0) {
			inheritance = (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE);
		}
		else if (wcscmp(inheritStr, L"none") == 0) {
			inheritance = NO_INHERITANCE;
		}
		else {
			WriteConsoleW(hConsole, L"Invalid inheritance option. Use: none, container, object, or both\n", 68, NULL, NULL);
			PrintUsage(hConsole);
			LocalFree(argv);
			return 1;
		}
	}

	// 解析对象类型
	SE_OBJECT_TYPE objectType;
	if (wcscmp(objectTypeStr, L"file") == 0 || wcscmp(objectTypeStr, L"FILE") == 0) {
		objectType = SE_FILE_OBJECT;
	}
	else if (wcscmp(objectTypeStr, L"registry") == 0 || wcscmp(objectTypeStr, L"REGISTRY") == 0 ||
		wcscmp(objectTypeStr, L"reg") == 0 || wcscmp(objectTypeStr, L"REG") == 0) {
		objectType = SE_REGISTRY_KEY;
	}
	else if (wcscmp(objectTypeStr, L"service") == 0 || wcscmp(objectTypeStr, L"SERVICE") == 0) {
		objectType = SE_SERVICE;
	}
	else if (wcscmp(objectTypeStr, L"printer") == 0 || wcscmp(objectTypeStr, L"PRINTER") == 0) {
		objectType = SE_PRINTER;
	}
	else if (wcscmp(objectTypeStr, L"kernel") == 0 || wcscmp(objectTypeStr, L"KERNEL") == 0) {
		objectType = SE_KERNEL_OBJECT;
	}
	else if (wcscmp(objectTypeStr, L"window") == 0 || wcscmp(objectTypeStr, L"WINDOW") == 0) {
		objectType = SE_WINDOW_OBJECT;
	}
	else if (wcscmp(objectTypeStr, L"ds") == 0 || wcscmp(objectTypeStr, L"DS") == 0 ||
		wcscmp(objectTypeStr, L"directory") == 0 || wcscmp(objectTypeStr, L"DIRECTORY") == 0) {
		objectType = SE_DS_OBJECT;
	}
	else {
		WriteConsoleW(hConsole, L"Unknown object type\n", 20, NULL, NULL);
		PrintUsage(hConsole);
		LocalFree(argv);
		return 1;
	}

	// 执行设置命令
	WCHAR buffer[1024];
	int len = wsprintfW(buffer, L"Setting integrity level for: %s\nObject type: %s\nIntegrity level: %s\nEnable: %s\n",
		objectPath, objectTypeStr, integrityLevel, bEnable ? L"true" : L"false");
	WriteConsoleW(hConsole, buffer, len, NULL, NULL);

	// 临时使用原函数并输出提示
	WriteConsoleW(hConsole, L"[NOTE: Actual implementation should use SetObjectIntegrityLevelEx]\n", 68, NULL, NULL);
	BOOL result = SetObjectIntegrity(objectPath, objectType, integrityLevel, bEnable, inheritance);

	if (result) {
		WriteConsoleW(hConsole, L"\nSUCCESS: Integrity level set operation completed!\n", 48, NULL, NULL);

		// 验证设置（仅对支持的对象类型）
		if (objectType == SE_REGISTRY_KEY || objectType == SE_FILE_OBJECT) {
			WriteConsoleW(hConsole, L"\nVerifying integrity level...\n", 29, NULL, NULL);

			PSECURITY_DESCRIPTOR pSD = NULL;
			PSID pOwner = NULL;
			PSID pGroup = NULL;
			PACL pDacl = NULL;
			PACL pSacl = NULL;

			DWORD dwError = GetNamedSecurityInfoW(
				(LPWSTR)objectPath,
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

							LPWSTR verifySidStr = NULL;
							if (ConvertSidToStringSidW(pVerifySid, &verifySidStr)) {
								len = wsprintfW(buffer, L"Verified integrity level: %s\n", verifySidStr);
								WriteConsoleW(hConsole, buffer, len, NULL, NULL);
								LocalFree(verifySidStr);
							}
							LocalFree(pVerifySid);
						}
					}
				}
				LocalFree(pSD);
			}
			else {
				len = wsprintfW(buffer, L"Note: Could not verify integrity level (error code: %lu)\n", dwError);
				WriteConsoleW(hConsole, buffer, len, NULL, NULL);
			}
		}
	}
	else {
		WriteConsoleW(hConsole, L"\nFAILED: Failed to set integrity level\n", 37, NULL, NULL);
	}
	LocalFree(argv);
	return 0;
}


// 打印使用说明
VOID PrintUsage(HANDLE hConsole) {
	LPCWSTR usage = L"\n=== Object Integrity Level Tool ===\n"
		L"\nUsage:\n"
		L" SetObjectIntegrity.exe <ObjectType> <ObjectPath> <IntegrityLevel> <enable|disable> [inheritance]\n"
		L"\nObject types:\n"
		L" file - File or directory (SE_FILE_OBJECT)\n"
		L" registry - Registry key (SE_REGISTRY_KEY)\n"
		L" service - Windows service (SE_SERVICE)\n"
		L" printer - Printer (SE_PRINTER)\n"
		L" kernel - Kernel object (SE_KERNEL_OBJECT)\n"
		L" window - Window station/desktop (SE_WINDOW_OBJECT)\n"
		L" ds - Directory service object (SE_DS_OBJECT)\n"
		L"\nIntegrity levels:\n"
		L" S-1-16-0 (Untrusted)\n"
		L" S-1-16-4096 (Low)\n"
		L" S-1-16-8192 (Medium)\n"
		L" S-1-16-12288 (High)\n"
		L" S-1-16-16384 (System)\n"
		L"\nEnable/Disable:\n"
		L" enable - Enable IntegrityLevel\n"
		L" disable - Disable IntegrityLevel\n"
		L"\nInheritance options (optional):\n"
		L" none - no inherit\n"
		L" container - container inherit\n"
		L" object - object inherit\n"
		L" both - container inherit and object inherit\n"
		L"\nExamples:\n"
		L" SetObjectIntegrity.exe file C:\\Temp\\test.txt S-1-16-4096 enable none\n"
		L" SetObjectIntegrity.exe registry CURRENT_USER\\Software\\MyApp S-1-16-8192 disable container\n"
		L" SetObjectIntegrity.exe service MyService S-1-16-12288 enable both\n"
		L"=================================================================\n";
	DWORD len = 0;
	while (usage[len]) len++;
	WriteConsoleW(hConsole, usage, len, NULL, NULL);
}
