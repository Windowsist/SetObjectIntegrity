#include "pch.h"

BOOL SetObjectIntegrity(
	LPCWSTR objectPath,
	SE_OBJECT_TYPE objectType,
	LPCWSTR integrityLevel,
	BOOL bEnable, // 是否启用完整性级别
	BYTE inheritance // 继承属性
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
		return FALSE;
	}

	// 创建 ACE
	dwAceSize = sizeof(SYSTEM_MANDATORY_LABEL_ACE) + GetLengthSid(pIntegritySid) - sizeof(DWORD);
	pAce = (PSYSTEM_MANDATORY_LABEL_ACE)LocalAlloc(LPTR, dwAceSize);
	if (!pAce) {
		LocalFree(pIntegritySid);
		return FALSE;
	}

	pAce->Header.AceType = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
	// 根据继承属性设置AceFlags
	pAce->Header.AceFlags = inheritance;
	pAce->Header.AceSize = (WORD)dwAceSize;
	pAce->Mask = aceMask; // 使用新的aceMask
	CopySid(GetLengthSid(pIntegritySid), &pAce->SidStart, pIntegritySid);

	// 创建 SACL
	dwNewSaclSize = sizeof(ACL) + dwAceSize;
	pNewSacl = (PACL)LocalAlloc(LPTR, dwNewSaclSize);
	if (!pNewSacl) {
		LocalFree(pAce);
		LocalFree(pIntegritySid);
		return FALSE;
	}

	if (!InitializeAcl(pNewSacl, dwNewSaclSize, ACL_REVISION)) {
		LocalFree(pAce);
		LocalFree(pNewSacl);
		LocalFree(pIntegritySid);
		return FALSE;
	}

	if (!AddAce(pNewSacl, ACL_REVISION, 0, (LPVOID)pAce, dwAceSize)) {
		LocalFree(pAce);
		LocalFree(pNewSacl);
		LocalFree(pIntegritySid);
		return FALSE;
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

	LocalFree(pAce);
	LocalFree(pNewSacl);
	LocalFree(pIntegritySid);

	return dwError == ERROR_SUCCESS;
}
