#pragma once
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

BOOL SetObjectIntegrity(
	LPCWSTR objectPath,
	SE_OBJECT_TYPE objectType,
	LPCWSTR integrityLevel,
	BOOL bEnable, // 是否启用完整性级别
	BYTE inheritance // 继承属性
);