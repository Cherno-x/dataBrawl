#pragma once

#include <Windows.h>

class VenvChecker {
public:
    static BOOL IsVenvByHardwareCheck();

private:
    VenvChecker() = default;
};

BOOL VenvChecker::IsVenvByHardwareCheck() {
    SYSTEM_INFO SysInfo = { 0 };
    MEMORYSTATUSEX MemStatus = { sizeof(MEMORYSTATUSEX) };
    HKEY hKey = NULL;
    DWORD dwUsbNumber = 0;
    DWORD dwRegErr = 0;


    // CPU 检查
    GetSystemInfo(&SysInfo);

    // 处理器少于2个
    if (SysInfo.dwNumberOfProcessors < 2) {
        return TRUE;
    }

    // 内存检查
    if (!GlobalMemoryStatusEx(&MemStatus)) {
        return FALSE;
    }

    // 内存少于2GB
   if ((DWORD)MemStatus.ullTotalPhys < (DWORD)(2u * 1073741824u)) 
    {
        return TRUE;
    }

    // 检查曾经连接过的USB数量
    if ((dwRegErr = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", 0, KEY_READ, &hKey)) != ERROR_SUCCESS) {
        return FALSE;
    }

    if ((dwRegErr = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &dwUsbNumber, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) != ERROR_SUCCESS) {
        return FALSE;
    }

    // 曾经连接过的USB少于2个
    if (dwUsbNumber < 2) {
        return TRUE;
    }

    RegCloseKey(hKey);

    return FALSE;
}
