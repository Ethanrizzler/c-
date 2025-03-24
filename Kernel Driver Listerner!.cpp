#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <aclapi.h>

bool Admin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {

        if (CheckTokenMembership(NULL, adminGroup, &isAdmin) == 0) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    return (isAdmin == TRUE);
}

void Requestadmin() {
    if (Admin()) return;

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH); 

    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.lpVerb = L"runas"; 
    sei.lpFile = exePath;
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteEx(&sei)) {
        MessageBoxW(NULL, L"Permisson Denied", L"Reaper Cleint", MB_OK | MB_ICONERROR); 
        exit(1);
    }
    exit(0);
}

bool Defender() {
    HKEY hKey;
    DWORD data, dataSize = sizeof(data);

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueEx(hKey, L"DisableAntiSpyware", NULL, NULL, (LPBYTE)&data, &dataSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (data == 0); // 0 = Enabled, 1 = Disabled
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool UAC() {
    HKEY hKey;
    DWORD data, dataSize = sizeof(data);

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueEx(hKey, L"EnableLUA", NULL, NULL, (LPBYTE)&data, &dataSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (data == 1); 
        }
        RegCloseKey(hKey);
    }
    return false;
}


bool Firewall() {
    HKEY hKey;
    DWORD data, dataSize = sizeof(data);

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueEx(hKey, L"EnableFirewall", NULL, NULL, (LPBYTE)&data, &dataSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return (data == 1); 
        }
        RegCloseKey(hKey);
    }
    return false;
}

void Drivers() {
    std::cout << "\n=== Loaded Drivers ===\n";

    DWORD bytesNeeded;
    LPVOID drivers[1024];

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &bytesNeeded)) {
        std::cout << "[!] Failed to get driver list\n";
        MessageBoxW(NULL, L"Failed to Load Drivers", L"Reaper Cleint", MB_OK | MB_ICONERROR);
        return;
    }

    DWORD numDrivers = bytesNeeded / sizeof(drivers[0]);
    for (DWORD i = 0; i < numDrivers; i++) {
        WCHAR driverPath[MAX_PATH];
        if (GetDeviceDriverFileName(drivers[i], driverPath, MAX_PATH)) {
            std::wstring driverName = driverPath;
            if (driverName.find(L"\\System32") != std::wstring::npos || driverName.find(L"\\SysWOW64") != std::wstring::npos) {
                std::wcout << L"[Windows Driver] " << driverName << "\n";
            }
            else {
                std::wcout << L"[Custom Driver] " << driverName << "\n";
            }
        }
    }
}


void resolve() {
    std::cout << "\nFixing security issues...\n";
    MessageBoxW(NULL, L"Driver Loaded", L"Driver Information", MB_OK | MB_ICONINFORMATION);
    HKEY hKey;
    DWORD enable = 0;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, L"DisableAntiSpyware", 0, REG_DWORD, (const BYTE*)&enable, sizeof(enable));
        RegCloseKey(hKey);
        std::cout << "[?] Windows Defender enabled!\n";
    }
    else {
        std::cout << "[!] Failed to enable Windows Defender.\n";
    }

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD enableUAC = 1;
        RegSetValueEx(hKey, L"EnableLUA", 0, REG_DWORD, (const BYTE*)&enableUAC, sizeof(enableUAC));
        RegCloseKey(hKey);
        std::cout << "[?] UAC enabled\n";
    }
    else {
        std::cout << "[!] Failed to enable UAC.\n";
        MessageBoxW(NULL, L"Failed to enable UAC", L"Reaper Cleint", MB_OK | MB_ICONINFORMATION);
    }

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD enableFirewall = 1;
        RegSetValueEx(hKey, L"EnableFirewall", 0, REG_DWORD, (const BYTE*)&enableFirewall, sizeof(enableFirewall));
        RegCloseKey(hKey);
        std::cout << "[?] Windows Firewall enabled!\n";
    }
    else {
        std::cout << "[!] Failed to enable Windows Firewall.\n";
    }
}

void Security() {
    std::cout << "\n=== Reaper Security Checker ===\n";

    bool defender = Defender();
    bool uac = UAC();
    bool firewall = Firewall();

    std::wcout << L"[*] Windows Defender: " << (defender ? L"ON" : L"OFF") << "\n";
    std::wcout << L"[*] User Account Control (UAC): " << (uac ? L"ON " : L"OFF") << "\n";
    std::wcout << L"[*] Windows Firewall: " << (firewall ? L"ON" : L"OFF") << "\n";

    Drivers();

    std::cout << "\n[+] Do you want to fix security issues? (Y/N): ";
    char choice;
    std::cin >> choice;

    if (choice == 'Y' || choice == 'y') {
        resolve();
    }
    else {
        std::cout << "[-] Security issues not fixed.\n";
    }
}


int main() {
    Requestadmin();
    Security();

    std::cout << "\n[+]Do you want to rescan? (Y/N): ";
    char choice;
    std::cin >> choice;

    if (choice == 'Y' || choice == 'y') {
        system("cls");
        Security();
    }
    else {
        std::cout << "Exiting...\n";
    }

    return 0;
}
