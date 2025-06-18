#include <windows.h>
#include <iostream>
#include <string>
#include <comdef.h>
#include <netfw.h>
#include <psapi.h>
#include <winnt.h>
#include <Wbemidl.h>
#include <iomanip>
#include <tlhelp32.h>
#include <shlobj.h>
#include <fstream>
#include <winreg.h>
#include <fcntl.h>   
#include <io.h>     
#include <conio.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wbemuuid.lib")

#define COLOR_RESET        L"\x1b[0m"
#define COLOR_HEADER       L"\x1b[38;5;117m"
#define COLOR_LABEL        L"\x1b[38;5;221m"
#define COLOR_SYSTEM_LABEL L"\x1b[38;5;182m"
#define COLOR_GREEN        L"\x1b[38;5;120m"
#define COLOR_RED          L"\x1b[38;5;203m"
#define COLOR_GRAY         L"\x1b[38;5;250m"
#define COLOR_LINK         L"\x1b[38;5;111m"
#define COLOR_BANNER       L"\x1b[38;2;255;224;1m"

std::wstring FormatStatusText(const std::wstring& value) {
    if (value == L"Enabled")     return COLOR_GREEN + value + COLOR_RESET;
    if (value == L"Disabled")    return COLOR_RED + value + COLOR_RESET;
    if (value == L"Unavailable") return COLOR_GRAY + value + COLOR_RESET;
    return value;
}

typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

// ===== SYSTEM INFORMATION =====

bool GetWindowsVersion(DWORD& major, DWORD& minor, DWORD& build) {
    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    if (!hMod) return false;

    RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
    if (!fxPtr) return false;

    RTL_OSVERSIONINFOW rovi = { 0 };
    rovi.dwOSVersionInfoSize = sizeof(rovi);
    if (fxPtr(&rovi) != 0) return false;

    major = rovi.dwMajorVersion;
    minor = rovi.dwMinorVersion;
    build = rovi.dwBuildNumber;
    return true;
}

DWORD GetUBR() {
    HKEY hKey;
    DWORD ubr = 0;
    DWORD size = sizeof(ubr);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        RegQueryValueExW(hKey, L"UBR", nullptr, nullptr, (LPBYTE)&ubr, &size);
        RegCloseKey(hKey);
    }
    return ubr;
}

std::wstring GetDisplayVersion() {
    HKEY hKey;
    wchar_t value[128];
    DWORD size = sizeof(value);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        // Сначала пытаемся получить DisplayVersion (для 20H2+)
        if (RegQueryValueExW(hKey, L"DisplayVersion", nullptr, nullptr,
            (LPBYTE)value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return value;
        }

        // Если DisplayVersion нет, пробуем ReleaseId (для <= 2004)
        size = sizeof(value); // сброс размера буфера
        if (RegQueryValueExW(hKey, L"ReleaseId", nullptr, nullptr,
            (LPBYTE)value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return value;
        }

        RegCloseKey(hKey);
    }

    return L"Unavailable";
}

std::wstring GetWindowsEdition(DWORD major, DWORD minor, DWORD build) {
    std::wstring base;

    if (major == 10 && build >= 22000) base = L"Windows 11";
    else if (major == 10)              base = L"Windows 10";
    else if (major == 6 && minor == 3) return L"Windows 8.1";
    else if (major == 6 && minor == 2) return L"Windows 8";
    else if (major == 6 && minor == 1) return L"Windows 7";
    else return L"Unknown";

    // Только для Windows 10 и 11: уточняем редакцию
    DWORD sku = 0;
    if (GetProductInfo(major, minor, 0, 0, &sku)) {
        if (base == L"Windows 10" || base == L"Windows 11") {
            switch (sku) {
            case PRODUCT_PROFESSIONAL:         base += L" Pro"; break;
            case PRODUCT_CORE:                 base += L" Home"; break;
            case PRODUCT_ENTERPRISE:           base += L" Enterprise"; break;
            case PRODUCT_EDUCATION:            base += L" Education"; break;
            case PRODUCT_CORE_COUNTRYSPECIFIC: base += L" Home (Single Language)"; break;
            case PRODUCT_PROFESSIONAL_N:       base += L" Pro N"; break;
            default: base += L" (SKU=" + std::to_wstring(sku) + L")"; break;
            }
        }
    }

    return base;
}

// ===== SECURITY CHECKS =====

std::wstring CheckRegistryDWORD(HKEY root, const std::wstring& path, const std::wstring& name) {
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(value);

    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, name.c_str(), nullptr, nullptr, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return value ? L"Enabled" : L"Disabled";
        }
        RegCloseKey(hKey);
    }
    return L"Unavailable";
}

std::wstring GetSecureBootStatusFromPowerShell() {
    // Команда PowerShell для проверки состояния Secure Boot
    const wchar_t* cmd = L"powershell -Command \"Confirm-SecureBootUEFI\"";

    // Буфер для чтения вывода
    wchar_t buffer[128];
    std::wstring result = L"Unavailable";

    // Открытие процесса PowerShell
    FILE* pipe = _wpopen(cmd, L"r");
    if (pipe) {
        // Чтение строки результата
        if (fgetws(buffer, sizeof(buffer) / sizeof(wchar_t), pipe)) {
            result = (wcsstr(buffer, L"True") != nullptr) ? L"Enabled" : L"Disabled";
        }
        fclose(pipe);
    }
    return result;
}

std::wstring CheckWindowsDefenderStatus() {
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager) return L"Unavailable";

    SC_HANDLE hService = OpenServiceW(scManager, L"WinDefend", SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(scManager);
        return L"Disabled";
    }

    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded = 0;

    BOOL success = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&status, sizeof(status), &bytesNeeded);

    CloseServiceHandle(hService);
    CloseServiceHandle(scManager);

    if (success) {
        return (status.dwCurrentState == SERVICE_RUNNING) ? L"Enabled" : L"Disabled";
    }
    return L"Unavailable";
}

std::wstring CheckFirewallStatus() {
    HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return L"Unavailable";

    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    std::wstring result = L"Unavailable";

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (SUCCEEDED(hr) && pNetFwPolicy2) {
        VARIANT_BOOL domainEnabled = VARIANT_FALSE;
        VARIANT_BOOL privateEnabled = VARIANT_FALSE;
        VARIANT_BOOL publicEnabled = VARIANT_FALSE;

        pNetFwPolicy2->get_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, &domainEnabled);
        pNetFwPolicy2->get_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, &privateEnabled);
        pNetFwPolicy2->get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, &publicEnabled);

        if (domainEnabled == VARIANT_TRUE ||
            privateEnabled == VARIANT_TRUE ||
            publicEnabled == VARIANT_TRUE) {
            result = L"Enabled";
        }
        else {
            result = L"Disabled";
        }

        pNetFwPolicy2->Release();
    }

    CoUninitialize();
    return result;
}

bool IsCFGEnabled(HMODULE module = nullptr) {
    if (!module) {
        module = GetModuleHandle(nullptr);  // Текущий EXE
        if (!module) return false;
    }

    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), module, &mi, sizeof(mi)))
        return false;

    BYTE* base = reinterpret_cast<BYTE*>(mi.lpBaseOfDll);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const auto& opt = nt->OptionalHeader;
    DWORD va = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    DWORD sz = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
    if (va == 0 || sz < sizeof(IMAGE_LOAD_CONFIG_DIRECTORY)) return false;

    auto cfg = reinterpret_cast<IMAGE_LOAD_CONFIG_DIRECTORY*>(base + va);
    const DWORD64 CFG_FLAG = 0x40000000ULL; // IMAGE_GUARD_CF_INSTRUMENTED

    return (cfg->GuardFlags & CFG_FLAG) != 0;
}

// ===== LIST OF UPDATES =====

void PrintInstalledUpdates() {
    HRESULT hres;

    // Инициализация COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::wcerr << L"Failed to initialize COM library." << std::endl;
        return;
    }

    // Установка безопасности
    hres = CoInitializeSecurity(
        nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);

    if (FAILED(hres)) {
        std::wcerr << L"Failed to initialize security." << std::endl;
        CoUninitialize();
        return;
    }

    IWbemLocator* pLocator = nullptr;
    hres = CoCreateInstance(
        CLSID_WbemLocator, nullptr,
        CLSCTX_INPROC_SERVER, IID_IWbemLocator,
        reinterpret_cast<void**>(&pLocator));

    if (FAILED(hres)) {
        std::wcerr << L"Failed to create IWbemLocator." << std::endl;
        CoUninitialize();
        return;
    }

    IWbemServices* pServices = nullptr;
    hres = pLocator->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        nullptr, nullptr, nullptr,
        0, nullptr, nullptr, &pServices);

    if (FAILED(hres)) {
        std::wcerr << L"Could not connect to WMI." << std::endl;
        pLocator->Release();
        CoUninitialize();
        return;
    }

    hres = CoSetProxyBlanket(
        pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE);

    if (FAILED(hres)) {
        std::wcerr << L"Could not set proxy blanket." << std::endl;
        pServices->Release();
        pLocator->Release();
        CoUninitialize();
        return;
    }

    IEnumWbemClassObject* pEnumerator = nullptr;
    hres = pServices->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_QuickFixEngineering"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator);

    if (FAILED(hres)) {
        std::wcerr << L"Query for updates failed." << std::endl;
        pServices->Release();
        pLocator->Release();
        CoUninitialize();
        return;
    }

    IWbemClassObject* pClassObject = nullptr;
    ULONG uReturn = 0;

    std::wcout << L"\n" << COLOR_HEADER << L"=== Installed Updates ===" << COLOR_RESET << std::endl;
    std::wcout << std::left
        << std::setw(20) << L"Source"
        << std::setw(20) << L"Description"
        << std::setw(15) << L"HotFixID"
        << std::setw(25) << L"InstalledBy"
        << L"InstalledOn" << std::endl;
    std::wcout << L"------              -----------         --------       -----------              -----------" << std::endl;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
        if (uReturn == 0) break;

        VARIANT vtSource, vtDescription, vtHotFixID, vtInstalledBy, vtInstalledOn;
        VariantInit(&vtSource); VariantInit(&vtDescription); VariantInit(&vtHotFixID);
        VariantInit(&vtInstalledBy); VariantInit(&vtInstalledOn);

        pClassObject->Get(L"CSName", 0, &vtSource, nullptr, nullptr);
        pClassObject->Get(L"Description", 0, &vtDescription, nullptr, nullptr);
        pClassObject->Get(L"HotFixID", 0, &vtHotFixID, nullptr, nullptr);
        pClassObject->Get(L"InstalledBy", 0, &vtInstalledBy, nullptr, nullptr);
        pClassObject->Get(L"InstalledOn", 0, &vtInstalledOn, nullptr, nullptr);

        std::wcout.width(20); std::wcout << (vtSource.vt == VT_BSTR ? vtSource.bstrVal : L"");
        std::wcout.width(20); std::wcout << (vtDescription.vt == VT_BSTR ? vtDescription.bstrVal : L"");
        std::wcout.width(15); std::wcout << (vtHotFixID.vt == VT_BSTR ? vtHotFixID.bstrVal : L"");
        std::wcout.width(25); std::wcout << (vtInstalledBy.vt == VT_BSTR ? vtInstalledBy.bstrVal : L"");
        std::wcout << (vtInstalledOn.vt == VT_BSTR ? vtInstalledOn.bstrVal : L"") << std::endl;

        VariantClear(&vtSource);
        VariantClear(&vtDescription);
        VariantClear(&vtHotFixID);
        VariantClear(&vtInstalledBy);
        VariantClear(&vtInstalledOn);
        pClassObject->Release();
    }

    pEnumerator->Release();
    pServices->Release();
    pLocator->Release();
    CoUninitialize();
}

// ===== CLIENT CHECKER =====

bool FileExists(const std::wstring& path) {
    std::ifstream file(path);
    return file.good();
}

bool IsServiceInstalled(const std::wstring& serviceName) {
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager) return false;

    SC_HANDLE scService = OpenServiceW(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!scService) {
        CloseServiceHandle(scManager);
        return false;
    }

    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);
    return true;
}

bool IsProcessRunning(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return false;
}

bool CheckFACEITPresence(std::wstring& details) {
    bool foundAppData = false;
    bool foundProcess = false;
    bool foundRegistry = false;

    // 1. Проверка AppData\Local\FACEIT\FACEIT.exe
    wchar_t* appDataPath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &appDataPath))) {
        std::wstring faceitPath = std::wstring(appDataPath) + L"\\FACEIT\\FACEIT.exe";
        foundAppData = FileExists(faceitPath);
        CoTaskMemFree(appDataPath);
    }

    // 2. Проверка процесса
    foundProcess = IsProcessRunning(L"FACEIT.exe");

    // 3. Проверка реестра
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FACEIT", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t installPath[MAX_PATH];
        DWORD size = sizeof(installPath);
        DWORD type = 0;

        if (RegQueryValueExW(hKey, L"InstallLocation", nullptr, &type, (LPBYTE)&installPath, &size) == ERROR_SUCCESS && type == REG_SZ) {
            std::wstring fullPath = std::wstring(installPath) + L"\\FACEIT.exe";
            foundRegistry = FileExists(fullPath);
        }
        RegCloseKey(hKey);
    }

    // Составляем детальный вывод
    std::wstring result;
    if (foundAppData)  result += L"AppData, ";
    if (foundProcess)  result += L"Process, ";
    if (foundRegistry) result += L"Registry, ";

    if (!result.empty())
        result = result.substr(0, result.size() - 2); // убираем лишнюю запятую и пробел

    details = result;
    return foundAppData || foundProcess || foundRegistry;
}

bool CheckRiotVanguardPresence(std::wstring& details) {
    bool foundService = IsServiceInstalled(L"vgc");
    bool foundFile = FileExists(L"C:\\Program Files\\Riot Vanguard\\vgc.exe");
    bool foundProcess = IsProcessRunning(L"vgtray.exe");

    std::wstring result;

    if (foundFile)    result += L"File, ";
    if (foundProcess) result += L"Process, ";
    if (foundService) result += L"Service, ";

    // Убираем последнюю запятую и пробел, если есть
    if (!result.empty())
        result = result.substr(0, result.size() - 2);

    details = result;
    return foundService || foundFile || foundProcess;
}

// OTHER

void EnableVirtualTerminalProcessing() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

void ScrollConsoleToTop() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        SMALL_RECT newWindow = csbi.srWindow;
        newWindow.Top = 0;
        newWindow.Bottom = csbi.srWindow.Bottom - csbi.srWindow.Top;

        SetConsoleWindowInfo(hConsole, TRUE, &newWindow);
    }
}

// ===== MAIN =====

int main() {
    SetConsoleOutputCP(CP_UTF8);
    EnableVirtualTerminalProcessing();
    _setmode(_fileno(stdout), _O_U8TEXT);

    std::wcout << "\n";
    std::wcout << COLOR_BANNER <<
        L"██╗  ██╗███████╗██╗    ██╗███████╗████████╗ ██████╗ ██████╗ ███████╗\n"
        L"██║  ██║██╔════╝██║    ██║██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝\n"
        L"███████║█████╗  ██║ █╗ ██║███████╗   ██║   ██║   ██║██████╔╝█████╗  \n"
        L"██╔══██║██╔══╝  ██║███╗██║╚════██║   ██║   ██║   ██║██╔══██╗██╔══╝  \n"
        L"██║  ██║███████╗╚███╔███╔╝███████║   ██║   ╚██████╔╝██║  ██║███████╗\n"
        L"╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝\n"
        << COLOR_RESET << std::endl;


    DWORD major = 0, minor = 0, build = 0;

    if (!GetWindowsVersion(major, minor, build)) {
        std::wcerr << COLOR_RED << L"Failed to retrieve Windows version." << COLOR_RESET << std::endl;
        return 1;
    }

    DWORD ubr = GetUBR();
    std::wstring edition = GetWindowsEdition(major, minor, build);
    std::wstring currentBuild = std::to_wstring(build) + L"." + std::to_wstring(ubr);
    std::wstring displayVersion = GetDisplayVersion();

    std::wcout << COLOR_HEADER << L"=== System Information ===" << COLOR_RESET << std::endl;
    std::wcout << COLOR_SYSTEM_LABEL << L"Windows Edition:" << COLOR_RESET << L" " << edition << std::endl;
    std::wcout << COLOR_SYSTEM_LABEL << L"Current Build:" << COLOR_RESET << L" " << currentBuild << std::endl;
    std::wcout << COLOR_SYSTEM_LABEL << L"Windows Update Version:" << COLOR_RESET << L" " << displayVersion << std::endl;

    std::wcout << L"\n" << COLOR_HEADER << L"=== Security Settings ===" << COLOR_RESET << std::endl;

    std::wstring blocklist = CheckRegistryDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", L"VulnerableDriverBlocklistEnable");

    std::wstring defender = CheckWindowsDefenderStatus();

    std::wstring memoryIntegrity = CheckRegistryDWORD(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", L"Enabled");

    std::wstring secureBootStatus = GetSecureBootStatusFromPowerShell();

    std::wstring firewall = CheckFirewallStatus();
    bool cfgEnabled = IsCFGEnabled();

    std::wcout << COLOR_LABEL << L"Vulnerable Driver Blocklist:\n " << COLOR_RESET
        << L"- " << FormatStatusText(blocklist) << std::endl;
    std::wcout << COLOR_LABEL << L"Windows Defender:\n " << COLOR_RESET
        << L"- " << FormatStatusText(defender) << std::endl;
    std::wcout << COLOR_LABEL << L"Core Isolation (Memory Integrity):\n " << COLOR_RESET
        << L"- " << FormatStatusText(memoryIntegrity) << std::endl;
    std::wcout << COLOR_LABEL << L"Secure Boot:\n " << COLOR_RESET
        << L"- " << FormatStatusText(secureBootStatus) << std::endl;
    std::wcout << COLOR_LABEL << L"Firewall Status:\n " << COLOR_RESET
        << L"- " << FormatStatusText(firewall) << std::endl;
    std::wcout << COLOR_LABEL << L"Control Flow Guard (CFG):\n " << COLOR_RESET
        << L"- " << (cfgEnabled ? COLOR_GREEN L"Enabled" COLOR_RESET : COLOR_RED L"Disabled" COLOR_RESET) << std::endl;

    std::wcout << L"\n" << COLOR_HEADER << L"=== Gaming Clients ===" << COLOR_RESET << std::endl;

    std::wstring faceitDetails;
    bool faceitInstalled = CheckFACEITPresence(faceitDetails);
    std::wcout << COLOR_LABEL << L"Faceit Client Installed:\n " << COLOR_RESET
        << (faceitInstalled ? COLOR_GREEN L"+ True (" + faceitDetails + L")" COLOR_RESET
            : COLOR_RED L"- False" COLOR_RESET) << std::endl;

    std::wstring vanguardDetails;
    bool vanguardInstalled = CheckRiotVanguardPresence(vanguardDetails);
    std::wcout << COLOR_LABEL << L"Riot Vanguard Installed:\n " << COLOR_RESET
        << (vanguardInstalled ? COLOR_GREEN L"+ True (" + vanguardDetails + L")" COLOR_RESET
            : COLOR_RED L"- False" COLOR_RESET) << std::endl;

    PrintInstalledUpdates();

    std::wcout << L"\n" << COLOR_LABEL << L"=== Thanks for choosing HEWSTORE! ===" << COLOR_RESET << std::endl;
    std::wcout << L"Visit our website at: " << COLOR_LINK << L"hewstore.com" << COLOR_RESET << std::endl;

    ScrollConsoleToTop();

    _getch();
}