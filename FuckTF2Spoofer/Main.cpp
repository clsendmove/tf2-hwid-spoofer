#include <iostream>
#include <windows.h>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

void PrintDiskSerialNumbers() {
    HRESULT hres;

    // Initialize COM.
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library. Error code: " << std::hex << hres << std::endl;
        return;
    }

    // Set general COM security levels.
    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM negotiates service
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities
        NULL                         // Reserved
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to initialize security. Error code: " << std::hex << hres << std::endl;
        CoUninitialize();
        return;
    }

    // Obtain the initial locator to WMI.
    IWbemLocator* pLoc = nullptr;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object. Error code: " << std::hex << hres << std::endl;
        CoUninitialize();
        return;
    }

    // Connect to WMI through the IWbemLocator.
    IWbemServices* pSvc = nullptr;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // WMI namespace
        NULL,                    // User name
        NULL,                    // User password
        0,                       // Locale
        NULL,                    // Security flags
        0,                       // Authority
        0,                       // Context object
        &pSvc                    // IWbemServices proxy
    );

    if (FAILED(hres)) {
        std::cerr << "Could not connect. Error code: " << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return;
    }

    // Set security levels on the proxy.
    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres)) {
        std::cerr << "Could not set proxy blanket. Error code: " << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    // Use the IWbemServices pointer to make requests of WMI.
    IEnumWbemClassObject* pEnumerator = nullptr;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT SerialNumber FROM Win32_DiskDrive"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        std::cerr << "Query for disk drive serial numbers failed. Error code: " << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    // Retrieve the data from the query.
    IWbemClassObject* pClsObj = nullptr;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pClsObj, &uReturn);
        if (0 == uReturn) break;

        VARIANT vtProp;
        hr = pClsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
            std::wcout << vtProp.bstrVal << std::endl;
        }
        VariantClear(&vtProp);

        pClsObj->Release();
    }

    // Cleanup
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
}

bool RunusermodeHWIDSpoof() {
    // Get the current directory
    char currentDir[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, currentDir) == 0) {
        std::cerr << "Failed to get current directory." << std::endl;
        return false;
    }

    // Construct the path to the "stuff" folder
    std::string stuffDir = std::string(currentDir) + "\\stuff";

    // Change the current directory to the "stuff" folder
    if (SetCurrentDirectoryA(stuffDir.c_str()) == 0) {
        std::cerr << "Failed to change directory to 'stuff'. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Path to the executable
    const char* exePath = "RPZ-HWID.exe";
    const char* exePathTwo = "SpoofSerialNumber.bat";
    // Set up the process creation structure as STARTUPINFOA
    STARTUPINFOA si = { sizeof(si) }; // Use STARTUPINFOA for ANSI
    PROCESS_INFORMATION pi;

    // Create the process to run RPZ-HWID.exe
    if (!CreateProcessA(
        exePath,      // Executable name
        NULL,         // Command line arguments (NULL = none)
        NULL,         // Process security attributes
        NULL,         // Thread security attributes
        FALSE,        // Inherit handles
        0,            // Creation flags (0 = default)
        NULL,         // Environment block (NULL = use parent's)
        NULL,         // Current directory (NULL = use the current one)
        &si,          // STARTUPINFOA structure
        &pi           // PROCESS_INFORMATION structure
    )) {
        std::cerr << "Failed to start RPZ-HWID.exe. Error code: " << GetLastError() << std::endl;
        return false;
    }

    if (!CreateProcessA(
        exePathTwo,      // Executable name
        NULL,         // Command line arguments (NULL = none)
        NULL,         // Process security attributes
        NULL,         // Thread security attributes
        FALSE,        // Inherit handles
        0,            // Creation flags (0 = default)
        NULL,         // Environment block (NULL = use parent's)
        NULL,         // Current directory (NULL = use the current one)
        &si,          // STARTUPINFOA structure
        &pi           // PROCESS_INFORMATION structure
    )) {
        std::cerr << "Failed to start RPZ-HWID.exe. Error code: " << GetLastError() << std::endl;
        return false;
    }
    // Wait for the process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

bool KillProcessByName(const std::wstring& processName) {
    // Create a snapshot of all processes
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot of processes. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Set up the PROCESSENTRY32 structure
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process in the snapshot
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Failed to get first process. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcessSnap);
        return false;
    }

    // Loop through all processes
    do {
        // Compare the process name with the target process name
        if (processName == pe32.szExeFile) {
            // Open the process with termination rights
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if (hProcess == NULL) {
                std::cerr << "Failed to open process " << pe32.szExeFile << " for termination. Error code: " << GetLastError() << std::endl;
            }
            else {
                // Terminate the process
                if (TerminateProcess(hProcess, 0)) {
                    std::cout << "Successfully terminated " << pe32.szExeFile << std::endl;
                }
                else {
                    std::cerr << "Failed to terminate process " << pe32.szExeFile << ". Error code: " << GetLastError() << std::endl;
                }
                CloseHandle(hProcess);
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    // Clean up and close the snapshot handle
    CloseHandle(hProcessSnap);
    return true;
}

int main() {
    printf("[*] Killing Steam..");
    KillProcessByName(L"steam.exe");
    printf("[*] Made by Vannie. | ONLY WORKS ON WIN10+\n");
    printf("[*] Credz; Lydian Spoofer (for ssd/hdd serial number spoofer), SecHex.\n");
    printf("\n");
    printf("[*] Serial Numbers Before:\n");
    PrintDiskSerialNumbers();
    printf("[*] Spoofing..\n");
    RunusermodeHWIDSpoof();
    printf("[*] Spoofed!\n");
    printf("[*] Spoofed Serial Numbers:\n");
    PrintDiskSerialNumbers();
    return 0;
}
