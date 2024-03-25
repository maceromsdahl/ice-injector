/*

░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░      ░▒▓█▓▒░▒▓███████▓▒░       ░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓███████▓▒░  
░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░        ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░▒▓█▓▒░      ░▒▓██████▓▒░        ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓██████▓▒░░▒▓█▓▒░        ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░  
░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░        ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓████████▓▒░▒▓██████▓▒░  ░▒▓█▓▒░   ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
                                                                                                                                       
                                                                                                                                       
                                                               by mace                                                                       
                                                                                                                                       */

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>

// Function to find the process ID by name
DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

// Function to inject a DLL into the target process
bool InjectDll(DWORD processId, const wchar_t* dllPath) {
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (process == NULL) {
        std::cerr << "Failed to open process" << std::endl;
        return false;
    }

    LPVOID dllPathAddr = VirtualAllocEx(process, NULL, wcslen(dllPath) * sizeof(wchar_t) + sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    if (dllPathAddr == NULL) {
        std::cerr << "Failed to allocate memory in the remote process" << std::endl;
        CloseHandle(process);
        return false;
    }

    if (!WriteProcessMemory(process, dllPathAddr, dllPath, wcslen(dllPath) * sizeof(wchar_t) + sizeof(wchar_t), NULL)) {
        std::cerr << "Failed to write to process memory" << std::endl;
        VirtualFreeEx(process, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
    if (kernel32 == NULL) {
        std::cerr << "Failed to get handle to kernel32.dll" << std::endl;
        VirtualFreeEx(process, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    LPTHREAD_START_ROUTINE loadLibraryAddr = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(kernel32, "LoadLibraryW"));
    if (loadLibraryAddr == NULL) {
        std::cerr << "Failed to get address of LoadLibraryW function" << std::endl;
        VirtualFreeEx(process, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    HANDLE remoteThread = CreateRemoteThread(process, NULL, 0, loadLibraryAddr, dllPathAddr, 0, NULL);
    if (remoteThread == NULL) {
        std::cerr << "Failed to create remote thread" << std::endl;
        VirtualFreeEx(process, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(process);
        return false;
    }

    WaitForSingleObject(remoteThread, INFINITE);

    VirtualFreeEx(process, dllPathAddr, 0, MEM_RELEASE);
    CloseHandle(remoteThread);
    CloseHandle(process);
    return true;
}

int main() {
    std::wstring processName;
    std::wstring dllPath;

    std::wcout << L"P: ";
    std::getline(std::wcin, processName);

    std::wcout << L"D: ";
    std::getline(std::wcin, dllPath);

    DWORD processId = GetProcessIdByName(processName.c_str());
    if (processId == 0) {
        std::cerr << "Failed to find process ID" << std::endl;
        return 1;
    }

    if (!InjectDll(processId, dllPath.c_str())) {
        std::cerr << "Failed to inject DLL" << std::endl;
        return 1;
    }

    std::wcout << L"DLL injected successfully" << std::endl;
    return 0;
}
