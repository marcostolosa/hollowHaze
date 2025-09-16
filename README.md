# hollowHaze 

Este programa implementa uma técnica de injeção de código chamada Process Hollowing, que substitui o conteúdo de um processo legítimo do sistema por um payload sem alterar seu nome ou aparência na lista de processos. O objetivo é evadir detecção por soluções de segurança baseadas em assinaturas ou comportamento.

## Requisitos:

- Sistema operacional Windows 7 ou superior (x64 recomendado).
- Compilador Microsoft Visual C++ (cl.exe) ou MinGW-w64 com suporte a x86_64-pc-windows-msvc.
- Permissões de administrador (UAC elevado) para acessar processos de outro usuário e modificar memória de kernel.
- Arquivo de payload válido no formato PE (Portable Executable), compilado para a mesma arquitetura do processo alvo (x64 ou x86).

## Compilação:

1. Abra o prompt de comando como administrador.
2. Navegue até o diretório onde o arquivo fonte está localizado (ex: hollowing.c).
3. Compile usando o compilador MSVC:
   - `cl /nologo /W4 /O2 /link /SUBSYSTEM:CONSOLE hollowing.c`
  
   Ou, se usar MinGW-w64:
   - `x86_64-w64-mingw32-gcc -o hollowing.exe hollowing.c -lntdll`

    O link com ntdll.lib é necessário para resolver as funções NtUnmapViewOfSection e NtQueryInformationProcess.

## Uso:

Execute o programa com dois argumentos:

`hollowing.exe <caminho_para_payload.exe> <caminho_para_alvo.exe>`

## Exemplos:
```
hollowing.exe C:\temp\payload.exe C:\Windows\System32\svchost.exe
hollowing.exe C:\temp\malware.exe C:\Windows\System32\explorer.exe
```

O payload deve ser um executável PE válido. O alvo deve ser um processo legítimo do sistema que esteja em execução e cuja arquitetura corresponda à do payload.

## Funcionamento:

1. O programa lê o conteúdo do arquivo payload.
2. Aplica uma ofuscação simples (XOR com chave gerada aleatoriamente) para evitar detecção por assinatura.
3. Verifica os headers PE do payload para garantir que é um executável válido.
4. Cria o processo alvo em modo suspenso (CREATE_SUSPENDED).
5. Verifica compatibilidade de arquitetura entre payload e alvo usando IsWow64Process2.
6. Desmapeia a imagem original do processo alvo da memória usando NtUnmapViewOfSection.
7. Remove a ofuscação do payload aplicando a mesma chave XOR.
8. Aloca memória no processo alvo no endereço preferencial do payload (ou fallback).
9. Copia os headers e as seções do payload para a memória do processo alvo.
10. Ajusta as permissões de memória conforme definido nos headers das seções (READ, WRITE, EXECUTE).
11. Atualiza o campo ImageBaseAddress no PEB (Process Environment Block) do processo alvo para apontar para o novo payload.
12. Modifica o ponteiro de instrução da thread principal (RCX/ECX) para apontar para o EntryPoint do payload.
13. Resume a thread do processo alvo, fazendo com que ele execute o payload disfarçado como o processo legítimo.
14. Libera recursos e encerra.

## Resultados esperados:

- O processo alvo continua aparecendo na lista de tarefas com seu nome original.
- O código executado é o payload, não o binário original.
- O uso de memória e CPU será o do payload.
- Detalhes de assinatura digital, caminho no disco e nome do processo permanecem inalterados.

Observações importantes:

- Este código foi projetado para fins educacionais e de pesquisa de segurança.
- Não use em ambientes produtivos sem autorização explícita.
- Sistemas modernos com EDRs (Endpoint Detection and Response) como Microsoft Defender, CrowdStrike ou SentinelOne podem detectar esta técnica por padrão.
- A ofuscação XOR aplicada é trivial e não oferece proteção contra análise dinâmica.
- Para maior eficácia, combine com outras técnicas: reflection loading, direct syscalls, ou patching de APIs.

Depuração:

Se o processo alvo falhar ao iniciar após a injeção:
- Verifique se o payload é compatível com a arquitetura do alvo.
- Confirme que o payload não depende de DLLs ausentes no contexto do processo alvo.
- Use ferramentas como Process Hacker ou WinDbg para inspecionar a memória do processo e validar a presença do payload.
- Certifique-se de que o payload não tenta acessar recursos externos antes da inicialização completa do ambiente (ex: chamadas a LoadLibrary em DllMain).

Limitações:

- Não suporta processos protegidos (Protected Processes) como lsass.exe ou smss.exe.
- Não funciona em sistemas com PatchGuard ativo (kernel-mode protection).
- Não modifica o arquivo no disco — apenas a memória em tempo de execução.
- Não é persistente — o payload desaparece ao reiniciar o processo.

Saída esperada:

[+] Hollowing concluído - PID XXXXX

Caso ocorra erro, o programa exibirá mensagens detalhadas com códigos de erro do Windows.

Advertência legal:

⚠️ **AVISO:** A utilização deste código em redes, sistemas ou dispositivos sem permissão explícita do proprietário constitui violação de leis de segurança da informação em diversos países, incluindo a Lei Brasileira de Acesso Informático (Lei nº 12.737/2012). O autor não assume qualquer responsabilidade pelo uso indevido deste software.

