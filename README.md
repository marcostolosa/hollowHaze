# Process Hollowing com Hell's Gate - Demo Educacional

![License](https://img.shields.io/badge/license-Educational-red.svg)
![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)
![Language](https://img.shields.io/badge/language-C%2B%2B-green.svg)

## Visão Geral

hollowHaze é um framework de demonstração técnica que implementa Process Hollowing com resolução de syscalls Hell's Gate para educação em cibersegurança e treinamento de red teams. O framework fornece implementação abrangente de técnicas avançadas de evasão utilizadas em análise de malware moderno.

**Propósito**: Demonstração educacional de técnicas de injeção de processos para profissionais de segurança, analistas de malware e pentesters.

**Aviso**: Este software é destinado exclusivamente para pesquisa de segurança autorizada e ambientes educacionais.

## Arquitetura Técnica

### Componentes Principais

**Implementação Hell's Gate**
- Resolução direta de syscalls do NTDLL
- Mecanismos de detecção e bypass de hooks
- Cálculo dinâmico de hash de funções (DJB2)
- Extração de números de syscall dos opcodes

**Engine de Process Hollowing**
- Criação de processos suspensos
- Análise e manipulação de cabeçalhos PE
- Desmapeamento de memória via NtUnmapViewOfSection
- Injeção de payload e modificação de contexto

## Estrutura do Repositório

```
hollowHaze/
├── demo.c          # Implementação principal (600+ linhas)
└── README.md       # Documentação
```

## Instruções de Compilação

### Pré-requisitos
- Ambiente de desenvolvimento Windows 10/11 x64
- GCC (MinGW-w64) ou Microsoft Visual Studio
- Privilégios de administrador para demonstração completa

### Compilação

**Usando GCC/MinGW:**
```bash
gcc -o hollowHaze.exe demo.c -lkernel32 -lntdll -luser32
```

**Usando Visual Studio:**
```bash
cl demo.c /Fe:hollowHaze.exe kernel32.lib ntdll.lib user32.lib
```

### Execução

```bash
# Demonstração padrão
.\hollowHaze.exe

# Modo debug com análise detalhada
.\hollowHaze.exe --debug
```

## Detalhes da Implementação

### Técnica Hell's Gate

A implementação Hell's Gate realiza resolução direta de syscalls para contornar hooks de EDR/AV:

1. **Análise NTDLL**: Mapeia NTDLL.DLL e localiza funções alvo
2. **Inspeção de Opcodes**: Examina prólogos de função para padrões de syscall
3. **Detecção de Hooks**: Identifica funções modificadas/com hooks
4. **Resolução Direta**: Extrai números de syscall de funções não-hookadas

**Funções Principais:**
- `find_syscall_number()` - Localiza números de syscall via análise de opcodes
- `djb2_hash()` - Gera hashes de nomes de função
- `init_hellsgate()` - Inicializa framework de resolução de syscalls

### Implementação Process Hollowing

O framework implementa o fluxo completo de process hollowing:

**Fase 1: Criação de Processo**
- Cria processo alvo em estado suspenso usando CREATE_SUSPENDED
- Obtém contexto inicial da thread e informações do processo

**Fase 2: Análise PE**
- Lê cabeçalhos DOS e NT da memória do processo alvo
- Extrai base da imagem, ponto de entrada e informações de seção

**Fase 3: Desmapeamento de Imagem**
- Usa NtUnmapViewOfSection para desmapear imagem executável original
- Trata falhas de desmapeamento graciosamente com mecanismos de fallback

**Fase 4: Alocação de Memória**
- Aloca região de memória executável no processo alvo
- Preferencialmente usa endereço base da imagem original

**Fase 5: Injeção de Payload**
- Escreve payload customizado na região de memória alocada
- Implementa tratamento adequado de erros e procedimentos de limpeza

**Fase 6: Modificação de Contexto**
- Modifica contexto da thread para apontar para payload injetado
- Atualiza ponteiro de instrução para novo ponto de entrada

**Fase 7: Retomada de Execução**
- Retoma thread suspensa para executar processo hollowed
- Mantém legitimidade do processo da perspectiva externa

## Detecção e Análise

### Indicadores Comportamentais

**Anomalias de Processo:**
- Processos com imagens primárias desmapeadas
- Regiões de memória executável em endereços não-padrão
- Discrepâncias entre imagem em disco e layout de memória
- Criação de processo suspenso seguida de modificação de contexto

**Padrões de Chamadas de API:**
- Uso direto de syscalls contornando APIs padrão
- Chamadas NtUnmapViewOfSection em processos recém-criados
- Operações WriteProcessMemory visando pontos de entrada de processo
- Modificações SetThreadContext em processos suspensos

### Ferramentas de Detecção

**Análise de Memória:**
- Hollows Hunter: https://github.com/hasherezade/hollows_hunter
- Pe-sieve: https://github.com/hasherezade/pe-sieve
- Process Hacker: https://processhacker.sourceforge.io/

**Monitoramento Comportamental:**
- Configuração Sysmon para Event ID 25 (Process Tampering)
- Monitoramento ETW (Event Tracing for Windows)
- WinAPIOverride para interceptação de chamadas de API

**Análise Forense:**
- Volatility Framework: https://www.volatilityfoundation.org/
- Desenvolvimento de regras YARA para detecção de padrões

## Mapeamento MITRE ATT&CK

**Técnica Primária:** T1055.012 - Process Injection: Process Hollowing
**Táticas:** Defense Evasion, Privilege Escalation

**Técnicas Relacionadas:**
- T1055.001: Dynamic-link Library Injection
- T1055.002: Portable Executable Injection
- T1055.003: Thread Execution Hijacking

**Fontes de Dados de Detecção:**
- Process: OS API Execution
- Process: Process Creation and Modification
- File: File System Modifications

## Áreas de Pesquisa Avançada

### Variantes Hell's Gate
- Heaven's Gate: transições de syscall x64 para x86
- Halos Gate: resolução indireta de syscalls
- Tartarus Gate: ofuscação de cadeia de syscalls

### Evolução de Injeção de Processo
- Técnicas de Manual DLL Loading
- Implementações de Module Stomping
- Métodos de Thread Stack Spoofing
- Variantes de Process Doppelgänging

### Metodologias de Evasão
- Estratégias de unhooking de NTDLL
- Implementação assembly direta de syscalls
- Evasão de hardware breakpoints
- Bypasses de proteção de memória

## Referências de Pesquisa de Segurança

**Pesquisa Original:**
- Hell's Gate: https://github.com/am0nsec/HellsGate
- SysWhispers: https://github.com/jthuraisamy/SysWhispers
- Process Injection Survey: Publicações de Pesquisa Endgame

**Recursos Acadêmicos:**
- MITRE ATT&CK Framework: https://attack.mitre.org/
- Diretrizes NIST Cybersecurity Framework
- Documentação Microsoft Security Development Lifecycle

**Treinamento Profissional:**
- Sektor7 Malware Development: https://institute.sektor7.net/
- SANS FOR610 Reverse Engineering Malware
- Offensive Security Advanced Windows Exploitation

## Diretrizes Legais e Éticas

### Uso Autorizado
- Pesquisa acadêmica de segurança dentro de estruturas institucionais
- Engajamentos autorizados de teste de penetração
- Exercícios de red team com escopo documentado e aprovação
- Desenvolvimento e teste de capacidades defensivas

### Requisitos de Conformidade
- Documentar todas as atividades de teste e limitações de escopo
- Manter contenção rigorosa dentro de ambientes autorizados
- Respeitar leis e regulamentos aplicáveis em sua jurisdição
- Aderir a códigos profissionais de conduta e políticas de divulgação

## Suporte Técnico

**Relatório de Problemas:** Submeta relatórios técnicos detalhados incluindo configuração do sistema, ambiente de compilação e saída de erro.

**Colaboração em Pesquisa:** Contate mantenedores para colaboração acadêmica no desenvolvimento de técnicas avançadas de evasão.

**Integração de Treinamento:** Framework disponível para integração em currículo de cibersegurança com licenciamento educacional adequado.

---

**Framework Educacional hollowHaze** - Plataforma de Pesquisa Avançada de Injeção de Processo

*"Em segurança ofensiva, conhecer as técnicas do adversário é fundamental para construir defesas eficazes"*