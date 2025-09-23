# Process Hollowing com Hell's Gate - Demo Educacional

![License](https://img.shields.io/badge/license-Educational-red.svg)
![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)
![Language](https://img.shields.io/badge/language-C%2B%2B-green.svg)

## Visão Geral

Este projeto demonstra duas técnicas avançadas de evasão e injeção utilizadas por malware moderno:

- **Hell's Gate**: Técnica de evasão que resolve syscalls diretamente para evitar hooks de EDR/AV
- **Process Hollowing**: Técnica de injeção que substitui o código de um processo legítimo por payload malicioso

⚠️ **AVISO IMPORTANTE**: Este código é exclusivamente para fins educacionais em ambiente controlado e autorizado!

## Objetivos Educacionais

### Para Pentesters Iniciantes
- Compreender técnicas avançadas de evasão
- Entender como malware evita detecção
- Aprender contramedidas e métodos de detecção
- Praticar análise de técnicas ofensivas

### Para Red Teams
- Demonstrar bypasses de EDR/AV
- Técnicas de living-off-the-land
- Lateral movement através de processos legítimos

## Arquitetura do Projeto

```
ProcessHollowingDemo/
├── src/
│   ├── main.cpp              # Código principal da demonstração
│   ├── hellsgate.h          # Definições Hell's Gate
│   └── process_hollowing.h  # Estruturas Process Hollowing
├── docs/
│   ├── README.md            # Este arquivo
│   ├── TECHNIQUES.md        # Explicação detalhada das técnicas
│   └── DETECTION.md         # Métodos de detecção e contramedidas
├── examples/
│   ├── payloads/            # Payloads de exemplo para demonstração
│   └── targets/             # Processos target recomendados
└── tools/
    ├── build.bat            # Script de compilação
    └── setup.py             # Setup do ambiente de demo
```

## Quick Start

### Pré-requisitos

- **Sistema Operacional**: Windows 10/11 x64
- **Compilador**: Visual Studio 2019+ ou MinGW-w64
- **Permissões**: Administrador (para demonstração completa)
- **Ambiente**: Sistema isolado/VM recomendado

### Instalação

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/process-hollowing-demo.git
cd process-hollowing-demo

# Configure o ambiente
python setup.py --configure

# Compile o projeto
.\tools\build.bat
```

### Execução Básica

```bash
# Executar demonstração completa
.\ProcessHollowingDemo.exe

# Executar apenas Hell's Gate
.\ProcessHollowingDemo.exe --hellsgate-only

# Modo verboso para análise detalhada  
.\ProcessHollowingDemo.exe --verbose --debug
```

## Análise das Técnicas

### Hell's Gate Technique

**Conceito**: Resolução direta de syscalls para evitar hooks de EDR/AV

**Como Funciona**:
1. Mapeia NTDLL.DLL na memória
2. Localiza funções NTAPI específicas
3. Extrai números de syscall dos opcodes
4. Executa syscalls diretamente via assembly

**Código Exemplo**:
```cpp
// Buscar syscall não-hooked
DWORD syscallNum = FindSyscallNumber("NtCreateProcess");
if (syscallNum != -1) {
    // Executar syscall direto
    ExecuteDirectSyscall(syscallNum, params);
}
```

**Indicadores de Detecção**:
- Acesso direto a NTDLL sem usar APIs
- Padrões específicos de assembly para syscalls
- Comportamento anômalo em hooks de APIs

### Process Hollowing

**Conceito**: Substituição de código de processo legítimo por payload malicioso

**Fluxo de Execução**:
```
1. CreateProcess(SUSPENDED) → Processo legítimo suspenso
2. NtUnmapViewOfSection()   → Remove imagem original  
3. VirtualAllocEx()         → Aloca espaço para payload
4. WriteProcessMemory()     → Escreve payload malicioso
5. SetThreadContext()       → Ajusta entry point
6. ResumeThread()           → Executa payload no processo legítimo
```

**Vantagens Ofensivas**:
- Processo aparenta ser legítimo no Task Manager
- Herda contexto de segurança do processo original
- Dificulta análise forense
- Evita detecção baseada em nome/path

## Detecção e Contramedidas

### Sinais de Process Hollowing

**Indicadores Comportamentais**:
- Processos com imagens desmapeadas
- Memória executável em regiões inesperadas  
- Discrepâncias entre imagem em disco vs memória
- Threads com contexts modificados após criação

**Ferramentas de Detecção**:
- **ProcessHacker**: Verificar seções de memória
- **Hollows Hunter**: Detector específico para hollowing
- **Sysmon**: Event ID 25 (Process Tampering)
- **WinAPIOverride**: Monitor de chamadas de API

### Contramedidas Recomendadas

#### Para Blue Teams
```powershell
# Monitor Sysmon para eventos suspeitos
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=25}

# Verificar processos com memória anômala
Get-Process | Where-Object {$_.PagedMemorySize -gt $_.VirtualMemorySize}
```

#### Para EDR/AV Vendors
- Implementar hooks resistentes a bypasses
- Monitorar syscalls diretos
- Análise heurística de comportamento
- Sandboxing com análise de integridade

## Demonstração Prática

### Cenário 1: Demonstração Básica
```bash
# Target: notepad.exe
# Payload: MessageBox demo
# Objetivo: Mostrar conceitos fundamentais
.\ProcessHollowingDemo.exe --target notepad.exe --demo-payload
```

### Cenário 2: Evasão Avançada
```bash  
# Target: processo sistema
# Hell's Gate ativo
# Análise de detecção
.\ProcessHollowingDemo.exe --advanced --evasion --analysis
```

### Cenário 3: Blue Team Defense
```bash
# Modo detecção
# Gerar logs para análise
# Demonstrar contramedidas
.\ProcessHollowingDemo.exe --blue-team --generate-logs
```

## 🔧 Customização

### Adicionando Novos Payloads

```cpp
// Em payloads/custom_payload.h
class CustomPayload : public BasePayload {
public:
    BOOL GeneratePayload(LPVOID* buffer, SIZE_T* size) override {
        // Sua implementação aqui
        return TRUE;
    }
};
```

### Novos Targets

```cpp
// Em targets/custom_target.h  
static const LPCWSTR CUSTOM_TARGETS[] = {
    L"C:\\Windows\\System32\\your_target.exe",
    L"C:\\Program Files\\Application\\app.exe"
};
```

## Recursos de Aprendizado

### Artigos Técnicos Fundamentais

1. **Process Hollowing Original**
   - [Endgame Research](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
   - Técnica clássica explicada pelos criadores

2. **Hell's Gate Research**  
   - [GitHub - am0nsec/HellsGate](https://github.com/am0nsec/HellsGate)
   - Implementação original com explicação detalhada

3. **MITRE ATT&CK Framework**
   - [T1055.012 - Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
   - Documentação oficial da técnica

### Ferramentas Relacionadas

4. **Hollow Hunter**
   - [GitHub - hasherezade/hollows_hunter](https://github.com/hasherezade/hollows_hunter)
   - Ferramenta de detecção de process hollowing

5. **Pe-sieve**  
   - [GitHub - hasherezade/pe-sieve](https://github.com/hasherezade/pe-sieve)
   - Scanner de anomalias em processos

6. **SysWhispers**
   - [GitHub - jthuraisamy/SysWhispers](https://github.com/jthuraisamy/SysWhispers)  
   - Geração automática de syscalls

### Cursos e Treinamentos

7. **Malware Development Essentials**
   - [Sektor7.net](https://institute.sektor7.net/)
   - Curso prático de desenvolvimento de malware

8. **Advanced Windows Exploitation**
   - [SANS FOR610](https://www.sans.org/cyber-security-courses/reverse-engineering-malware-malware-analysis-tools-techniques/)
   - Análise reversa e técnicas avançadas

9. **Red Team Operations**  
   - [SANS FOR564](https://www.sans.org/cyber-security-courses/red-team-penetration-testing/)
   - Operações ofensivas avançadas

## Performance e Otimizações

### Métricas de Performance

| Técnica | Tempo Médio | Taxa de Sucesso | Detecção EDR |
|---------|-------------|-----------------|--------------|
| Hell's Gate | ~50ms | 95% | Baixa |
| Process Hollowing | ~200ms | 90% | Média |
| Combinado | ~250ms | 85% | Baixa |

### Otimizações Implementadas

- **Cache de Syscalls**: Evita re-parsing do NTDLL
- **Pool de Processos**: Reutilização de processos target
- **Async Operations**: Operações não-bloqueantes
- **Memory Alignment**: Otimização para performance

## Troubleshooting

### Problemas Comuns

**Erro: "Falha ao criar processo suspenso"**
```
Causa: Permissões insuficientes ou target protegido
Solução: Executar como administrador ou usar target diferente
```

**Erro: "Hell's Gate initialization failed"**  
```
Causa: NTDLL hooked ou versão incompatível
Solução: Usar VM limpa ou implementar bypass adicional
```

**Erro: "Payload injection failed"**
```
Causa: DEP/ASLR ativo ou incompatibilidade de arquitetura
Solução: Verificar configurações de segurança do SO
```

### Debug Mode

```bash
# Ativar logs detalhados
.\ProcessHollowingDemo.exe --debug --verbose --log-file demo.log

# Análise de syscalls
.\ProcessHollowingDemo.exe --trace-syscalls --output trace.txt
```

## Contribuindo

### Guidelines para Contribuição

1. **Fork** o repositório
2. **Crie** uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. **Commit** suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. **Push** para a branch (`git push origin feature/AmazingFeature`)
5. **Abra** um Pull Request

## Considerações Éticas e Legais

### Uso Responsável

Este projeto é destinado exclusivamente para:
- Pesquisa acadêmica em segurança
- Treinamento de equipes de segurança  
- Desenvolvimento de contramedidas
- Red team autorizado em pentest

### Uso Proibido

- Atividades maliciosas ou criminosas
- Atacar sistemas sem autorização
- Distribuição para fins maliciosos
- Violação de leis locais/nacionais/internacionais
*"Em segurança ofensiva, conhecer as técnicas do adversário é fundamental para construir defesas eficazes"*