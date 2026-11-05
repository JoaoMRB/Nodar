# Nodar

> Descobre quem está ligado à tua rede local, identifica cada dispositivo e avisa-te quando aparece alguém novo.

Aplicação nativa para Windows, feita em C# / .NET 9 (WinForms). Analisa a tua LAN e mostra cada dispositivo com IP, MAC, fabricante, hostname, tipo, sistema operativo provável e serviços expostos. Guarda o histórico de quem entrou e saiu da rede.

> **Estado:** em desenvolvimento ativo. A interface e as funcionalidades ainda vão mudar bastante.

---

## Funcionalidades

### Descoberta de dispositivos
- Deteção automática da rede local: interface, IP, máscara, gateway e intervalo da sub-rede. Ignora adaptadores virtuais (VPN, Hyper-V, VirtualBox…).
- Descoberta por **ARP** através da API nativa do Windows (`SendARP` / `iphlpapi.dll`), com ping como alternativa.
- **Scan profundo** opcional, que percorre toda a sub-rede.
- Resolução de **hostname** por DNS reverso.
- Identificação do **fabricante** pelo prefixo do MAC (OUI) e classificação automática do **tipo de dispositivo**.
- Marca o dispositivo que corresponde a este PC.

### Análise
- **Scan de portas** às portas TCP mais comuns.
- **Deteção de serviços** por leitura de banners (produto e versão).
- **Deteção de sistema operativo** por fingerprint TCP/IP (TTL, window size, MSS, flag DF), com nível de confiança.
- **Verificação de vulnerabilidades conhecidas**: cruza os serviços e versões detetados com uma base de CVEs. *Experimental, ver [Limitações](#limitações).*

### Monitorização
- **Histórico persistente** de cada dispositivo: quando foi visto pela primeira vez, entradas e saídas da rede.
- **Lista de monitorização**: escolhes os dispositivos a vigiar e recebes notificação quando entram ou saem.
- **Notificação de dispositivo novo**: alerta na bandeja do sistema quando aparece um dispositivo desconhecido.
- **Atualização automática** com intervalo configurável.
- Opção para mostrar ou esconder dispositivos offline.

### Exportação e relatórios
- Exportação da lista de dispositivos para **CSV**.
- **Relatório de auditoria** em **HTML**, **JSON** ou **Markdown**.

### Em desenvolvimento
O código destas partes já existe, mas ainda não está ligado à interface nem ao scan:
- Scanner de portas avançado (modos SYN / FIN / XMAS / NULL / ACK)
- Traceroute com análise de rota
- Perfis de velocidade do scan (de *Paranoid* a *Insane*). O seletor já aparece na interface, mas ainda não tem efeito.

---

## Requisitos

- **Windows 10 ou 11** (x64)
- Para compilar: [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- **Recomendado:** executar como **Administrador**. Sem permissões elevadas, a descoberta ARP e algumas análises dão resultados incompletos (a app avisa quando é o caso).

---

## Como usar

### Opção 1: executável pronto
Descarrega o `.exe` da página de [Releases](../../releases). É um ficheiro único que não precisa de .NET instalado. Executa-o, de preferência como Administrador.

### Opção 2: correr a partir do código
```bash
git clone <url-do-repositório>
cd <pasta-do-repositório>
dotnet run --project NetworkScanner/NetworkScanner.csproj
```
Também podes usar o [`run.bat`](run.bat).

### Opção 3: gerar o executável
```bash
build.bat
```
Gera um executável único e self-contained em `dist/Nodar.exe`.

---

## Estrutura do projeto

```
NetworkScanner/
├── Program.cs                       # Ponto de entrada
├── MainForm.cs                      # Interface principal
├── Models/NetworkModels.cs          # Modelos (dispositivo, rede, histórico, scan)
├── UI/Theme.cs                      # Tema escuro e componentes visuais
└── Services/
    ├── NetworkDiscoveryService.cs   # Deteção da rede, ARP, ping, DNS
    ├── VendorService.cs             # Base OUI (fabricante) e tipo de dispositivo
    ├── OSFingerprintService.cs      # Fingerprint de sistema operativo
    ├── OSFingerprintDatabase.cs     # Assinaturas de SO
    ├── ServiceDetectionService.cs   # Banners e deteção de serviços
    ├── VulnerabilityDatabase.cs     # Base de CVEs (experimental)
    ├── AuditReportService.cs        # Relatórios HTML / JSON / Markdown
    ├── ExportService.cs             # Exportação CSV
    ├── AdvancedPortScanner.cs       # (em desenvolvimento)
    ├── TracerouteService.cs         # (em desenvolvimento)
    └── TimingTemplates.cs           # (em desenvolvimento)
archive/python-web/                  # Protótipo web original em Python (não é mantido)
```

Os dados locais (histórico e lista de monitorização) ficam em `%LOCALAPPDATA%\Nodar\`, em ficheiros JSON. Nada é enviado para fora do teu computador.

---

## Limitações

- Só analisa a rede local onde o PC está ligado.
- Alguns dispositivos não respondem a ping nem a ARP (firewall, modo de poupança de energia, smartphones com MAC aleatório) e podem não aparecer ou aparecer de forma intermitente.
- A deteção de SO é **heurística** e pode falhar, sobretudo com dispositivos IoT.
- A **verificação de vulnerabilidades é experimental**. A base de CVEs é local e incompleta, e uma correspondência por versão **não confirma** que o dispositivo está vulnerável. Não serve de substituto para uma auditoria de segurança a sério.

---

## Roadmap

- [ ] Base de vulnerabilidades com dados oficiais (NVD / CISA KEV) em vez de uma lista estática
- [ ] Ligar à interface o scanner avançado, o traceroute e os perfis de timing
- [ ] Monitorização em segundo plano (minimizado para a bandeja / serviço)
- [ ] Nomes personalizados e "dispositivos de confiança"
- [ ] Deteção por mDNS / NetBIOS / SSDP para identificar melhor os dispositivos
- [ ] Separar a `MainForm` em componentes mais pequenos
- [ ] Testes automatizados

---

## Uso responsável

Esta ferramenta é para **redes que são tuas ou que tens autorização explícita para analisar**. Fazer scan de portas e vulnerabilidades em redes de terceiros sem permissão pode ser ilegal no teu país. O autor não se responsabiliza pelo uso indevido.

---

## Licença

[MIT](LICENSE) © 2026 JoaoRb
