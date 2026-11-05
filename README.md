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
- **Verificação de vulnerabilidades conhecidas** com dados oficiais da [NVD](https://nvd.nist.gov/) (NIST) e do catálogo [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Ver [Como funciona a verificação de vulnerabilidades](#como-funciona-a-verificação-de-vulnerabilidades).

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

### Testes
```bash
dotnet test
```

---

## Como funciona a verificação de vulnerabilidades

Ativa **Analisar portas**, **Serviços** e **Vulnerabilidades**. Para cada serviço com banner, o Nodar faz isto:

1. **Identifica o produto e a versão** a partir do banner. Por exemplo, `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` dá OpenSSH 8.9p1, pacote Ubuntu. A versão nunca é adivinhada: sem versão no banner, o serviço fica marcado como *versão desconhecida*.
2. **Descarrega da NVD os CVEs desse produto** e compara localmente as regras de versão afetada (intervalos e versões exatas). A comparação percebe formatos reais como `8.2p1`, `1.3.5e` ou `1.0rc1`.
3. **Marca os CVEs com exploração ativa confirmada**, com base no catálogo CISA KEV, incluindo os que foram usados em ransomware.

Cada serviço mostra o estado da verificação: *verificado*, *verificado com cache antiga*, *versão desconhecida*, *produto não suportado* ou *NVD inacessível*. Um serviço que não foi verificado nunca aparece como "sem vulnerabilidades".

**Produtos suportados:** OpenSSH, Dropbear, Apache HTTP Server, nginx, Microsoft IIS, lighttpd, Jetty, vsftpd, ProFTPD, FileZilla Server, Exim, MySQL, MariaDB e Redis.

**Importante:** os resultados são *potenciais*.
- Uma correspondência por versão não prova que a falha existe. Configuração, módulos ativos e plataforma podem mudar o resultado.
- Distribuições como Ubuntu, Debian e RHEL aplicam correções sem mudar o número de versão ("backports"). O Nodar avisa quando deteta um pacote de distribuição. Nesses casos, confirma no próprio sistema.

### Privacidade e rede
- Para a NVD só é enviado o **identificador do produto** (ex.: `cpe:2.3:a:openbsd:openssh`). **Não são enviados IPs, MACs, hostnames nem as versões detetadas.** A comparação de versões é feita no teu PC.
- O catálogo KEV é descarregado inteiro, sem nenhum dado teu.
- Os dados ficam em cache em `%LOCALAPPDATA%\Nodar\cache\`: a NVD durante 3 dias e o KEV durante 1. Sem internet, é usada a cache existente e a app avisa.

### Chave da NVD (opcional)
Sem chave, a NVD limita a 5 pedidos por 30 segundos, e a primeira consulta de cada produto demora alguns segundos. Com uma [chave gratuita](https://nvd.nist.gov/developers/request-an-api-key), o limite passa para 50. Para a definir, usa uma destas opções:
- variável de ambiente `NVD_API_KEY`; ou
- ficheiro `%LOCALAPPDATA%\Nodar\settings.json` com `{ "nvdApiKey": "a-tua-chave" }`.

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
    ├── ServiceDetectionService.cs   # Leitura de banners
    ├── Vulnerabilities/
    │   ├── BannerParser.cs          # Produto e versão a partir do banner
    │   ├── ProductCatalog.cs        # Produtos suportados e identificadores CPE
    │   ├── VersionComparer.cs       # Comparação de versões (8.2p1, 1.3.5e, 1.0rc1…)
    │   ├── CpeMatcher.cs            # Regras de versão afetada da NVD
    │   ├── NvdParser.cs / NvdClient.cs   # NVD CVE API 2.0
    │   ├── KevClient.cs             # Catálogo CISA KEV
    │   ├── VulnerabilityCache.cs    # Cache local
    │   └── VulnerabilityService.cs  # Orquestração e estado de cada verificação
    ├── AuditReportService.cs        # Relatórios HTML / JSON / Markdown
    ├── ExportService.cs             # Exportação CSV
    ├── AdvancedPortScanner.cs       # (em desenvolvimento)
    ├── TracerouteService.cs         # (em desenvolvimento)
    └── TimingTemplates.cs           # (em desenvolvimento)
tests/Nodar.Tests/                   # Testes (xUnit), com respostas reais da NVD como fixtures
archive/python-web/                  # Protótipo web original em Python (não é mantido)
```

Os dados locais (histórico, lista de monitorização e cache de vulnerabilidades) ficam em `%LOCALAPPDATA%\Nodar\`.

---

## Limitações

- Só analisa a rede local onde o PC está ligado.
- Alguns dispositivos não respondem a ping nem a ARP (firewall, modo de poupança de energia, smartphones com MAC aleatório) e podem não aparecer ou aparecer de forma intermitente.
- A deteção de SO é **heurística** e pode falhar, sobretudo com dispositivos IoT.
- O **router/gateway** ainda não passa pelo scan de portas nem pela verificação de vulnerabilidades.
- A verificação de vulnerabilidades depende do banner. Serviços **HTTPS/TLS** ainda não são lidos, e muitos dispositivos (routers, câmaras, IoT) não anunciam versão. Uma correspondência por versão **não confirma** que o dispositivo está vulnerável. Não substitui uma auditoria de segurança a sério.
- As descrições dos CVEs vêm da NVD, em inglês.

---

## Roadmap

- [x] Base de vulnerabilidades com dados oficiais (NVD / CISA KEV) em vez de uma lista estática
- [ ] Ler banners HTTPS/TLS e incluir o gateway na análise
- [ ] Ligar à interface o scanner avançado, o traceroute e os perfis de timing
- [ ] Monitorização em segundo plano (minimizado para a bandeja / serviço)
- [ ] Nomes personalizados e "dispositivos de confiança"
- [ ] Deteção por mDNS / NetBIOS / SSDP para identificar melhor os dispositivos
- [ ] Separar a `MainForm` em componentes mais pequenos
- [ ] Alargar os testes automatizados ao resto da aplicação (há testes para a verificação de vulnerabilidades)

---

## Uso responsável

Esta ferramenta é para **redes que são tuas ou que tens autorização explícita para analisar**. Fazer scan de portas e vulnerabilidades em redes de terceiros sem permissão pode ser ilegal no teu país. O autor não se responsabiliza pelo uso indevido.

---

## Licença

[MIT](LICENSE) © 2026 JoaoRb
