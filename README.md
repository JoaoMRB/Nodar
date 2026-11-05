<p align="center">
  <img src="src/Nodar.App/Assets/nodar-128.png" width="96" alt="Nodar" />
</p>

<h1 align="center">Nodar</h1>

> Descobre quem está ligado à tua rede local, identifica cada dispositivo e avisa-te quando aparece alguém novo.

Aplicação para Windows feita em C# / .NET 9, com interface em [Avalonia](https://avaloniaui.net/). Analisa a tua LAN e mostra cada dispositivo com IP, MAC, fabricante, hostname, tipo, sistema operativo provável, serviços expostos e vulnerabilidades conhecidas. Guarda o histórico de quem entrou e saiu da rede.

> **Estado:** em desenvolvimento ativo.

---

## Funcionalidades

### Interface
- Escura e translúcida (Acrylic/Mica no Windows 11), com barra lateral e quatro vistas: **Dispositivos**, **Segurança**, **Histórico** e **Monitorizados**.
- Lista de dispositivos com ícone e cor por tipo, selos (*Router*, *Este PC*, *Novo*), portas abertas e vulnerabilidades. Tem pesquisa por nome, IP, MAC ou fabricante.
- Painel de detalhes com a informação do dispositivo, os serviços e o estado da verificação de cada um, as vulnerabilidades (CVSS, exploração ativa, ligação à NVD) e a atividade.
- Opções de análise num painel próprio. As preferências ficam guardadas.
- Notificações discretas dentro da app, sem caixas de diálogo a interromper.

### Descoberta de dispositivos
- Deteção automática da rede local: interface, IP, máscara, gateway e intervalo da sub-rede. Ignora adaptadores virtuais (VPN, Hyper-V, VirtualBox…).
- Descoberta por **ARP** em toda a sub-rede: o Windows resolve todos os endereços em paralelo e o Nodar lê a tabela de vizinhos (`GetIpNetTable2`). Uma rede /23 (510 endereços) demora cerca de 3 s, sem privilégios de administrador.
- **Não depende de ping**: iPhones bloqueados, Macs com firewall, impressoras e muitos aparelhos IoT ignoram ping, mas respondem sempre a ARP.
- Redes até 1024 endereços são sempre varridas por inteiro; **Sub-rede completa** alarga o varrimento a redes maiores.
- Nome por DNS reverso (o nome que o router atribui) e por **Bonjour/mDNS**: Macs, iPhones, iPads, Apple TV, Chromecast e impressoras anunciam o nome ("MacBook Pro da Ana") e o modelo.
- **Fabricante** pelo registo oficial do IEEE (cerca de 40 000 fabricantes), descarregado e guardado em cache. Dispositivos com **endereço Wi-Fi privado** (MAC aleatório) aparecem como tal e são identificados por Bonjour.
- **Tipo de dispositivo** pelo modelo, pelo fabricante e pelo hostname: router, computador, telemóvel, TV, impressora, consola, câmara, casa inteligente, servidor…
- Dispositivos atrás de um **repetidor Wi-Fi** que partilha o mesmo MAC continuam separados (identificados por MAC+IP).
- Marca o dispositivo que corresponde a este PC.

### Análise
- **Scan de portas** às portas TCP mais comuns, incluindo as típicas de routers (TR-069, UPnP). O router também é analisado.
- **Deteção de serviços** por leitura de banners, incluindo HTTPS (TLS) e a versão do servidor DNS (`version.bind`). As sondas nunca enviam credenciais nem tentativas de login.
- **Deteção de sistema operativo** por fingerprint TCP/IP (TTL, window size, MSS, flag DF), com nível de confiança.
- **Verificação de vulnerabilidades conhecidas** com dados oficiais da [NVD](https://nvd.nist.gov/) (NIST) e do catálogo [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Ver [Como funciona a verificação de vulnerabilidades](#como-funciona-a-verificação-de-vulnerabilidades).

### Monitorização
- **Histórico persistente** de cada dispositivo: quando foi visto pela primeira vez e quando entrou e saiu da rede. Os dispositivos são identificados pelo MAC, por isso uma mudança de IP por DHCP não cria um dispositivo "novo".
- **Dispositivos novos**: aviso quando aparece um dispositivo que nunca tinha sido visto. O primeiro scan conta como linha de base.
- **Monitorizados**: tocas na estrela de um dispositivo e recebes um aviso quando ele entra ou sai. Para evitar falsos alarmes com telemóveis em repouso, um dispositivo só é dado como saído depois de falhar dois scans seguidos.
- **Atualização automática** com intervalo configurável (1 a 15 minutos).
- Opção para mostrar ou esconder dispositivos offline.

### Exportação e relatórios
- Exportação da lista de dispositivos para **CSV**.
- **Relatório de auditoria** em **HTML**, **JSON** ou **Markdown**.

### Em desenvolvimento
O código destas partes já existe em `Nodar.Core`, mas ainda não está ligado à interface nem ao scan:
- Scanner de portas avançado (modos SYN / FIN / XMAS / NULL / ACK)
- Traceroute com análise de rota
- Perfis de velocidade do scan (de *Paranoid* a *Insane*)

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
dotnet run --project src/Nodar.App
```
Também podes usar o [`run.bat`](run.bat).

### Opção 3: gerar o executável
```bash
build.bat
```
Gera um executável único e self-contained em `dist/Nodar.exe`. O [`Abrir Nodar.bat`](Abrir%20Nodar.bat) abre-o e, se ainda não existir, gera-o primeiro.

### Modo demonstração
```bash
dist\Nodar.exe --demo
```
Mostra uma rede fictícia com serviços desatualizados, para veres a interface com vulnerabilidades sem precisares de uma rede vulnerável. Os dispositivos são inventados, mas os serviços são verificados na NVD real, por isso os CVEs são verdadeiros para essas versões. Usa uma pasta temporária e não mexe no teu histórico.

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

**Produtos suportados:** OpenSSH, Dropbear, Apache HTTP Server, nginx, Microsoft IIS, lighttpd, Jetty, vsftpd, ProFTPD, FileZilla Server, Exim, MySQL, MariaDB, Redis, e também os comuns em routers: dnsmasq (incluindo Pi-hole), Unbound, ISC BIND e MiniUPnPd.

**Importante:** os resultados são *potenciais*.
- Uma correspondência por versão não prova que a falha existe. Configuração, módulos ativos e plataforma podem mudar o resultado.
- Distribuições como Ubuntu, Debian e RHEL aplicam correções sem mudar o número de versão ("backports"). O Nodar avisa quando deteta um pacote de distribuição. Nesses casos, confirma no próprio sistema.

### Privacidade e rede
- Para a NVD só é enviado o **identificador do produto** (ex.: `cpe:2.3:a:openbsd:openssh`). **Não são enviados IPs, MACs, hostnames nem as versões detetadas.** A comparação de versões é feita no teu PC.
- O catálogo KEV é descarregado inteiro, sem nenhum dado teu.
- Para identificar fabricantes, o Nodar descarrega o registo público do IEEE (`standards-oui.ieee.org`) uma vez por mês. Nenhum dado teu é enviado.
- As perguntas Bonjour/mDNS e ARP ficam só na tua rede local.
- Os dados ficam em cache em `%LOCALAPPDATA%\Nodar\cache\`: a NVD durante 3 dias e o KEV durante 1. Sem internet, é usada a cache existente e a app avisa.

### Chave da NVD (opcional)
Sem chave, a NVD limita a 5 pedidos por 30 segundos, e a primeira consulta de cada produto demora alguns segundos. Com uma [chave gratuita](https://nvd.nist.gov/developers/request-an-api-key), o limite passa para 50. Para a definir, usa uma destas opções:
- variável de ambiente `NVD_API_KEY`; ou
- ficheiro `%LOCALAPPDATA%\Nodar\settings.json` com `{ "nvdApiKey": "a-tua-chave" }`.

---

## Estrutura do projeto

```
src/Nodar.App/                       # Interface (Avalonia, MVVM)
├── Views/MainWindow.axaml           # Janela principal e as quatro vistas
├── ViewModels/                      # Estado e comandos da interface
├── Styles/                          # Tema (cores, sombras), estilos dos controlos e ícones
└── Services/                        # Diálogos/área de transferência e modo demonstração

src/Nodar.Core/                      # Lógica, sem interface gráfica
├── Models/NetworkModels.cs          # Modelos (dispositivo, rede, histórico, scan)
├── Monitoring/DeviceTracker.cs      # Histórico, dispositivos novos e monitorizados
├── Settings/AppSettings.cs          # Preferências
└── Services/
    ├── NetworkDiscoveryService.cs   # Orquestração do scan (em paralelo)
    ├── NeighborDiscovery.cs         # Descoberta ARP (tabela de vizinhos do Windows)
    ├── MdnsProbe.cs                 # Bonjour/mDNS: nome e modelo
    ├── DeviceIdentification.cs      # Modelo → família e tipo (Mac14,7 → Mac)
    ├── OuiRegistry.cs               # Registo de fabricantes do IEEE
    ├── VendorService.cs             # Fabricante e tipo de dispositivo
    ├── OSFingerprintService.cs      # Fingerprint de sistema operativo
    ├── OSFingerprintDatabase.cs     # Assinaturas de SO
    ├── ServiceDetectionService.cs   # Leitura de banners (TCP e TLS, com timeouts)
    ├── DnsVersionProbe.cs           # Versão do servidor DNS (version.bind)
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

Os dados locais (histórico, lista de monitorização, preferências e cache de vulnerabilidades) ficam em `%LOCALAPPDATA%\Nodar\`.

---

## Limitações

- Só analisa a rede local onde o PC está ligado.
- Dispositivos em repouso profundo ou desligados do Wi-Fi podem falhar um scan. Para não gerar alarmes falsos, só são dados como "saídos" depois de falharem dois scans seguidos.
- iPhones e Androids podem **trocar o endereço Wi-Fi privado** (por exemplo, com "endereço rotativo" no iOS 18). Quando isso acontece, aparecem como um dispositivo novo.
- A deteção de SO é **heurística** e pode falhar, sobretudo com dispositivos IoT.
- A verificação de vulnerabilidades depende do banner. Muitos dispositivos (routers, câmaras, IoT) não anunciam versão. Uma correspondência por versão **não confirma** que o dispositivo está vulnerável. Não substitui uma auditoria de segurança a sério.
- As descrições dos CVEs vêm da NVD, em inglês.
- Os avisos (dispositivo novo, entrada e saída de um monitorizado) só aparecem com a app aberta. Ainda não há notificações do Windows nem execução em segundo plano.

---

## Roadmap

- [x] Base de vulnerabilidades com dados oficiais (NVD / CISA KEV) em vez de uma lista estática
- [x] Ler banners HTTPS/TLS e incluir o gateway na análise
- [ ] Identificar o firmware do router (modelo e versão) por UPnP/SSDP e páginas de login
- [ ] Ligar à interface o scanner avançado, o traceroute e os perfis de timing
- [x] Interface moderna (Avalonia) e lógica separada em `Nodar.Core`
- [ ] Notificações do Windows e monitorização em segundo plano (bandeja do sistema)
- [ ] Nomes personalizados e "dispositivos de confiança"
- [x] Identificação por Bonjour/mDNS e registo de fabricantes do IEEE
- [ ] Identificação por NetBIOS e SSDP/UPnP (Windows, Smart TVs, consolas)
- [x] Ícone da aplicação
- [ ] Screenshots no README
- [ ] Testes dos ViewModels da interface (o Core já tem 155 testes)

---

## Uso responsável

Esta ferramenta é para **redes que são tuas ou que tens autorização explícita para analisar**. Fazer scan de portas e vulnerabilidades em redes de terceiros sem permissão pode ser ilegal no teu país. O autor não se responsabiliza pelo uso indevido.

---

## Licença

[MIT](LICENSE) © 2026 JoaoRb
