import type { IconName } from '../shared/icon';

/**
 * Rede fictícia da demo, com os mesmos serviços e versões do modo demonstração da app
 * (src/Nodar.App/Services/DemoData.cs). Os equipamentos, nomes, IPs e MACs são inventados
 * (os prefixos de MAC são de fabricantes reais, para baterem certo com a marca); os serviços e versões são os da app,
 * e os CVEs mostrados são reais para essas versões (NVD + CISA KEV).
 * As contagens totais são as que a app mostra em modo demonstração.
 */

export type Lang = 'pt' | 'en';
type Text = Record<Lang, string>;

export type DeviceKind = 'router' | 'computer' | 'phone' | 'tv' | 'printer' | 'server' | 'console';
export type Trust = 'known' | 'review' | 'suspicious';
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

export interface Cve {
  id: string;
  score: number;
  severity: Severity;
  kev?: boolean;
  summary: Text;
}

export interface Service {
  port: number;
  name: string;
  product?: string;
  distro?: string;
}

export interface Device {
  id: string;
  name: Text;
  hostname: string;
  ip: string;
  mac: string;
  vendor: string;
  model: Text;
  os: string;
  kind: DeviceKind;
  icon: IconName;
  isRouter?: boolean;
  isThisPc?: boolean;
  trust: Trust;
  note?: Text;
  ports: number;
  services: Service[];
  cveCount: number;
  kevCount: number;
  cves: Cve[];
  firstSeen: string;
}

/** Cores por tipo, iguais a src/Nodar.App/ViewModels/Visuals.cs (fundo, traço). */
export const KIND_COLORS: Record<string, [string, string]> = {
  router: ['rgba(124,108,255,.15)', '#A79CFF'],
  thisPc: ['rgba(76,141,255,.15)', '#7FB0FF'],
  computer: ['rgba(76,141,255,.15)', '#7FB0FF'],
  phone: ['rgba(229,231,235,.15)', '#E5E7EB'],
  tv: ['rgba(244,114,182,.15)', '#F9A8D4'],
  printer: ['rgba(251,191,36,.15)', '#FCD34D'],
  server: ['rgba(34,211,238,.15)', '#67E8F9'],
  console: ['rgba(167,139,250,.15)', '#C4B5FD'],
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  Critical: '#FF4D6D',
  High: '#FB923C',
  Medium: '#FBBF24',
  Low: '#34D399',
};

const same = (s: string): Text => ({ pt: s, en: s });

export const DEVICES: Device[] = [
  {
    id: 'router',
    name: same('router'),
    hostname: 'router',
    ip: '192.168.50.1',
    mac: 'DC:EF:09:00:00:01',
    vendor: 'Netgear',
    model: same('Netgear Nighthawk RAX50'),
    os: 'Linux',
    kind: 'router',
    icon: 'router',
    isRouter: true,
    trust: 'known',
    ports: 4,
    services: [
      { port: 53, name: 'DNS', product: 'dnsmasq 2.78' },
      { port: 80, name: 'HTTP', product: 'lighttpd 1.4.45' },
      { port: 443, name: 'HTTPS' },
      { port: 49152, name: 'UPnP', product: 'MiniUPnPd 1.9' },
    ],
    cveCount: 23,
    kevCount: 0,
    cves: [
      {
        id: 'CVE-2019-11072',
        score: 9.8,
        severity: 'Critical',
        summary: {
          pt: 'lighttpd antes de 1.4.54: overflow de inteiro com sinal no tratamento de URLs.',
          en: 'lighttpd before 1.4.54: signed integer overflow when handling URLs.',
        },
      },
      {
        id: 'CVE-2017-8798',
        score: 9.8,
        severity: 'Critical',
        summary: {
          pt: 'MiniUPnP até 2.0: erro de sinal num inteiro permite negação de serviço remota.',
          en: 'MiniUPnP through 2.0: integer signedness error allows remote denial of service.',
        },
      },
      {
        id: 'CVE-2020-25681',
        score: 8.1,
        severity: 'High',
        summary: {
          pt: 'dnsmasq antes de 2.83 (DNSpooq): heap overflow ao ordenar RRSets com DNSSEC.',
          en: 'dnsmasq before 2.83 (DNSpooq): heap overflow when sorting RRSets with DNSSEC.',
        },
      },
      {
        id: 'CVE-2018-19052',
        score: 7.5,
        severity: 'High',
        summary: {
          pt: 'lighttpd antes de 1.4.50: possível path traversal no mod_alias.',
          en: 'lighttpd before 1.4.50: possible path traversal in mod_alias.',
        },
      },
    ],
    firstSeen: '06/11/2026 17:15',
  },
  {
    id: 'laptop',
    name: { pt: 'Portátil da Ana', en: "Ana's laptop" },
    hostname: 'PORTATIL-ANA',
    ip: '192.168.50.23',
    mac: '48:C3:5A:10:4A:01',
    vendor: 'Lenovo',
    model: same('ThinkPad X1 Carbon'),
    os: 'Windows 11',
    kind: 'computer',
    icon: 'laptop',
    isThisPc: true,
    trust: 'known',
    ports: 0,
    services: [],
    cveCount: 0,
    kevCount: 0,
    cves: [],
    firstSeen: '06/11/2026 17:15',
  },
  {
    id: 'homelab',
    name: { pt: 'Servidor da garagem', en: 'Garage server' },
    hostname: 'homelab',
    ip: '192.168.50.40',
    mac: 'DC:A6:32:7B:00:12',
    vendor: 'Raspberry Pi',
    model: same('Raspberry Pi'),
    os: 'Linux',
    kind: 'server',
    icon: 'server',
    trust: 'known',
    note: { pt: 'Raspberry Pi com as cópias de segurança.', en: 'Raspberry Pi holding the backups.' },
    ports: 3,
    services: [
      { port: 22, name: 'SSH', product: 'OpenSSH 8.9p1', distro: 'Ubuntu' },
      { port: 80, name: 'HTTP', product: 'nginx 1.18.0', distro: 'Ubuntu' },
      { port: 6379, name: 'Redis', product: 'Redis 6.0.16' },
    ],
    cveCount: 61,
    kevCount: 1,
    cves: [
      {
        id: 'CVE-2023-44487',
        score: 7.5,
        severity: 'High',
        kev: true,
        summary: {
          pt: 'HTTP/2 Rapid Reset: cancelar pedidos em massa esgota o servidor (nginx).',
          en: 'HTTP/2 Rapid Reset: mass request cancellation exhausts the server (nginx).',
        },
      },
      {
        id: 'CVE-2025-49844',
        score: 9.9,
        severity: 'Critical',
        summary: {
          pt: 'Redis: um script Lua de um utilizador autenticado pode levar a execução remota de código.',
          en: 'Redis: a Lua script from an authenticated user can lead to remote code execution.',
        },
      },
      {
        id: 'CVE-2023-38408',
        score: 9.8,
        severity: 'Critical',
        summary: {
          pt: 'OpenSSH antes de 9.3p2: caminho de pesquisa PKCS#11 do ssh-agent permite execução remota.',
          en: 'OpenSSH before 9.3p2: ssh-agent PKCS#11 search path allows remote code execution.',
        },
      },
      {
        id: 'CVE-2024-6387',
        score: 8.1,
        severity: 'High',
        summary: {
          pt: 'regreSSHion: race condition no sshd que pode permitir execução de código como root.',
          en: 'regreSSHion: race condition in sshd that may allow code execution as root.',
        },
      },
    ],
    firstSeen: '06/11/2026 17:15',
  },
  {
    id: 'nas',
    name: same('nas'),
    hostname: 'nas',
    ip: '192.168.50.52',
    mac: '00:11:32:AB:CD:EF',
    vendor: 'Synology',
    model: same('Synology'),
    os: 'Linux',
    kind: 'server',
    icon: 'server',
    trust: 'known',
    ports: 2,
    services: [
      { port: 21, name: 'FTP', product: 'ProFTPD 1.3.5' },
      { port: 443, name: 'HTTPS', product: 'nginx 1.20.1' },
    ],
    cveCount: 23,
    kevCount: 2,
    cves: [
      {
        id: 'CVE-2015-3306',
        score: 10,
        severity: 'Critical',
        kev: true,
        summary: {
          pt: 'ProFTPD 1.3.5 mod_copy: ler e escrever ficheiros arbitrários sem autenticação.',
          en: 'ProFTPD 1.3.5 mod_copy: read and write arbitrary files without authentication.',
        },
      },
      {
        id: 'CVE-2023-44487',
        score: 7.5,
        severity: 'High',
        kev: true,
        summary: {
          pt: 'HTTP/2 Rapid Reset: cancelar pedidos em massa esgota o servidor (nginx).',
          en: 'HTTP/2 Rapid Reset: mass request cancellation exhausts the server (nginx).',
        },
      },
      {
        id: 'CVE-2022-41741',
        score: 7.8,
        severity: 'High',
        summary: {
          pt: 'nginx antes de 1.22.1: corrupção de memória no módulo mp4 com ficheiros forjados.',
          en: 'nginx before 1.22.1: memory corruption in the mp4 module with crafted files.',
        },
      },
    ],
    firstSeen: '06/11/2026 17:15',
  },
  {
    id: 'tv',
    name: { pt: 'TV da Sala', en: 'Living Room TV' },
    hostname: 'LGwebOSTV-sala',
    ip: '192.168.50.61',
    mac: '84:CC:11:00:11:22',
    vendor: 'LG Electronics',
    model: same('LG OLED (webOS)'),
    os: 'webOS',
    kind: 'tv',
    icon: 'tv',
    trust: 'known',
    ports: 1,
    services: [{ port: 8008, name: 'HTTP' }],
    cveCount: 0,
    kevCount: 0,
    cves: [],
    firstSeen: '06/11/2026 17:15',
  },
  {
    id: 'printer',
    name: { pt: 'Impressora do escritório', en: 'Office printer' },
    hostname: 'BRN-escritorio',
    ip: '192.168.50.77',
    mac: '00:80:77:33:44:55',
    vendor: 'Brother',
    model: same('Brother HL-L2350DW'),
    os: '—',
    kind: 'printer',
    icon: 'printer',
    trust: 'known',
    ports: 2,
    services: [{ port: 80, name: 'HTTP' }],
    cveCount: 0,
    kevCount: 0,
    cves: [],
    firstSeen: '06/11/2026 17:15',
  },
  {
    id: 'phone',
    name: { pt: 'Telemóvel do Rui', en: "Rui's phone" },
    hostname: 'moto-g84-Rui',
    ip: '192.168.50.88',
    mac: 'C4:A0:52:66:77:88',
    vendor: 'Motorola',
    model: same('moto g84'),
    os: 'Android',
    kind: 'phone',
    icon: 'phone',
    trust: 'review',
    ports: 0,
    services: [],
    cveCount: 0,
    kevCount: 0,
    cves: [],
    firstSeen: '09/11/2026 19:08',
  },
  {
    id: 'ps5',
    name: same('PS5'),
    hostname: 'PS5',
    ip: '192.168.50.95',
    mac: '7C:BB:8A:99:00:11',
    vendor: 'Sony',
    model: same('PlayStation 5'),
    os: '—',
    kind: 'console',
    icon: 'gamepad',
    trust: 'suspicious',
    note: { pt: 'Aparece à noite. Perguntar a quem esteve cá.', en: 'Shows up at night. Ask who was around.' },
    ports: 0,
    services: [],
    cveCount: 0,
    kevCount: 0,
    cves: [],
    firstSeen: '06/11/2026 17:15',
  },
];

export type FilterId =
  | 'all'
  | 'computers'
  | 'phones'
  | 'tv'
  | 'network'
  | 'printers'
  | 'consoles'
  | 'servers'
  | 'suspicious'
  | 'unreviewed'
  | 'vulnerable';

export const FILTERS: { id: FilterId; icon: IconName; test: (d: Device, trust: Trust) => boolean }[] = [
  { id: 'all', icon: 'grid', test: () => true },
  { id: 'computers', icon: 'laptop', test: (d) => d.kind === 'computer' },
  { id: 'phones', icon: 'phone', test: (d) => d.kind === 'phone' },
  { id: 'tv', icon: 'tv', test: (d) => d.kind === 'tv' },
  { id: 'network', icon: 'router', test: (d) => d.kind === 'router' },
  { id: 'printers', icon: 'printer', test: (d) => d.kind === 'printer' },
  { id: 'consoles', icon: 'gamepad', test: (d) => d.kind === 'console' },
  { id: 'servers', icon: 'server', test: (d) => d.kind === 'server' },
  { id: 'suspicious', icon: 'alert', test: (_, t) => t === 'suspicious' },
  { id: 'unreviewed', icon: 'eye', test: (_, t) => t === 'review' },
  { id: 'vulnerable', icon: 'shield', test: (d) => d.cveCount > 0 },
];

export const UPNP_PORTS = [
  { proto: 'TCP', port: 22, desc: 'SSH', dev: 'homelab', target: '192.168.50.40:22', sensitive: true },
  { proto: 'UDP', port: 3074, desc: 'PlayStation Network', dev: 'ps5', target: '192.168.50.95:3074', sensitive: false },
  { proto: 'TCP', port: 32400, desc: 'Plex Media Server', dev: 'nas', target: '192.168.50.52:32400', sensitive: false },
];

export const INTERNET_PORTS = [
  { label: '22 · SSH', upnp: true, danger: true },
  { label: '7547 · TR-069', upnp: false, danger: false },
  { label: '32400', upnp: true, danger: false },
];
