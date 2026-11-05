"""Network scanner for discovering devices on the local LAN."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any

try:
    from scapy.all import ARP, Ether, srp  # type: ignore

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


MAC_VENDOR_PREFIXES: dict[str, str] = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1A:11": "Google",
    "00:1B:44": "Samsung",
    "00:1E:C2": "Apple",
    "00:23:12": "Apple",
    "00:25:00": "Apple",
    "00:26:BB": "Apple",
    "28:CF:E9": "Apple",
    "3C:07:54": "Apple",
    "40:B0:34": "Apple",
    "68:AB:1E": "Apple",
    "7C:D1:C3": "Apple",
    "A4:83:E7": "Apple",
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:17:88": "Philips Hue",
    "18:B4:30": "Nest/Google",
    "44:65:0D": "Amazon",
    "34:D2:70": "Amazon",
    "FC:65:DE": "Amazon",
    "50:DC:E7": "Amazon",
    "AC:63:BE": "Xiaomi",
    "64:09:80": "Xiaomi",
    "34:CE:00": "Xiaomi",
    "00:1A:79": "Huawei",
    "00:E0:FC": "Huawei",
    "28:6E:D4": "Huawei",
    "00:90:4C": "TP-Link",
    "50:C7:BF": "TP-Link",
    "14:CC:20": "TP-Link",
    "00:1D:0F": "D-Link",
    "1C:7E:E5": "D-Link",
    "00:24:01": "D-Link",
    "00:1F:33": "Netgear",
    "A0:04:60": "Netgear",
    "C0:3F:0E": "Netgear",
    "00:15:6D": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "24:5A:4C": "Ubiquiti",
    "00:1B:21": "Intel",
    "00:1E:67": "Intel",
    "3C:97:0E": "Intel",
    "00:50:F2": "Microsoft",
    "00:15:5D": "Microsoft Hyper-V",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
}


@dataclass
class NetworkInfo:
    interface: str
    ip: str
    netmask: str
    gateway: str
    network: str
    hostname: str


@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    status: str = "online"
    open_ports: list[int] = field(default_factory=list)
    is_local: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_mac(mac: str) -> str:
    mac = mac.upper().replace("-", ":")
    parts = re.findall(r"[0-9A-F]{2}", mac)
    if len(parts) >= 6:
        return ":".join(parts[:6])
    return mac


def lookup_vendor(mac: str) -> str:
    if not mac:
        return "Desconhecido"
    prefix = normalize_mac(mac)[:8]
    return MAC_VENDOR_PREFIXES.get(prefix, "Desconhecido")


def get_hostname(ip: str, timeout: float = 0.5) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        return ""


def run_command(command: list[str], timeout: int = 10) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def get_local_network_windows() -> NetworkInfo | None:
    output = run_command(["ipconfig", "/all"])
    if not output:
        return None

    hostname = socket.gethostname()
    blocks = re.split(r"\r?\n\r?\n", output)
    best: NetworkInfo | None = None

    for block in blocks:
        if "IPv4" not in block:
            continue
        if re.search(r"Virtual|Hyper-V|VMware|Loopback|Bluetooth", block, re.I):
            continue

        adapter_match = re.search(r"^[^:]+Adapter ([^\r\n:]+)", block, re.M)
        interface = adapter_match.group(1).strip() if adapter_match else "Desconhecida"

        ip_match = re.search(r"IPv4[^:]*:\s*([\d.]+)", block)
        mask_match = re.search(r"Subnet Mask[^:]*:\s*([\d.]+)", block)
        gateway_match = re.search(r"Default Gateway[^:]*:\s*([\d.]+)", block)

        if not ip_match or not mask_match:
            continue

        ip = ip_match.group(1)
        netmask = mask_match.group(1)
        gateway = gateway_match.group(1) if gateway_match else ""

        try:
            network = str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))
        except ValueError:
            continue

        info = NetworkInfo(
            interface=interface,
            ip=ip,
            netmask=netmask,
            gateway=gateway,
            network=network,
            hostname=hostname,
        )

        if not best or (not best.gateway and gateway):
            best = info

    return best


def get_local_network_unix() -> NetworkInfo | None:
    output = run_command(["ip", "-4", "route"])
    if not output:
        return None

    hostname = socket.gethostname()
    gateway = ""
    interface = ""
    network = ""

    for line in output.splitlines():
        if line.startswith("default"):
            parts = line.split()
            if "via" in parts:
                gateway = parts[parts.index("via") + 1]
            if "dev" in parts:
                interface = parts[parts.index("dev") + 1]
        elif "/" in line and "dev" in line:
            parts = line.split()
            network = parts[0]
            if "dev" in parts:
                interface = parts[parts.index("dev") + 1]

    if not network:
        return None

    try:
        iface_output = run_command(["ip", "-4", "addr", "show", interface])
        ip_match = re.search(r"inet ([\d.]+)/([\d]+)", iface_output)
        if not ip_match:
            return None
        ip = ip_match.group(1)
        prefix = int(ip_match.group(2))
        netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}", strict=False).netmask)
    except (ValueError, IndexError):
        return None

    return NetworkInfo(
        interface=interface,
        ip=ip,
        netmask=netmask,
        gateway=gateway,
        network=network,
        hostname=hostname,
    )


def get_local_network() -> NetworkInfo | None:
    if platform.system() == "Windows":
        return get_local_network_windows()
    return get_local_network_unix()


def scan_arp_scapy(network: str, timeout: int = 2) -> list[tuple[str, str]]:
    if not SCAPY_AVAILABLE:
        return []

    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        answered, _ = srp(packet, timeout=timeout, verbose=0)
        devices: list[tuple[str, str]] = []
        for _, received in answered:
            devices.append((received.psrc, received.hwsrc))
        return devices
    except Exception:
        return []


def scan_arp_table() -> list[tuple[str, str]]:
    if platform.system() == "Windows":
        output = run_command(["arp", "-a"])
        pattern = r"([\d.]+)\s+([0-9a-fA-F-]{17})"
    else:
        output = run_command(["arp", "-an"])
        pattern = r"\(([\d.]+)\) at ([0-9a-fA-F:]{17})"

    devices: list[tuple[str, str]] = []
    for ip, mac in re.findall(pattern, output):
        if ip.startswith("224.") or ip.startswith("239."):
            continue
        if mac.lower() in {"ff-ff-ff-ff-ff-ff", "ff:ff:ff:ff:ff:ff"}:
            continue
        devices.append((ip, normalize_mac(mac)))
    return devices


def ping_host(ip: str, timeout_ms: int = 500) -> bool:
    system = platform.system()
    if system == "Windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]

    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode == 0


def ping_sweep(network: str, max_workers: int = 64) -> list[str]:
    net = ipaddress.IPv4Network(network, strict=False)
    hosts = [str(ip) for ip in net.hosts()]
    alive: list[str] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_host, host): host for host in hosts}
        for future in as_completed(futures):
            host = futures[future]
            try:
                if future.result():
                    alive.append(host)
            except Exception:
                pass

    return sorted(alive, key=lambda x: ipaddress.IPv4Address(x))


def scan_ports(ip: str, ports: list[int] | None = None, timeout: float = 0.3) -> list[int]:
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080, 8443]

    open_ports: list[int] = []
    lock = threading.Lock()

    def check_port(port: int) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                with lock:
                    open_ports.append(port)
        except OSError:
            pass
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=32) as executor:
        list(executor.map(check_port, ports))

    return sorted(open_ports)


def scan_network(
    network: str | None = None,
    deep_scan: bool = False,
    port_scan: bool = False,
) -> dict[str, Any]:
    info = get_local_network()
    if not info:
        return {"error": "Nao foi possivel detetar a rede local.", "devices": []}

    target_network = network or info.network
    local_ip = info.ip

    arp_devices = scan_arp_scapy(target_network)
    method = "arp_scapy" if arp_devices else "arp_table+ping"

    if not arp_devices:
        arp_devices = scan_arp_table()

    ip_to_mac = {ip: mac for ip, mac in arp_devices}
    discovered_ips = set(ip_to_mac.keys())

    if deep_scan or len(discovered_ips) < 3:
        for ip in ping_sweep(target_network):
            discovered_ips.add(ip)

    devices: list[Device] = []
    for ip in sorted(discovered_ips, key=lambda x: ipaddress.IPv4Address(x)):
        mac = ip_to_mac.get(ip, "")
        hostname = get_hostname(ip)
        vendor = lookup_vendor(mac)
        open_ports: list[int] = []

        if port_scan:
            open_ports = scan_ports(ip)

        devices.append(
            Device(
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor=vendor,
                status="online",
                open_ports=open_ports,
                is_local=(ip == local_ip),
            )
        )

    return {
        "network_info": asdict(info),
        "target_network": target_network,
        "scan_method": method,
        "scapy_available": SCAPY_AVAILABLE,
        "device_count": len(devices),
        "devices": [device.to_dict() for device in devices],
    }
