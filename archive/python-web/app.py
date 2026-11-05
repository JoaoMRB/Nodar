"""Web API for local network device discovery."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from scanner import get_local_network, scan_network, scan_ports

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="Quem Esta Ligado a Rede",
    description="Descobre dispositivos ligados a tua rede local",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/network")
async def network_info() -> dict:
    info = get_local_network()
    if not info:
        return {"error": "Nao foi possivel detetar a rede local."}
    from dataclasses import asdict

    return asdict(info)


@app.get("/api/scan")
async def scan(
    deep: bool = Query(False, description="Ping sweep completo na sub-rede"),
    ports: bool = Query(False, description="Analisar portas comuns em cada dispositivo"),
    network: str | None = Query(None, description="Sub-rede a analisar (ex: 192.168.1.0/24)"),
) -> dict:
    return scan_network(network=network, deep_scan=deep, port_scan=ports)


@app.get("/api/scan/{ip}/ports")
async def device_ports(ip: str) -> dict:
    open_ports = scan_ports(ip)
    return {"ip": ip, "open_ports": open_ports}
