import asyncio
import ipaddress
from typing import List, Dict, Tuple

COMMON_PORTS = [22, 5985, 5986, 8000]  # SSH, WinRM (HTTP/HTTPS), agent default

async def _probe_host(host: str, ports: List[int], timeout: float = 0.8) -> Dict:
    results = {}
    for port in ports:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            results[port] = True
        except Exception:
            results[port] = False
    return {"host": host, "open_ports": [p for p, ok in results.items() if ok]}

async def discover_cidr(cidr: str, ports: List[int] = None, concurrency: int = 256) -> List[Dict]:
    if ports is None:
        ports = COMMON_PORTS
    net = ipaddress.ip_network(cidr, strict=False)
    sem = asyncio.Semaphore(concurrency)
    async def wrapped_probe(h):
        async with sem:
            return await _probe_host(str(h), ports)
    tasks = [wrapped_probe(h) for h in net.hosts()]
    results = []
    for chunk in asyncio.as_completed(tasks):
        results.append(await chunk)
    # Label type by open ports
    for r in results:
        r["type"] = "unknown"
        if 22 in r["open_ports"]:
            r["type"] = "linux-ssh"
        if 5985 in r["open_ports"] or 5986 in r["open_ports"]:
            r["type"] = "windows-winrm"
        if 8000 in r["open_ports"]:
            r["type"] = "remotecli-agent"
    return [r for r in results if r["open_ports"]]