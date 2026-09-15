#!/usr/bin/env python3
"""
oscp-scan — enumeration-only recon for OSCP-style boxes.

Uses the port templates + one-liners from PassTh3H4sh/OSCP-Prep.
Does not run brute force, password sprays, or exploits.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


BANNED_TOKENS = (
    "hydra",
    "sqlmap",
    "searchsploit",
    "msfconsole",
    "msfvenom",
    "responder",
    "--script vuln",
    "rockyou",
    "password spray",
)

UDP_SERVICES_CANDIDATES = (
    "/usr/share/nmap/nmap-services",
    "/usr/local/share/nmap/nmap-services",
    "/opt/homebrew/share/nmap/nmap-services",
)


def die(msg: str, code: int = 1) -> None:
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def log(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[-] {msg}", flush=True)


def load_yaml(path: Path) -> dict:
    if yaml is None:
        die("PyYAML is required: sudo apt install python3-yaml  OR  pip install pyyaml")
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def which(bin_name: str) -> str | None:
    return shutil.which(bin_name)


def first_existing(paths: list[str]) -> str | None:
    for p in paths:
        if p and Path(p).is_file():
            return p
    return None


def nmap_bin(need_root: bool) -> list[str]:
    nmap = which("nmap")
    if not nmap:
        die("nmap is not installed")
    if need_root and os.geteuid() != 0:
        sudo = which("sudo")
        if sudo:
            return [sudo, nmap]
        warn("not root and no sudo; UDP / SYN accuracy may suffer")
    return [nmap]


def top_udp_ports(n: int = 100) -> list[int]:
    svc = first_existing(list(UDP_SERVICES_CANDIDATES))
    ranked: list[tuple[float, int]] = []
    if svc:
        with open(svc, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                portproto = parts[1]
                try:
                    freq = float(parts[2])
                except ValueError:
                    continue
                if "/udp" not in portproto:
                    continue
                port = int(portproto.split("/")[0])
                ranked.append((freq, port))
        ranked.sort(reverse=True)
        ports = []
        seen = set()
        for _, port in ranked:
            if port not in seen:
                seen.add(port)
                ports.append(port)
            if len(ports) >= n:
                break
        if ports:
            return ports
    return [
        53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 500, 514, 520,
        631, 1434, 1900, 4500, 5353, 17185,
    ]


def parse_nmap_xml(xml_path: Path) -> list[dict]:
    if not xml_path.is_file():
        return []
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        warn(f"could not parse {xml_path}")
        return []
    services = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") not in {"open", "open|filtered"}:
                continue
            svc = port.find("service")
            services.append(
                {
                    "port": int(port.get("portid")),
                    "proto": port.get("protocol", "tcp"),
                    "name": (svc.get("name") if svc is not None else "unknown") or "unknown",
                    "product": (svc.get("product") if svc is not None else "") or "",
                    "version": (svc.get("version") if svc is not None else "") or "",
                    "tunnel": (svc.get("tunnel") if svc is not None else "") or "",
                    "hostname": hostname,
                    "extrainfo": (svc.get("extrainfo") if svc is not None else "") or "",
                }
            )
    return services


def slug_service(svc: dict) -> str:
    name = (svc.get("name") or "unknown").lower()
    if svc.get("tunnel") == "ssl" and name == "http":
        name = "https"
    return name


def is_http(svc: dict) -> bool:
    name = slug_service(svc)
    if name in {"http", "https", "http-proxy", "http-alt", "ssl/http"}:
        return True
    return "http" in name


def url_for(ip: str, svc: dict) -> str:
    port = svc["port"]
    name = slug_service(svc)
    tls = svc.get("tunnel") == "ssl" or name in {"https", "ssl/http"} or port in {443, 8443}
    scheme = "https" if tls else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{ip}"
    return f"{scheme}://{ip}:{port}"


def normalize_heading(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9+\- ]+", "", text)
    text = re.sub(r"\s+", " ", text)
    return text


def parse_template_headings(path: Path) -> list[str]:
    headings = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = re.match(r"^#{1,6}\s+(.+?)\s*$", line)
        if m:
            headings.append(normalize_heading(m.group(1)))
    return headings


def load_templates(templates_dir: Path) -> dict[str, dict]:
    index: dict[str, dict] = {}
    if not templates_dir.is_dir():
        return index
    for md in sorted(templates_dir.glob("*.md")):
        stem = md.stem
        headings = parse_template_headings(md)
        entry = {"path": md, "stem": stem, "headings": headings}
        index[stem.lower()] = entry
        m = re.match(r"(?:udp-)?(\d+)(?:-\d+)?-(.+)$", stem, re.I)
        if m:
            port = m.group(1)
            svc = m.group(2).lower()
            index.setdefault(f"port:{port}", entry)
            index.setdefault(f"svc:{svc}", entry)
            index.setdefault(f"svc:{svc.replace('-', '')}", entry)
    return index


def pick_template(svc: dict, index: dict) -> dict | None:
    port = str(svc["port"])
    name = slug_service(svc)
    proto = svc["proto"]
    candidates = []
    if proto == "udp":
        candidates += [f"udp-{port}-{name}", f"UDP-{port}-{name}"]
    candidates += [
        f"{port}-{name}",
        f"{port}-{name.replace('_', '-')}",
        f"port:{port}",
        f"svc:{name}",
        f"svc:{name.replace('_', '-')}",
    ]
    aliases = {
        "microsoft-ds": ["smb", "445-smb"],
        "netbios-ssn": ["netbios-ssn", "139-netbios-ssn"],
        "ms-wbt-server": ["rdp", "3389-rdp"],
        "domain": ["dns", "53-dns"],
        "www": ["http"],
        "http-proxy": ["http"],
    }
    for alias in aliases.get(name, []):
        candidates.append(alias.lower())
        candidates.append(f"svc:{alias.lower()}")
    for key in candidates:
        hit = index.get(key.lower())
        if hit:
            return hit
    return None


def command_ids_for(svc: dict, tmpl: dict | None, cfg: dict) -> list[str]:
    heading_map = {normalize_heading(k): v for k, v in cfg.get("heading_map", {}).items()}
    ids: list[str] = []
    if tmpl:
        for heading in tmpl["headings"]:
            mapped = heading_map.get(heading)
            if mapped is None:
                for key, val in heading_map.items():
                    if key and (key in heading or heading in key):
                        mapped = val
                        break
            if mapped:
                ids.extend(mapped)
    if not ids:
        defaults = cfg.get("service_defaults", {})
        name = slug_service(svc)
        ids.extend(defaults.get(name, defaults.get("unknown", [])))
        if is_http(svc) and name not in defaults:
            ids.extend(defaults.get("http", []))
    seen = set()
    out = []
    for i in ids:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def format_cmd(template: str, ctx: dict) -> str:
    class Safe(dict):
        def __missing__(self, key: str) -> str:
            return "{" + key + "}"
    return template.format_map(Safe(ctx))


def banned(cmd: str) -> bool:
    low = cmd.lower()
    return any(tok in low for tok in BANNED_TOKENS)


def run_cmd(cmd: str, cwd: Path, timeout: int, dry_run: bool) -> tuple[int, str]:
    if dry_run:
        log(f"DRY {cmd}")
        return 0, ""
    log(cmd)
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout or ""
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        return 124, out + f"\n[timeout after {timeout}s]"


def ensure_box_layout(box_dir: Path, templates_box: Path | None) -> None:
    box_dir.mkdir(parents=True, exist_ok=True)
    (box_dir / "External").mkdir(exist_ok=True)
    (box_dir / "Internal").mkdir(exist_ok=True)
    (box_dir / "External" / "evidence").mkdir(exist_ok=True)
    (box_dir / "Internal" / "evidence").mkdir(exist_ok=True)
    (box_dir / "scans").mkdir(exist_ok=True)
    defaults = {
        "README.md": f"# {box_dir.name}\n\nAuto-generated by oscp-scan. Fill the path after you finish the box.\n",
        "Exploit.md": "## Foothold\n\n",
        "Loot.md": "## Users\n\n## Credentials\n\n## Hashes\n",
        "Internal/Priv-Esc.md": "## Priv Esc\n\n",
    }
    if templates_box and templates_box.is_dir():
        for src in templates_box.glob("*.md"):
            dest = box_dir / src.name
            if not dest.exists():
                dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        priv = templates_box / "Priv-Esc.md"
        if priv.exists() and not (box_dir / "Internal" / "Priv-Esc.md").exists():
            (box_dir / "Internal" / "Priv-Esc.md").write_text(
                priv.read_text(encoding="utf-8"), encoding="utf-8"
            )
    for rel, content in defaults.items():
        dest = box_dir / rel
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")


def write_general_info(path: Path, ip: str, services: list[dict], tcp_cmd: str, udp_cmds: list[str]) -> None:
    rows = ["| Port | Proto | Service | Product | Version |", "| --- | --- | --- | --- | --- |"]
    for s in services:
        prod = (s.get("product") or "").replace("|", "\\|")
        ver = (s.get("version") or "").replace("|", "\\|")
        rows.append(f"| {s['port']} | {s['proto']} | {slug_service(s)} | {prod} | {ver} |")
    body = f"""## Host Info
```
IP: {ip}
Scanned: {datetime.now().isoformat(timespec="seconds")}
```

## SCANS

### NMAP

#### Full TCP
```bash
{tcp_cmd}
```

#### UDP top 100
```bash
{udp_cmds[0] if udp_cmds else ""}
```

#### UDP remaining (all except top 100)
```bash
{udp_cmds[1] if len(udp_cmds) > 1 else ""}
```

### Open ports

{os.linesep.join(rows)}
"""
    path.write_text(body, encoding="utf-8")


def append_section(md_path: Path, heading: str, cmd: str, output: str) -> None:
    existing = md_path.read_text(encoding="utf-8") if md_path.exists() else f"## {md_path.stem}\n"
    block = f"""
## {heading}

```bash
{cmd}
```

```
{output.rstrip() if output.strip() else "(no output)"}
```
"""
    md_path.write_text(existing.rstrip() + "\n" + block, encoding="utf-8")


def copy_template(tmpl: dict | None, dest: Path) -> None:
    if dest.exists():
        return
    if tmpl:
        dest.write_text(tmpl["path"].read_text(encoding="utf-8"), encoding="utf-8")
    else:
        dest.write_text("## NMAP\n\n```bash\n\n```\n", encoding="utf-8")


def run_nmap_tcp(ip: str, box_dir: Path, dry_run: bool, extra: str) -> str:
    scans = box_dir / "scans"
    scans.mkdir(exist_ok=True)
    out_n = box_dir / "nmap"
    out_xml = scans / "nmap-tcp.xml"
    cmd = f"{' '.join(nmap_bin(False))} -p- -sV -sC {ip} --open -oN {out_n} -oX {out_xml} {extra}".strip()
    code, out = run_cmd(cmd, box_dir, timeout=60 * 45, dry_run=dry_run)
    (scans / "nmap-tcp.console.txt").write_text(out, encoding="utf-8")
    if code != 0:
        warn(f"TCP nmap exited {code}")
    return cmd


def run_nmap_udp(ip: str, box_dir: Path, dry_run: bool, skip_rest: bool, extra: str) -> list[str]:
    scans = box_dir / "scans"
    top = top_udp_ports(100)
    top_csv = ",".join(str(p) for p in top)
    cmds = []
    bin_ = " ".join(nmap_bin(True))
    cmd_top = (
        f"{bin_} -sU --top-ports 100 --open "
        f"-oN {box_dir / 'nmap_udp_top100'} -oX {scans / 'nmap-udp-top100.xml'} {extra} {ip}"
    ).strip()
    cmds.append(cmd_top)
    code, out = run_cmd(cmd_top, box_dir, timeout=60 * 30, dry_run=dry_run)
    (scans / "nmap-udp-top100.console.txt").write_text(out, encoding="utf-8")
    if code != 0:
        warn(f"UDP top-100 nmap exited {code}")
    if not skip_rest:
        cmd_rest = (
            f"{bin_} -sU -p- --exclude-ports {top_csv} --open "
            f"-oN {box_dir / 'nmap_udp_rest'} -oX {scans / 'nmap-udp-rest.xml'} {extra} {ip}"
        ).strip()
        cmds.append(cmd_rest)
        log("UDP remaining scan covers every UDP port except nmap's top 100. This is slow.")
        code, out = run_cmd(cmd_rest, box_dir, timeout=60 * 90, dry_run=dry_run)
        (scans / "nmap-udp-rest.console.txt").write_text(out, encoding="utf-8")
        if code != 0:
            warn(f"UDP remaining nmap exited {code}")
    return cmds


def merge_services(*groups: list[dict]) -> list[dict]:
    seen = {}
    for group in groups:
        for s in group:
            key = (s["proto"], s["port"])
            if key not in seen:
                seen[key] = s
            else:
                if seen[key].get("name") in {"unknown", ""} and s.get("name"):
                    seen[key] = s
    return sorted(seen.values(), key=lambda x: (x["proto"], x["port"]))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Enumeration-only auto scan using OSCP-Prep templates and one-liners."
    )
    p.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    p.add_argument("-n", "--name", help="Box folder name (default: target)")
    p.add_argument("-o", "--out", default=".", help="Parent directory for the box folder")
    p.add_argument("--repo", default="", help="Path to OSCP-Prep repo (templates + tools)")
    p.add_argument("--dry-run", action="store_true", help="Print commands, do not execute")
    p.add_argument("--skip-udp", action="store_true", help="Skip all UDP scans")
    p.add_argument("--skip-udp-rest", action="store_true", help="Only run UDP top 100")
    p.add_argument("--skip-service-scans", action="store_true", help="Only run nmap")
    p.add_argument("--nmap-append", default="", help="Extra flags appended to every nmap scan")
    p.add_argument("--timeout", type=int, default=600, help="Per service-command timeout in seconds")
    return p


def detect_repo(explicit: str) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if (path / "templates" / "ports").is_dir():
            return path
        die(f"--repo {path} does not look like OSCP-Prep (missing templates/ports)")
    here = Path(__file__).resolve()
    for cand in [here.parent, here.parent.parent, here.parent.parent.parent, Path.cwd()]:
        if (cand / "templates" / "ports").is_dir():
            return cand
        if (cand / "OSCP-Prep" / "templates" / "ports").is_dir():
            return cand / "OSCP-Prep"
    return None


def main() -> None:
    args = build_parser().parse_args()
    ip = args.target
    name = args.name or re.sub(r"[^A-Za-z0-9._-]+", "-", ip)
    box_dir = Path(args.out).expanduser().resolve() / name
    repo = detect_repo(args.repo)
    tool_dir = Path(__file__).resolve().parent
    cfg_path = tool_dir / "commands.yaml"
    if not cfg_path.is_file():
        die(f"missing {cfg_path}")
    cfg = load_yaml(cfg_path)
    templates_dir = repo / "templates" / "ports" if repo else None
    templates_box = repo / "templates" / "box" if repo else None
    index = load_templates(templates_dir) if templates_dir else {}
    if repo:
        log(f"using templates from {repo}")
    else:
        warn("OSCP-Prep repo not found; falling back to service defaults in commands.yaml")
        warn("pass --repo /path/to/OSCP-Prep")
    wordlists = cfg.get("wordlists", {})
    ctx_base = {
        "ip": ip,
        "host": ip,
        "wordlist_dirs": first_existing(wordlists.get("dirs", [])) or "/usr/share/wordlists/dirb/common.txt",
        "wordlist_files": first_existing(wordlists.get("files", [])) or "/usr/share/wordlists/dirb/common.txt",
        "wordlist_users": first_existing(wordlists.get("users", [])) or "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    }
    ensure_box_layout(box_dir, templates_box)
    os.chdir(box_dir)
    log(f"box directory: {box_dir}")
    tcp_cmd = run_nmap_tcp(ip, box_dir, args.dry_run, args.nmap_append)
    udp_cmds: list[str] = []
    if not args.skip_udp:
        udp_cmds = run_nmap_udp(ip, box_dir, args.dry_run, args.skip_udp_rest, args.nmap_append)
    services = merge_services(
        parse_nmap_xml(box_dir / "scans" / "nmap-tcp.xml"),
        parse_nmap_xml(box_dir / "scans" / "nmap-udp-top100.xml"),
        parse_nmap_xml(box_dir / "scans" / "nmap-udp-rest.xml"),
    )
    if not services and not args.dry_run:
        warn("no open ports parsed from nmap XML — notes will be sparse")
    hostnames = [s.get("hostname") for s in services if s.get("hostname")]
    if hostnames:
        ctx_base["host"] = hostnames[0]
    write_general_info(box_dir / "General-Info.md", ip, services, tcp_cmd, udp_cmds)
    if args.skip_service_scans:
        log("skipping per-port enumeration")
        return
    catalog = cfg.get("commands", {})
    ran_smb = False
    for svc in services:
        tmpl = pick_template(svc, index)
        ids = command_ids_for(svc, tmpl, cfg)
        stem = f"{svc['port']}-{slug_service(svc)}"
        if svc["proto"] == "udp":
            stem = f"UDP-{stem}"
        dest = box_dir / "External" / f"{stem}.md"
        copy_template(tmpl, dest)
        if slug_service(svc) in {"microsoft-ds", "netbios-ssn"} and ran_smb:
            ids = [i for i in ids if i not in {"enum4linux", "enum4linux_ng", "smbclient_list", "nxc_smb", "nbtscan"}]
        if slug_service(svc) in {"microsoft-ds", "netbios-ssn"}:
            ran_smb = True
        ctx = dict(ctx_base)
        ctx.update({"port": svc["port"], "proto": svc["proto"], "url": url_for(ip, svc)})
        nmap_snippet = f"{svc['port']}/{svc['proto']} {slug_service(svc)} {svc.get('product','')} {svc.get('version','')}".strip()
        append_section(dest, "NMAP", tcp_cmd if svc["proto"] == "tcp" else " ".join(udp_cmds), nmap_snippet)
        for cid in ids:
            spec = catalog.get(cid)
            if not spec:
                continue
            binary = spec.get("bin")
            if binary and not which(binary):
                warn(f"{binary} not installed — skip {cid}")
                append_section(dest, spec.get("title", cid), spec.get("cmd", ""), f"SKIPPED: {binary} not in PATH")
                continue
            cmd = format_cmd(spec["cmd"], ctx)
            if banned(cmd):
                warn(f"blocked non-enum command: {cmd}")
                continue
            code, output = run_cmd(cmd, box_dir, timeout=args.timeout, dry_run=args.dry_run)
            if code != 0:
                output = (output or "") + f"\n[exit {code}]"
            append_section(dest, spec.get("title", cid), cmd, output)
    log("done")
    log(f"notes: {box_dir / 'General-Info.md'}")
    log("enum only — foothold stays in Exploit.md")


if __name__ == "__main__":
    main()
