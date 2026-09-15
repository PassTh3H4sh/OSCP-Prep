# oscp-scan

Enumeration-only auto recon for the notes layout in this repo.

It does **not** exploit, brute-force logins, spray passwords, or run `nmap --script vuln`.

## What it runs

1. TCP (your one-liner, plus XML next to it for parsing):

```bash
nmap -p- -sV -sC $IP --open -oN nmap
```

2. UDP top 100:

```bash
sudo nmap -sU --top-ports 100 --open -oN nmap_udp_top100 $IP
```

3. Every other UDP port (all UDP **except** nmap’s first 100 popular ports):

```bash
sudo nmap -sU -p- --exclude-ports <top-100-udp> --open -oN nmap_udp_rest $IP
```

That last scan is slow. Skip it with `--skip-udp-rest` if you only want the popular 100 for now.

4. Per open port, tools taken from `templates/ports/*.md` headings, using the one-liners in `commands.yaml` (copied from `tools/` + `methodology/Enumeration.md`).

| Template heading | Tool |
| --- | --- |
| CURL | `curl -skI` |
| Whatweb | `whatweb` |
| Nikto | `nikto` |
| Gobuster | dirs + files, `raft-medium-*` |
| Enum4linux / Enum4linux-ng / nbtscan / smbclient | SMB enum |
| SNMP-WALK | `snmpwalk` public v2c then v1 |
| Reverse-lookup / DNS-Zone-Transfer | `host`, `dnsrecon`, `dig axfr` |
| VRFY / expn user-enum | `smtp-user-enum` + short username list |
| SSH-AUDIT | `ssh-audit` |

Missing binaries are skipped and written into the note as `SKIPPED`.

## Install

On Kali:

```bash
sudo apt install nmap python3-yaml gobuster nikto whatweb smbclient enum4linux
# optional but used when the matching port is open:
sudo apt install enum4linux-ng nbtscan snmp dnsrecon dnsutils smtp-user-enum ssh-audit onesixtyone netexec
```

```bash
chmod +x tools/oscp-scan/oscp-scan.py
```

## Usage

From anywhere:

```bash
python3 /path/to/OSCP-Prep/tools/oscp-scan/oscp-scan.py \
  -t TARGET \
  -n boxname \
  -o /path/to/OSCP-Prep/boxes \
  --repo /path/to/OSCP-Prep
```

Dry run (print the plan, no packets beyond what you already accept):

```bash
python3 tools/oscp-scan/oscp-scan.py -t TARGET -n test --dry-run --repo .
```

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--dry-run` | Print commands only |
| `--skip-udp` | No UDP at all |
| `--skip-udp-rest` | UDP top 100 only |
| `--skip-service-scans` | Nmap only, no gobuster/nikto/etc |
| `--nmap-append "-T4 --min-rate 2000"` | Extra nmap flags |
| `--timeout 600` | Per follow-up command cap (seconds) |

## Output

```
boxes/<name>/
  nmap                      <- your requested -oN name
  nmap_udp_top100
  nmap_udp_rest
  General-Info.md           <- port table
  External/<port>-<svc>.md  <- template + filled command output
  scans/                    <- XML + raw tool output
  Exploit.md                <- left blank on purpose
```

## Scope

Authorized labs / exam targets only. Pointing this at systems you do not have permission to test is out of scope.
