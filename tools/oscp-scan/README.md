# oscp-scan

Enumeration-only auto recon for the notes layout in this vault.

It does **not** exploit, brute-force logins, spray passwords, or run `nmap --script vuln`.

## Daily workflow (Obsidian + Kali)

The vault is the same folder Obsidian opens and Kali `cd`s into.

1. In Obsidian: create `boxes/<name>/` (copy `templates/box/` if you want the empty notes).
2. In Kali:

```bash
cd /path/to/OSCP-Prep/boxes/<name>
oscp-scan -t TARGET
```

The script writes into **the directory you are standing in**: `nmap`, `General-Info.md`, `External/`, `scans/`.

Install the command once (no `.py`):

```bash
cd /path/to/OSCP-Prep/tools/oscp-scan
chmod +x install.sh
./install.sh          # /usr/local/bin or ~/.local/bin
# ./install.sh --user    # force ~/.local/bin
# ./install.sh --system  # force /usr/local/bin (sudo if needed)
```

If it installed to `~/.local/bin` and `oscp-scan` is not found:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

`git pull` updates the tool; the wrapper keeps pointing at this file.

## What it runs

1. TCP:

```bash
nmap -p- -sV -sC $IP --open -oN nmap
```

2. UDP top 100, then every other UDP port (exclude those top 100). Use `--skip-udp-rest` to skip the long scan.

3. Per open port, tools from `templates/ports/*.md` headings.

## Other ways to launch

```bash
oscp-scan -t TARGET
oscp-scan -t TARGET --dry-run
oscp-scan -t TARGET --skip-udp-rest --nmap-append "-T4"
cd /path/to/OSCP-Prep && oscp-scan -t TARGET -n boxname -o boxes
```

## Scope

Authorized labs / exam targets only.
