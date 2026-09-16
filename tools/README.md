# Tools

Command snippets I used while practicing.

Lab IPs in text are `TARGET` / `ATTACKER`.

## oscp-scan (auto enum)

Private repo: [PassTh3H4sh/oscp-scan](https://github.com/PassTh3H4sh/oscp-scan) — not stored in this vault. Templates in `templates/ports/` stay here.

### First-time setup

```bash
git clone git@github.com:PassTh3H4sh/OSCP-Prep.git ~/OSCP-Prep
git clone git@github.com:PassTh3H4sh/oscp-scan.git ~/oscp-scan
cd ~/oscp-scan
chmod +x install.sh oscp-scan.py
./install.sh
```

Open `~/OSCP-Prep` as the Obsidian vault. If `oscp-scan` is not found:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Full writeup: [oscp-scan README](https://github.com/PassTh3H4sh/oscp-scan#first-time-setup-once).

### Each box

```bash
mkdir -p ~/OSCP-Prep/boxes/<name>
cd ~/OSCP-Prep/boxes/<name>
oscp-scan -t TARGET
```

Obsidian shows the files as they land in that folder. `--no-hints` skips the Look at section. `--skip-udp-rest` skips the long UDP scan.

---

| Tool |
| --- |
| [7z](7z.md) |
| [AS-REP-Roasting](AS-REP-Roasting.md) |
| [Bloodhound](Bloodhound.md) |
| [Certutil](Certutil.md) |
| [Chisel](Chisel.md) |
| [Droopescan](Droopescan.md) |
| [Evil-Winrm](Evil-Winrm.md) |
| [Hashcat](Hashcat.md) |
| [Impacket-secretsdump](Impacket-secretsdump.md) |
| [John](John.md) |
| [Kerberoasting](Kerberoasting.md) |
| [LDAPsearch](LDAPsearch.md) |
| [Mimikatz](Mimikatz.md) |
| [Netexec](Netexec.md) |
| [PrintSpoofer](PrintSpoofer.md) |
| [Psexec-UAC-bypass](Psexec-UAC-bypass.md) |
| [RPCclient](RPCclient.md) |
| [Responder](Responder.md) |
| [Rubeus](Rubeus.md) |
| [Tar](Tar.md) |
| [accesschk](accesschk.md) |
| [cadaver](cadaver.md) |
| [commix](commix.md) |
| [crackmapexec](crackmapexec.md) |
| [crunch](crunch.md) |
| [curl](curl.md) |
| [dir](dir.md) |
| [dirsearch](dirsearch.md) |
| [dnsenum](dnsenum.md) |
| [dnsrecon](dnsrecon.md) |
| [enum4linux](enum4linux.md) |
| [exiftool](exiftool.md) |
| [feroxbuster](feroxbuster.md) |
| [ffuf](ffuf.md) |
| [ftp](ftp.md) |
| [git-dumper](git-dumper.md) |
| [git](git.md) |
| [gobuster](gobuster.md) |
| [host](host.md) |
| [hydra](hydra.md) |
| [impacket-GetST](impacket-GetST.md) |
| [impacket-addcomputer](impacket-addcomputer.md) |
| [impacket-mssqlclient](impacket-mssqlclient.md) |
| [impacket-smbserver](impacket-smbserver.md) |
| [impacket-wmiexec](impacket-wmiexec.md) |
| [iwr](iwr.md) |
| [kerbrute](kerbrute.md) |
| [ligolo-ng](ligolo-ng.md) |
| [msfconsole](msfconsole.md) |
| [msfvenom](msfvenom.md) |
| [mysql](mysql.md) |
| [nbtscan](nbtscan.md) |
| [netcat](netcat.md) |
| [netdiscover](netdiscover.md) |
| [nikto](nikto.md) |
| [nmap](nmap.md) |
| [nslookup](nslookup.md) |
| [ntlmrelayx](ntlmrelayx.md) |
| [onesixtyone](onesixtyone.md) |
| [openssl](openssl.md) |
| [powershell](powershell.md) |
| [proxychains](proxychains.md) |
| [python](python.md) |
| [rdesktop](rdesktop.md) |
| [runas](runas.md) |
| [schtasks](schtasks.md) |
| [scp](scp.md) |
| [searchsploit](searchsploit.md) |
| [smbclient](smbclient.md) |
| [smtp-user-enum](smtp-user-enum.md) |
| [snmpwalk](snmpwalk.md) |
| [socat](socat.md) |
| [sqlmap](sqlmap.md) |
| [ssh](ssh.md) |
| [strings](strings.md) |
| [tcpdump](tcpdump.md) |
| [theHarvester](theHarvester.md) |
| [unzip](unzip.md) |
| [wfuzz](wfuzz.md) |
| [wget](wget.md) |
| [whatweb](whatweb.md) |
| [whois](whois.md) |
| [winPEAS](winPEAS.md) |
| [wpscan](wpscan.md) |
| [wsgidav](wsgidav.md) |
| [xFreerdp](xFreerdp.md) |
| [zbarimg](zbarimg.md) |
