#!/usr/bin/env python3
"""
Kali Recon Toolkit - a small reconnaissance wrapper around Nmap.

It runs an Nmap service scan against a target, saves the XML, parses it into a
clean report, and flags services that are worth a second look (plain-text
protocols, remote access, databases exposed to the network).

Run only against hosts you own or are authorised to test.

Usage:
    python3 recon.py 127.0.0.1                 # scan a host (needs nmap)
    python3 recon.py 192.168.1.10 -p 1-1024    # custom port range
    python3 recon.py --parse samples/scan.xml  # just parse an existing Nmap XML
"""

import argparse
import subprocess
import sys
import os
import shutil
import xml.etree.ElementTree as ET

# services that deserve attention, and why
RISKY = {
    "ftp": "clear-text file transfer",
    "telnet": "clear-text remote shell",
    "http": "unencrypted web traffic",
    "smtp": "mail - check for open relay",
    "pop3": "clear-text mail",
    "imap": "clear-text mail",
    "microsoft-ds": "SMB - common lateral-movement target",
    "netbios-ssn": "SMB/NetBIOS exposed",
    "ms-wbt-server": "RDP - brute-force target",
    "mysql": "database exposed to the network",
    "ms-sql-s": "database exposed to the network",
    "postgresql": "database exposed to the network",
    "vnc": "remote desktop - often weakly authenticated",
    "rpcbind": "RPC - information disclosure",
}


def run_nmap(target, ports):
    if not shutil.which("nmap"):
        sys.exit("nmap not found. Install it:  sudo apt install -y nmap")
    out_xml = "scan.xml"
    cmd = ["nmap", "-sV", "-T4", "-p", ports, "-oX", out_xml, target]
    print(f"[*] Running: {' '.join(cmd)}\n")
    subprocess.run(cmd, check=False)
    return out_xml


def parse(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts = []
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "?"
        ports = []
        for p in host.findall("./ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "service": svc.get("name") if svc is not None else "",
                "product": (svc.get("product", "") + " " + svc.get("version", "")).strip() if svc is not None else "",
            })
        hosts.append({"addr": addr, "ports": sorted(ports, key=lambda x: x["port"])})
    return hosts


def report(hosts):
    print("=" * 64)
    print("  RECON REPORT")
    print("=" * 64)
    total_open, findings = 0, []
    for h in hosts:
        print(f"\nHost: {h['addr']}  ({len(h['ports'])} open ports)")
        print(f"  {'PORT':<9}{'SERVICE':<16}{'VERSION'}")
        print("  " + "-" * 50)
        for p in h["ports"]:
            total_open += 1
            print(f"  {str(p['port']) + '/' + p['proto']:<9}{p['service']:<16}{p['product']}")
            if p["service"] in RISKY:
                findings.append((h["addr"], p["port"], p["service"], RISKY[p["service"]]))

    print("\n" + "=" * 64)
    print("  FLAGGED SERVICES")
    print("=" * 64)
    if not findings:
        print("  none")
    for addr, port, svc, why in findings:
        print(f"  [!] {addr}:{port}  {svc}  -  {why}")
    print(f"\nSummary: {len(hosts)} host(s), {total_open} open port(s), {len(findings)} flagged.")


def main():
    ap = argparse.ArgumentParser(description="Nmap recon wrapper + report")
    ap.add_argument("target", nargs="?", help="host/IP to scan")
    ap.add_argument("-p", "--ports", default="1-1000", help="port range (default 1-1000)")
    ap.add_argument("--parse", metavar="XML", help="parse an existing Nmap XML instead of scanning")
    args = ap.parse_args()

    if args.parse:
        xml_path = args.parse
    elif args.target:
        xml_path = run_nmap(args.target, args.ports)
    else:
        ap.error("give a target to scan, or --parse an XML file")

    if not os.path.exists(xml_path):
        sys.exit(f"XML not found: {xml_path}")
    report(parse(xml_path))


if __name__ == "__main__":
    main()
