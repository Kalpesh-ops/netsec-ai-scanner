import nmap
import logging
import socket
import shutil
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NmapScanner:
    def __init__(self):
        # 1. Force Python to find the Nmap binary
        # Streamlit Cloud installs it to /usr/bin/nmap usually
        possible_paths = ["/usr/bin/nmap", "/usr/local/bin/nmap", "nmap"]
        
        found_path = None
        for path in possible_paths:
            if shutil.which(path):
                found_path = path
                break
        
        if not found_path:
            # Last ditch effort: Assume it's in path even if shutil misses it
            found_path = "nmap"

        try:
            # Initialize with specific path if found
            self.scanner = nmap.PortScanner(nmap_search_path=[found_path])
            logging.info(f"Nmap Scanner initialized at: {found_path}")
        except nmap.PortScannerError:
            raise Exception("Nmap binary not found. Did you add 'packages.txt' and REBOOT?")
        except Exception as e:
            logging.error(f"Error initializing scanner: {e}")
            raise

    def run_scan(self, target, fast_mode=False):
        try:
            # Resolve target first to ensure validity
            socket.gethostbyname(target)
            
            logging.info(f"Starting scan on target: {target}...")

            # --- CRITICAL CLOUD FIX ---
            # Cloud Servers (Streamlit/Heroku) DO NOT allow root access.
            # We MUST use -sT (Connect Scan) instead of -sS (SYN Scan).
            # We must remove -O (OS Detection) as it requires root.
            
            if fast_mode:
                # -sT: Unprivileged Connect Scan
                # -F: Fast mode (top 100 ports)
                scan_args = "-sT -F" 
            else:
                # -sT: Connect Scan
                # -sV: Version Detection (Works without root!)
                # --script vuln: Vulnerability scripts (Works without root!)
                scan_args = "-sT -sV --script vuln"
            
            # Run the scan
            self.scanner.scan(hosts=target, arguments=scan_args)
            
            return self._structure_data_for_ai(target)
            
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            return {"error": f"Scan failed: {str(e)}"}

    def _structure_data_for_ai(self, target):
        """
        Cleans the raw Nmap output into a clean JSON format.
        """
        clean_data = {
            "target": target,
            "scan_stats": self.scanner.scanstats(),
            "hosts": []
        }

        for host in self.scanner.all_hosts():
            host_info = {
                "ip": host,
                "status": self.scanner[host].state(),
                "hostnames": self.scanner[host].hostname(),
                "open_ports": []
            }

            for proto in self.scanner[host].all_protocols():
                ports = self.scanner[host][proto].keys()
                for port in sorted(ports):
                    port_data = self.scanner[host][proto][port]
                    
                    # Extract script output safely
                    vuln_output = ""
                    if 'script' in port_data:
                        vuln_output = port_data['script']

                    host_info["open_ports"].append({
                        "port": port,
                        "protocol": proto,
                        "state": port_data['state'],
                        "service": port_data['name'],
                        "product": port_data.get('product', 'unknown'),
                        "version": port_data.get('version', 'unknown'),
                        "vulnerabilities_found": vuln_output
                    })
            
            clean_data["hosts"].append(host_info)

        return clean_data