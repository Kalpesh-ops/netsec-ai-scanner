# Logic for Nmap Scanning
import nmap
import json
import logging
import socket

# Configure logging to track scan progress
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NmapScanner:
    def __init__(self):
        """
        Initializes the Nmap PortScanner.
        Checks if Nmap is installed and accessible.
        """
        try:
            self.scanner = nmap.PortScanner()
            logging.info("Nmap Scanner initialized successfully.")
        except nmap.PortScannerError:
            logging.error("Nmap not found! Please ensure Nmap is installed on your OS and added to PATH.")
            raise Exception("Nmap binary not found.")
        except Exception as e:
            logging.error(f"Error initializing scanner: {e}")
            raise

    def validate_target(self, target):
        """
        Simple validation to ensure target is reachable or valid IP.
        """
        try:
            # Attempt to resolve hostname or check IP validity
            socket.gethostbyname(target)
            return True
        except socket.error:
            logging.warning(f"Invalid target IP/Hostname: {target}")
            return False

    def run_scan(self, target, fast_mode=False):
        """
        Executes the Nmap scan.
        
        Args:
            target (str): IP address or range (e.g., '192.168.1.1' or '192.168.1.0/24')
            fast_mode (bool): If True, skips scripts for speed. If False, runs deep analysis.
        
        Returns:
            dict: Structured scan results optimized for AI analysis.
        """
        if not self.validate_target(target):
            return {"error": "Invalid target address"}

        logging.info(f"Starting scan on target: {target}...")

        # Arguments Explanation:
        # -sS: Stealth SYN Scan (harder to block)
        # -sV: Version Detection (crucial for knowing WHICH software is running)
        # -O: OS Detection (helps identify system type)
        # --script vuln: Runs basic vulnerability scripts (mini-Nessus)
        # -T4: Timing template (Aggressive speed)
        
        if fast_mode:
            scan_args = "-sS -T4 -F" # Fast scan, top 100 ports
        else:
            scan_args = "-sS -sV -O --script vuln -T4" 
        
        try:
            # Run the scan
            self.scanner.scan(hosts=target, arguments=scan_args)
            
            # Parse and return results
            return self._structure_data_for_ai(target)
            
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            return {"error": str(e)}

    def _structure_data_for_ai(self, target):
        """
        Cleans the raw Nmap output into a clean JSON format
        that the Gemini AI Agent can easily understand.
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
                "os_match": [],
                "open_ports": []
            }

            # Get OS info if available
            if 'osmatch' in self.scanner[host]:
                for os in self.scanner[host]['osmatch']:
                    host_info["os_match"].append({
                        "name": os['name'],
                        "accuracy": os['accuracy']
                    })

            # Get Protocols (usually tcp/udp)
            for proto in self.scanner[host].all_protocols():
                ports = self.scanner[host][proto].keys()
                for port in sorted(ports):
                    port_data = self.scanner[host][proto][port]
                    
                    # Extract script output (vulnerabilities found by --script vuln)
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

# --- TEST BLOCK (Runs only when executing this file directly) ---
if __name__ == "__main__":
    scanner = NmapScanner()
    
    # CHANGE THIS IP to your local router or a test device (e.g., 192.168.1.1)
    target_ip = "127.0.0.1" 
    
    print(f"Running deep scan on {target_ip}. This may take 1-5 minutes...")
    result = scanner.run_scan(target_ip, fast_mode=True) # Using fast mode for quick test
    
    print(json.dumps(result, indent=4))
    
    # Save to temp file for inspection
    with open("logs/temp_scans/latest_scan.json", "w") as f:
        json.dump(result, f, indent=4)
    print("Scan saved to logs/temp_scans/latest_scan.json")