# Logic for Vulnerability parsing
import re

class VulnChecker:
    @staticmethod
    def extract_cves(nmap_data):
        """
        Parses Nmap JSON output to find 'script' entries containing CVEs.
        Returns a simplified list of vulnerabilities found.
        """
        vulnerabilities = []
        
        # Regex to find CVE-YYYY-NNNN patterns
        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")

        if "hosts" not in nmap_data:
            return []

        for host in nmap_data["hosts"]:
            for port in host.get("open_ports", []):
                script_output = port.get("vulnerabilities_found", "")
                
                if script_output:
                    # Find specific CVEs
                    cves = cve_pattern.findall(script_output)
                    
                    vulnerabilities.append({
                        "port": port["port"],
                        "service": port["service"],
                        "raw_output": script_output[:200], # Truncate for brevity
                        "cves_detected": list(set(cves)) # Unique CVEs
                    })
        
        return vulnerabilities