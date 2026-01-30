import sys
import os
import re
from enum import Enum
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.scanner.nmap_engine import NmapScanner
from src.scanner.scapy_engine import ScapyEngine
from src.scanner.tshark_engine import TSharkScanner
from src.ai_agent.gemini_client import GeminiAgent
from src.utils.data_sanitizer import sanitize_scan_data
from src.utils.token_optimizer import prune_scan_data

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI(title="NetSec AI Kernel")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engines
nmap_engine = NmapScanner()
scapy_engine = ScapyEngine()
tshark_engine = TSharkScanner()
ai_agent = GeminiAgent()

# --- ENUMS ---
class ScanMode(str, Enum):
    fast = "fast"
    deep = "deep"
    pen_test = "pen_test"

# --- SCAN PROFILES ---
SCAN_PROFILES = {
    "fast": {
        "label": "Fast Scan",
        "estimated_seconds": {
            "nmap": 30,
            "scapy": 0,
            "tshark": 0,
            "ai": 8,
            "total": 38
        }
    },
    "deep": {
        "label": "Deep Scan",
        "estimated_seconds": {
            "nmap": 90,
            "scapy": 3,
            "tshark": 0,
            "ai": 12,
            "total": 105
        }
    },
    "pen_test": {
        "label": "Pen Testing Scan",
        "estimated_seconds": {
            "nmap": 180,
            "scapy": 5,
            "tshark": 25,
            "ai": 15,
            "total": 225
        }
    }
}

# --- SECURITY: INPUT VALIDATION ---
def validate_target(target: str):
    # Stricter IPv4 regex that validates octet range (0-255)
    ipv4_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    
    if re.match(ipv4_regex, target) or re.match(domain_regex, target) or target == "localhost":
        return True
    raise ValueError("Invalid Target Format. Detection of potential injection attack.")

class ScanRequest(BaseModel):
    target: str
    scan_mode: ScanMode = ScanMode.fast

# --- FIREWALL ANALYSIS HELPERS ---

def infer_firewall_from_nmap(scan_data: dict, target: str) -> dict:
    """
    Fallback firewall detection using Nmap port state analysis.
    
    Logic:
    - If ANY port is 'filtered' -> Stateful firewall detected
    - If ports are 'closed' but host is up -> Likely unfiltered/stateless
    - If ALL ports are 'open' -> Very permissive firewall
    - Mixed states -> Complex firewall rules
    
    Args:
        scan_data: Raw Nmap scan result dict
        target: Target IP for reference
    
    Returns:
        dict with firewall_status, explanation, and inference_method
    """
    try:
        hosts = scan_data.get("hosts", [])
        if not hosts:
            return {
                "target": target,
                "port": "N/A",
                "response_type": "No Host Data",
                "firewall_status": "Unknown",
                "explanation": "No host data available from Nmap scan.",
                "inference_method": "nmap_fallback",
                "confidence": "low"
            }
        
        host_data = hosts[0]
        open_ports = host_data.get("open_ports", [])
        
        if not open_ports:
            return {
                "target": target,
                "port": "N/A",
                "response_type": "No Open Ports",
                "firewall_status": "Highly Restrictive / Firewall Active",
                "explanation": "No open ports detected. Target is either offline or protected by an aggressive firewall.",
                "inference_method": "nmap_fallback",
                "confidence": "high"
            }
        
        # Analyze port states
        port_states = {}
        for port in open_ports:
            state = port.get("state", "unknown") if isinstance(port, dict) else "unknown"
            port_states[state] = port_states.get(state, 0) + 1
        
        total_ports = len(open_ports)
        if total_ports == 0:
            # Safety check - shouldn't reach here due to earlier check, but just in case
            return {
                "target": target,
                "port": "N/A",
                "response_type": "No Data",
                "firewall_status": "Unable to Determine",
                "explanation": "No port data available for analysis.",
                "inference_method": "nmap_fallback",
                "confidence": "low"
            }
        
        filtered_count = port_states.get("filtered", 0)
        open_count = port_states.get("open", 0)
        closed_count = port_states.get("closed", 0)
        
        logging.info(f"[Firewall Inference] Port states: {port_states}")
        
        # --- INFERENCE RULES ---
        
        # Rule 1: High percentage of filtered ports = Stateful Firewall
        if filtered_count > 0 and (filtered_count / len(open_ports)) >= 0.5:
            return {
                "target": target,
                "port": "multiple",
                "response_type": "Mixed (Filtered Majority)",
                "firewall_status": "Stateful / Filtered (Inferred via Nmap)",
                "explanation": f"Nmap detected {filtered_count}/{len(open_ports)} ports as filtered. This indicates a stateful firewall is active, blocking unsolicited packets.",
                "inference_method": "nmap_fallback",
                "confidence": "high",
                "port_breakdown": port_states
            }
        
        # Rule 2: Mostly open ports with some filtered = Complex Rules
        if open_count > 0 and filtered_count > 0:
            return {
                "target": target,
                "port": "multiple",
                "response_type": "Mixed (Open + Filtered)",
                "firewall_status": "Stateful with Selective Rules (Inferred via Nmap)",
                "explanation": f"Nmap detected {open_count} open and {filtered_count} filtered ports. The firewall has selective rules allowing some services.",
                "inference_method": "nmap_fallback",
                "confidence": "medium",
                "port_breakdown": port_states
            }
        
        # Rule 3: All or mostly open = Permissive Firewall
        if open_count >= (len(open_ports) - 1):
            return {
                "target": target,
                "port": "multiple",
                "response_type": "All Open",
                "firewall_status": "Permissive / Unfiltered (Inferred via Nmap)",
                "explanation": f"Nmap detected {open_count}/{len(open_ports)} ports as open with minimal filtering. Firewall is permissive or absent.",
                "inference_method": "nmap_fallback",
                "confidence": "high",
                "port_breakdown": port_states
            }
        
        # Rule 4: Mix of closed and filtered = Moderate Security
        if closed_count > 0 and filtered_count > 0:
            return {
                "target": target,
                "port": "multiple",
                "response_type": "Mixed (Closed + Filtered)",
                "firewall_status": "Moderate Firewall (Stateless Likely)",
                "explanation": f"Nmap detected closed and filtered ports. Firewall likely responds differently to various probes.",
                "inference_method": "nmap_fallback",
                "confidence": "medium",
                "port_breakdown": port_states
            }
        
        # Rule 5: Mostly closed ports = Stateless/Unfiltered
        if closed_count >= (len(open_ports) - 1):
            return {
                "target": target,
                "port": "multiple",
                "response_type": "Mostly Closed",
                "firewall_status": "Stateless / Unfiltered (Inferred via Nmap)",
                "explanation": "Most ports are closed (host responds), suggesting a stateless firewall or host-level filtering.",
                "inference_method": "nmap_fallback",
                "confidence": "medium",
                "port_breakdown": port_states
            }
        
        # Default fallback
        return {
            "target": target,
            "port": "multiple",
            "response_type": "Indeterminate",
            "firewall_status": "Unknown Firewall State (Inferred via Nmap)",
            "explanation": "Nmap detected mixed port states. Firewall configuration is complex or indeterminate.",
            "inference_method": "nmap_fallback",
            "confidence": "low",
            "port_breakdown": port_states
        }
    
    except Exception as e:
        logging.error(f"Nmap firewall inference failed: {e}")
        return {
            "target": target,
            "port": "N/A",
            "response_type": "Inference Error",
            "firewall_status": "Unable to Determine",
            "explanation": f"Firewall inference failed: {str(e)}",
            "inference_method": "nmap_fallback",
            "confidence": "low"
        }

def analyze_firewall(scan_data: dict, target: str, scan_mode: str) -> dict:
    """
    Primary firewall analysis with graceful fallback.
    
    Strategy:
    1. Try Scapy direct probe (requires admin/root)
    2. Fall back to Nmap inference if Scapy fails
    
    Args:
        scan_data: Raw Nmap result
        target: Target IP
        scan_mode: Scan mode (determines whether to attempt Scapy)
    
    Returns:
        dict with firewall analysis (from Scapy or Nmap inference)
    """
    # Only attempt Scapy on deep/pen_test modes
    if scan_mode not in ["deep", "pen_test"]:
        return {
            "status": "skipped",
            "reason": f"Firewall analysis not enabled for {scan_mode} mode"
        }
    
    logging.info(f"[Firewall Analysis] Attempting Scapy probe on {target}...")
    
    try:
        # Determine target port based on scan mode
        firewall_port = 445 if scan_mode == "pen_test" else 80
        
        # Attempt direct probe with Scapy
        fw_status = scapy_engine.firewall_detect(target, port=firewall_port)
        
        # Check if Scapy encountered an error
        if "error" in fw_status:
            raise PermissionError(fw_status["error"])
        
        logging.info(f"[Firewall Analysis] Scapy probe successful: {fw_status['firewall_status']}")
        fw_status["inference_method"] = "scapy_direct"
        return fw_status
    
    except PermissionError as pe:
        logging.warning(f"[Firewall Analysis] Scapy requires elevated privileges: {pe}")
        logging.info(f"[Firewall Analysis] Falling back to Nmap-based inference...")
        
        # Use Nmap inference as fallback
        return infer_firewall_from_nmap(scan_data, target)
    
    except Exception as e:
        logging.warning(f"[Firewall Analysis] Scapy probe failed ({type(e).__name__}): {e}")
        logging.info(f"[Firewall Analysis] Falling back to Nmap-based inference...")
        
        # Use Nmap inference as fallback
        return infer_firewall_from_nmap(scan_data, target)

@app.post("/api/scan")
async def run_scan(request: ScanRequest):
    """
    Multi-mode network scanning endpoint.
    Implements privacy-by-design with strict data sanitization.
    """
    try:
        # 1. VALIDATION
        validate_target(request.target)
        scan_mode = request.scan_mode.value
        
        logging.info(f"[*] Initiating {scan_mode.upper()} scan on {request.target}...")
        
        # 2. NMAP SCAN (all modes)
        scan_result = nmap_engine.run_scan(request.target, mode=scan_mode)
        
        if "error" in scan_result:
            raise HTTPException(status_code=500, detail=scan_result["error"])
        
        # 3. FIREWALL ANALYSIS (deep & pen_test only) with Intelligent Fallback
        if scan_mode in ["deep", "pen_test"]:
            logging.info(f"[*] Initiating firewall analysis for {scan_mode} mode...")
            fw_analysis = analyze_firewall(scan_result, request.target, scan_mode)
            scan_result["firewall_analysis"] = fw_analysis
            
            # Log the method used
            method = fw_analysis.get("inference_method", "unknown")
            logging.info(f"[✓] Firewall analysis complete (method: {method})")
        
        # 4. TSHARK PACKET CAPTURE (pen_test only)
        if scan_mode == "pen_test":
            try:
                logging.info(f"[*] Initiating TShark packet capture...")
                tshark_duration = SCAN_PROFILES["pen_test"]["estimated_seconds"]["tshark"]
                capture_result = tshark_engine.run_capture(request.target, duration=tshark_duration)
                scan_result["tshark_capture"] = capture_result
                logging.info(f"[✓] TShark capture complete")
            except Exception as e:
                logging.warning(f"[!] TShark capture failed: {e}")
                scan_result["tshark_capture"] = {"error": str(e), "status": "failed"}
        
        # 5. DATA SANITIZATION (PRIVACY-BY-DESIGN)
        logging.info(f"[*] Sanitizing scan data...")
        clean_data = sanitize_scan_data(scan_result, target=request.target)
        logging.info(f"[✓] Data sanitization complete")
        
        # 6. TOKEN OPTIMIZATION
        logging.info(f"[*] Optimizing data for AI analysis...")
        optimized_data = prune_scan_data(clean_data)
        logging.info(f"[✓] Optimization complete")
        
        logging.info(f"[✓] Scan pipeline complete for {request.target}")
        
        return {
            "status": "scan_complete",
            "data": clean_data,
            "scan_profile": SCAN_PROFILES[scan_mode]
        }
        
    except ValueError as ve:
        logging.error(f"[!] Validation error: {ve}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logging.error(f"[!] Scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze")
async def analyze_scan(data: dict):
    """AI threat analysis endpoint."""
    try:
        logging.info(f"[*] Received analysis request...")
        optimized_data = prune_scan_data(data)
        logging.info(f"[*] Sending optimized data to Gemini...")
        report = ai_agent.analyze_scan(optimized_data)
        logging.info(f"[✓] AI analysis complete")
        return {"report": report}
    except Exception as e:
        logging.error(f"[!] Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "backend": "online",
        "version": "2.0"
    }

if __name__ == "__main__":
    import uvicorn
    logging.info("[*] Starting NetSec AI Kernel on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)