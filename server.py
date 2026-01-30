import sys
import os
import re
from enum import Enum
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.scanner.nmap_engine import NmapScanner
from src.scanner.scapy_engine import ScapyEngine
from src.scanner.tshark_engine import TSharkScanner
from src.ai_agent.gemini_client import GeminiAgent
from src.utils.data_sanitizer import sanitize_scan_data
from src.utils.token_optimizer import prune_scan_data

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
        
        print(f"[*] Initiating {scan_mode.upper()} scan on {request.target}...")
        
        # 2. NMAP SCAN (all modes)
        scan_result = nmap_engine.run_scan(request.target, mode=scan_mode)
        
        if "error" in scan_result:
            raise HTTPException(status_code=500, detail=scan_result["error"])
        
        # 3. SCAPY FIREWALL ANALYSIS (deep & pen_test only)
        if scan_mode in ["deep", "pen_test"]:
            try:
                firewall_port = 445 if scan_mode == "pen_test" else 80
                fw_status = scapy_engine.firewall_detect(request.target, port=firewall_port)
                scan_result["firewall_analysis"] = fw_status
            except Exception as e:
                scan_result["firewall_analysis"] = {"error": str(e)}
        
        # 4. TSHARK PACKET CAPTURE (pen_test only)
        if scan_mode == "pen_test":
            try:
                tshark_duration = SCAN_PROFILES["pen_test"]["estimated_seconds"]["tshark"]
                capture_result = tshark_engine.run_capture(request.target, duration=tshark_duration)
                scan_result["tshark_capture"] = capture_result
            except Exception as e:
                scan_result["tshark_capture"] = {"error": str(e)}
        
        # 5. DATA SANITIZATION (PRIVACY-BY-DESIGN)
        clean_data = sanitize_scan_data(scan_result, target=request.target)
        
        # 6. TOKEN OPTIMIZATION
        optimized_data = prune_scan_data(clean_data)
        
        return {
            "status": "scan_complete",
            "data": clean_data,
            "scan_profile": SCAN_PROFILES[scan_mode]
        }
        
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        print(f"[!] Scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze")
async def analyze_scan(data: dict):
    """AI threat analysis endpoint."""
    try:
        optimized_data = prune_scan_data(data)
        print("[*] Sending optimized data to Gemini...")
        report = ai_agent.analyze_scan(optimized_data)
        return {"report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))