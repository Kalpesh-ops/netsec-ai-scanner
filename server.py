import sys
import os
import re
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.scanner.nmap_engine import NmapScanner
from src.scanner.scapy_engine import ScapyEngine
from src.ai_agent.gemini_client import GeminiAgent
from src.utils.data_sanitizer import sanitize_scan_data
from src.utils.token_optimizer import prune_scan_data # <--- NEW IMPORT

app = FastAPI(title="NetSec AI Kernel")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

nmap_engine = NmapScanner()
scapy_engine = ScapyEngine()
ai_agent = GeminiAgent()

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
    scan_type: str = "fast"

@app.post("/api/scan")
async def run_scan(request: ScanRequest):
    try:
        # 1. Security Check
        validate_target(request.target)
        
        # 2. Scans
        print(f"[*] Scanning {request.target}...")
        scan_result = nmap_engine.run_scan(request.target, fast_mode=(request.scan_type == "fast"))
        
        # 3. Firewall Analysis (Scapy)
        try:
            fw_status = scapy_engine.firewall_detect(request.target)
            scan_result['firewall_analysis'] = fw_status
        except Exception as e:
            scan_result['firewall_analysis'] = {"error": str(e)}

        clean_data = sanitize_scan_data(scan_result)
        return {"status": "scan_complete", "data": clean_data}

    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze")
async def analyze_scan(data: dict):
    try:
        # 4. Token Optimization (The Filter)
        optimized_data = prune_scan_data(data)
        
        print("[*] Sending Optimized Data to Gemini...")
        report = ai_agent.analyze_scan(optimized_data) # Send SMALL data
        return {"report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))