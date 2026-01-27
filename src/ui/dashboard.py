import streamlit as st
import sys
import os
import time

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from src.scanner.nmap_engine import NmapScanner
from src.scanner.scapy_engine import ScapyEngine
from src.ai_agent.gemini_client import GeminiAgent
from src.database.firebase_auth import FirebaseAuth
from src.database.firestore_db import FirestoreDB
from src.utils.validators import validate_target
from src.utils.data_sanitizer import sanitize_scan_data
from src.scanner.vuln_checker import VulnChecker

# Page Config (Wide Mode is Essential here)
st.set_page_config(
    page_title="NetSec AI Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS to maximize screen real estate
st.markdown("""
<style>
    .report-container { background-color: #1E1E1E; padding: 20px; border-radius: 10px; border: 1px solid #333; }
    .stAlert { padding: 0.5rem; }
</style>
""", unsafe_allow_html=True)

# Session State
if "user" not in st.session_state: st.session_state.user = None
if "scan_report" not in st.session_state: st.session_state.scan_report = None
if "scan_data" not in st.session_state: st.session_state.scan_data = None
if "scan_status" not in st.session_state: st.session_state.scan_status = "Ready"

def main():
    # --- HEADER ---
    st.title("🛡️ NetSec AI Auto-Pentester")

    # --- SIDEBAR (Controls & Login) ---
    with st.sidebar:
        st.header("⚙️ Control Panel")
        
        # 1. Login Logic
        if st.session_state.user:
            st.success(f"👤 {st.session_state.user.get('email', 'Guest')}")
            if st.button("Logout", type="primary", use_container_width=True):
                st.session_state.user = None
                st.rerun()
        else:
            if st.button("🚀 Guest Login (Fast)", use_container_width=True):
                auth = FirebaseAuth()
                st.session_state.user = auth.sign_in_anonymous()
                st.rerun()
            
            with st.expander("Admin Login"):
                email = st.text_input("Email")
                pwd = st.text_input("Password", type="password")
                if st.button("Sign In"):
                    auth = FirebaseAuth()
                    st.session_state.user = auth.sign_in_email(email, pwd)
                    st.rerun()

        st.divider()

        # 2. Scan Inputs
        st.subheader("🎯 Target")
        target_ip = st.text_input("IP / Domain", value="127.0.0.1")
        scan_mode = st.selectbox("Scan Profile", ["Fast Scan (Top 100)", "Deep Scan (Full + Vuln)"])
        
        if st.button("🔥 START ATTACK SIMULATION", type="primary", use_container_width=True):
            if not validate_target(target_ip):
                st.error("Invalid IP/Hostname")
            else:
                run_scan_pipeline(target_ip, scan_mode)

        # 3. Compact Logs (In Sidebar)
        st.divider()
        st.subheader("📜 Live Logs")
        status_box = st.empty()
        status_box.info(st.session_state.scan_status)

    # --- MAIN CONTENT AREA (The "Large Part") ---
    
    # We use a container to make the report prominent
    report_area = st.container()

    with report_area:
        if st.session_state.scan_report:
            st.markdown("### 📝 Security Assessment Report")
            
            # Use tabs to organize the large output
            tab_ai, tab_tech, tab_history = st.tabs(["🤖 AI Analyst Report", "💻 Technical Data", "🗄️ History"])
            
            with tab_ai:
                # The Report takes center stage
                st.markdown(f'<div class="report-container">{st.session_state.scan_report}</div>', unsafe_allow_html=True)
                
                # Download button right below report
                st.download_button(
                    "📥 Download PDF/Markdown", 
                    st.session_state.scan_report, 
                    file_name="security_report.md"
                )

            with tab_tech:
                # Firewall & Port Data
                col_fw, col_vuln = st.columns(2)
                with col_fw:
                    st.info("Firewall Status")
                    fw_data = st.session_state.scan_data.get("firewall_analysis", {})
                    st.json(fw_data)
                
                with col_vuln:
                    st.error("Identified Vulnerabilities")
                    vulns = VulnChecker.extract_cves(st.session_state.scan_data)
                    if vulns:
                        st.write(vulns)
                    else:
                        st.success("No Common CVEs found in script output.")
                
                with st.expander("View Full Raw JSON"):
                    st.json(st.session_state.scan_data)

            with tab_history:
                if st.session_state.user:
                    db = FirestoreDB()
                    history = db.get_history(st.session_state.user['uid'])
                    if history:
                        for h in history:
                            st.text(f"{h.get('timestamp')} - {h.get('target')}")
                    else:
                        st.info("No history found.")
                else:
                    st.warning("Login to view history.")
        
        else:
            # Welcome Placeholder
            st.info("👋 Ready to Scan. Enter a target in the sidebar to begin.")
            st.markdown("""
            #### System Capabilities:
            * **Nmap Engine:** Port Discovery & Service Versioning
            * **Scapy Engine:** Packet Injection & Firewall State Detection
            * **Gemini AI:** Automatic CVE Analysis & Remediation Plans
            """)

def run_scan_pipeline(target, mode):
    # 1. Setup Status Container
    # We use a context manager so the user sees progress LIVE
    with st.status("🚀 Launching Cyber Kill Chain...", expanded=True) as status:
        
        # 2. Init
        status.write("🛠️ Initializing Nmap & Scapy Engines...")
        nmap = NmapScanner()
        scapy = ScapyEngine()
        agent = GeminiAgent()
        db = FirestoreDB() if st.session_state.user else None
        
        # 3. NMAP SCAN
        status.write(f"🔍 Scanning Target: {target} (Please wait)...")
        is_fast = "Fast" in mode
        scan_res = nmap.run_scan(target, fast_mode=is_fast)
        
        if "error" in scan_res:
            status.update(label="❌ Scan Failed", state="error")
            st.error(scan_res['error'])
            return

        # 4. SCAPY FIREWALL TEST
        status.write("🛡️ Probing Firewall Rules...")
        fw_res = scapy.firewall_detect(target, port=445)
        scan_res["firewall_analysis"] = fw_res

        # 5. AI ANALYSIS
        status.write("🧠 Sanitizing Data & Sending to Gemini AI...")
        clean_data = sanitize_scan_data(scan_res)
        ai_report = agent.analyze_scan(clean_data)

        # 6. SAVE TO DB
        if db:
            status.write("☁️ Syncing results to Firebase...")
            db.save_scan(st.session_state.user['uid'], target, scan_res, ai_report)

        # 7. FINALIZE
        st.session_state.scan_data = scan_res
        st.session_state.scan_report = ai_report
        st.session_state.scan_status = "✅ Scan Complete"
        
        status.update(label="✅ Assessment Complete!", state="complete")
    
    # Force a refresh ONLY AT THE END to show the results
    st.rerun()

if __name__ == "__main__":
    main()