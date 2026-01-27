import os
import sys

def main():
    print("------------------------------------------------")
    print("   NetSec AI Scanner - Hackathon Edition v1.0   ")
    print("------------------------------------------------")
    print("[*] Launching Web Interface...")
    
    # Execute Streamlit from python script
    os.system("streamlit run src/ui/dashboard.py")

if __name__ == "__main__":
    main()