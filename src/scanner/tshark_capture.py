# Logic for TShark/Wireshark
import subprocess
import os
import logging
import time

class TSharkCapture:
    def __init__(self, output_dir="logs/captures"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def capture_traffic(self, interface="eth0", duration=10, target_ip=None):
        """
        Captures network traffic to a .pcap file.
        """
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"capture_{timestamp}.pcap"
        filepath = os.path.join(self.output_dir, filename)
        
        # Build command: tshark -i <interface> -a duration:<sec> -w <file>
        # Filter for target IP if provided
        cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", filepath]
        
        if target_ip and target_ip != "127.0.0.1":
            cmd.extend(["-f", f"host {target_ip}"])

        logging.info(f"Starting TShark capture on {interface} for {duration}s...")
        
        try:
            # We use Popen so it doesn't block the main thread entirely if we wanted async, 
            # but for this script, we'll wait.
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            
            if os.path.exists(filepath):
                return filepath
            else:
                return None
        except FileNotFoundError:
            logging.error("TShark not found. Please install Wireshark.")
            return None
        except Exception as e:
            logging.error(f"Capture failed: {e}")
            return None