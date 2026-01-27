# Logic for Google Gemini API
# src/ai_agent/gemini_client.py

import os
import json
import logging
import google.generativeai as genai
from dotenv import load_dotenv

# Try relative import, fallback to absolute for testing
try:
    from .prompts import SYSTEM_PROMPT
except ImportError:
    from prompts import SYSTEM_PROMPT

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class GeminiAgent:
    def __init__(self):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            logging.error("GOOGLE_API_KEY not found in .env file.")
            raise ValueError("Missing API Key")

        genai.configure(api_key=self.api_key)
        
        # UPDATED MODEL LIST based on your check_models.py output
        # We prioritize 2.5 Flash for speed/quality, then fall back to 2.0
        self.preferred_models = [
            'gemini-2.5-flash',
            'gemini-2.0-flash',
            'gemini-flash-latest',
            'gemini-pro-latest'
        ]
        
        self.model = None
        self._initialize_model()

    def _initialize_model(self):
        """
        Iterates through preferred models and initializes the first one that works.
        """
        for model_name in self.preferred_models:
            try:
                logging.info(f"Attempting to initialize model: {model_name}")
                self.model = genai.GenerativeModel(
                    model_name=model_name,
                    system_instruction=SYSTEM_PROMPT
                )
                self.current_model_name = model_name
                logging.info(f"Selected Model: {model_name}")
                return
            except Exception as e:
                logging.warning(f"Failed to init {model_name}: {e}")
                continue
        
        # If all precise names fail, try a generic fallback
        try:
            self.model = genai.GenerativeModel('gemini-pro')
            self.current_model_name = 'gemini-pro (fallback)'
        except:
            raise RuntimeError("Could not initialize any Gemini models. Check API Key.")

    def analyze_scan(self, scan_data):
        try:
            if isinstance(scan_data, dict):
                scan_json_str = json.dumps(scan_data, indent=2)
            else:
                scan_json_str = scan_data

            logging.info(f"Sending data to {self.current_model_name}...")
            
            response = self.model.generate_content(
                f"Here is the Nmap scan result: \n\n{scan_json_str}"
            )
            return response.text

        except Exception as e:
            logging.error(f"AI Analysis Failed: {e}")
            return f"Error during analysis: {str(e)}"

if __name__ == "__main__":
    # Test Block
    mock_scan_file = "logs/temp_scans/latest_scan.json"
    if os.path.exists(mock_scan_file):
        with open(mock_scan_file, "r") as f:
            scan_data = json.load(f)
        
        agent = GeminiAgent()
        print(agent.analyze_scan(scan_data))
    else:
        print("Run nmap_engine.py first to generate data.")