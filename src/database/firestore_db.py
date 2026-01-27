# Logic for Firestore Database
import firebase_admin
from firebase_admin import credentials, firestore
import os
import logging
from datetime import datetime

class FirestoreDB:
    def __init__(self):
        # Prevent initializing the app twice in Streamlit
        if not firebase_admin._apps:
            cred_path = os.getenv("FIREBASE_CREDENTIALS_PATH", "config/firebase_key.json")
            
            if os.path.exists(cred_path):
                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred)
                self.db = firestore.client()
                logging.info("Firestore connected.")
            else:
                logging.error(f"Firebase key not found at {cred_path}")
                self.db = None
        else:
            self.db = firestore.client()

    def save_scan(self, user_id, target_ip, scan_data, ai_report):
        if not self.db: return False
        
        try:
            doc_ref = self.db.collection("users").document(user_id).collection("scans").document()
            doc_ref.set({
                "target": target_ip,
                "timestamp": datetime.now(),
                "scan_data": scan_data,
                "ai_report": ai_report
            })
            return True
        except Exception as e:
            logging.error(f"Failed to save scan: {e}")
            return False

    def get_history(self, user_id):
        if not self.db: return []
        
        try:
            docs = self.db.collection("users").document(user_id).collection("scans")\
                .order_by("timestamp", direction=firestore.Query.DESCENDING).stream()
            
            return [{"id": d.id, **d.to_dict()} for d in docs]
        except Exception as e:
            logging.error(f"Failed to fetch history: {e}")
            return []