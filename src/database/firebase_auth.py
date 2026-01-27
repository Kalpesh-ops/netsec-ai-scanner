import os
import requests
import logging
from dotenv import load_dotenv

load_dotenv()

class FirebaseAuth:
    def __init__(self):
        self.api_key = os.getenv("FIREBASE_WEB_API_KEY")
        if not self.api_key:
            logging.error("FIREBASE_WEB_API_KEY is missing")

    def sign_in_anonymous(self):
        """
        Creates a 'Passwordless' Anonymous account.
        This gives the user a real UID to save data to Firestore.
        """
        # The signUp endpoint with no email/password creates an anonymous user
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
        payload = {"returnSecureToken": True}
        
        try:
            r = requests.post(url, json=payload)
            data = r.json()
            
            if "error" in data:
                return {"error": data["error"]["message"]}
            
            return {
                "uid": data["localId"],
                "token": data["idToken"],
                "email": "Guest (Anonymous)"
            }
        except Exception as e:
            return {"error": str(e)}

    def sign_in_email(self, email, password):
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={self.api_key}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        return self._make_request(url, payload)

    def sign_up_email(self, email, password):
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={self.api_key}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        return self._make_request(url, payload)

    def _make_request(self, url, payload):
        try:
            r = requests.post(url, json=payload)
            data = r.json()
            if "error" in data:
                return {"error": data["error"]["message"]}
            return {
                "uid": data["localId"],
                "token": data["idToken"],
                "email": data.get("email", "User")
            }
        except Exception as e:
            return {"error": str(e)}