# 🛡️ NetSec AI Auto-Pentester
> *Automated Network Vulnerability Scanning & AI-Powered Remediation Agent*

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit)
![Gemini](https://img.shields.io/badge/Google%20Gemini-8E75B2?style=for-the-badge&logo=google)
![Firebase](https://img.shields.io/badge/Firebase-FFCA28?style=for-the-badge&logo=firebase)

---

## 🚩 Problem Statement
In the modern digital landscape, network security is complex. Tools like **Nmap** and **Wireshark** are powerful but output raw technical data that is incomprehensible to the average user or junior developer. Small businesses and students often leave critical ports open (like SMB or MySQL) simply because they don't understand the cryptic logs produced by traditional scanners.

---

## 💡 The Solution
**NetSec AI** bridges the gap between complex security data and human understanding. It is an automated penetration testing tool that:
1.  **Scans** the network using industry-standard engines (Nmap & Scapy).
2.  **Analyzes** the raw logs using **Google Gemini 2.5 Flash**.
3.  **Translates** technical jargon into a clear, actionable "Fix-It" report.
4.  **Preserves** history using a secure cloud database (Firebase).

It turns *"Port 445 Open (Microsoft-DS)"* into *"High Risk: Your file sharing service is exposed. Block it using this firewall command..."*

---

## ⚙️ How It Works (Architecture)

The application follows a modular 4-stage pipeline:

### 1. Reconnaissance (The Eyes)
- Uses `python-nmap` to perform SYN Scans, Version Detection (`-sV`), and OS Detection (`-O`).
- Runs **NSE Scripts** (`--script vuln`) to check for known CVEs.

### 2. Firewall Probing (The Muscle)
- Uses **Scapy** to inject custom TCP ACK packets.
- Analyzes the response (RST vs. Drop) to determine if the firewall is **Stateful** (Secure) or **Stateless** (Vulnerable).

### 3. AI Analysis (The Brain)
- Raw JSON data is sanitized (PII removed) and sent to **Google Gemini 2.5 Flash**.
- The AI acts as a Senior Penetration Tester, correlating open ports with known exploits.

### 4. Presentation (The Face)
- A reactive **Streamlit** dashboard displays the data, allows PDF downloads, and syncs history to **Firebase Firestore**.

---

## 🛠️ Google Technologies Used

### 1. Google Gemini 2.5 Flash (via AI Studio)
| Aspect | Details |
|--------|---------|
| **Role** | The core intelligence engine |
| **Why** | Massive context window (handling large Nmap logs) and low latency for real-time scanning |
| **Implementation** | `src/ai_agent/gemini_client.py` |

### 2. Google Firebase (Auth & Firestore)
| Aspect | Details |
|--------|---------|
| **Role** | User management and data persistence |
| **Features** | Anonymous Auth for one-click "Guest Mode", Firestore for scan history |
| **Implementation** | `src/database/firestore_db.py` |

---

## 📂 Directory Structure

```text
NetSec_AI_Scanner/
│
├── main.py                     # Application Launcher
├── requirements.txt            # Dependency definitions
├── .env                        # API Keys (Gemini & Firebase)
│
├── config/                     # Configuration settings
│   └── firebase_key.json       # Service Account Credentials
│
├── src/                        # Source Code
│   ├── ai_agent/               # AI MODULE
│   │   ├── gemini_client.py    # Connects to Google AI Studio
│   │   └── prompts.py          # System Instructions for the AI
│   │
│   ├── scanner/                # SECURITY MODULE
│   │   ├── nmap_engine.py      # Port scanning logic
│   │   ├── scapy_engine.py     # Firewall testing logic
│   │   └── vuln_checker.py     # CVE extraction regex
│   │
│   ├── database/               # CLOUD MODULE
│   │   ├── firebase_auth.py    # Passwordless/Email Login
│   │   └── firestore_db.py     # Save/Load Scan History
│   │
│   ├── ui/                     # FRONTEND MODULE
│   │   └── dashboard.py        # Streamlit Web Interface
│   │
│   └── utils/                  # HELPERS
│       ├── data_sanitizer.py   # Privacy filter (Redacts MACs)
│       └── validators.py       # Input checking
│
└── logs/                       # Local storage for debug logs
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+**
- **Nmap** installed on your system (Add to PATH)
- **Npcap** (Windows only) for Scapy functionality

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/netsec-ai.git
   cd netsec-ai
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment:**
   
   Create a `.env` file in the root directory:
   ```env
   GOOGLE_API_KEY="your_gemini_key"
   FIREBASE_WEB_API_KEY="your_firebase_web_key"
   FIREBASE_CREDENTIALS_PATH="config/firebase_key.json"
   ```

4. **Run the Application:**
   ```bash
   python main.py
   ```

---

## 🌐 Deployment Guide

Since standard web hosting (like Vercel) blocks Nmap, here are your deployment options:

### Option A: Local Tunneling (Recommended)

Run the app on your laptop but give judges a public link.

1. Run your app:
   ```bash
   python main.py
   ```

2. Open a new terminal and run:
   ```bash
   ssh -R 80:localhost:8501 serveo.net
   ```

3. Copy the URL it gives you (e.g., `https://random-name.serveo.net`) and submit that.

### Option B: Streamlit Cloud (Code Demo Only)

1. Create a file named `packages.txt` in your root folder.

2. Add the following inside it:
   ```text
   nmap
   ```

3. Deploy via [share.streamlit.io](https://share.streamlit.io).

> ⚠️ **Note:** Deep scans and Scapy firewall tests might fail due to cloud permission limits, but the UI will load perfectly.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📧 Contact

For questions or support, please open an issue in the repository.