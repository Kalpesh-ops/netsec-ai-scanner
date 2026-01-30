# 🛡️ NetSec AI Scanner
> *Automated Network Vulnerability Scanning & AI-Powered Intelligence Analysis*

![Python](https://img.shields.io/badge/Python-3.12+-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi)
![React](https://img.shields.io/badge/React-19.2.4-61dafb?style=for-the-badge&logo=react)
![Gemini](https://img.shields.io/badge/Google%20Gemini%202.5-8E75B2?style=for-the-badge&logo=google)
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

## ⚙️ Architecture & How It Works

The application is built on a modern **Full-Stack Architecture**:

### Backend Stack (FastAPI)
- **Server**: FastAPI with Uvicorn ASGI server
- **Scanning Engines**: Nmap, Scapy, TShark integration
- **AI Analysis**: Google Gemini 2.5 Flash for intelligent threat assessment
- **Database**: Firebase Firestore for scan history and user management
- **API**: RESTful endpoints for network scanning and threat analysis

### Frontend Stack (React + Vite)
- **Framework**: React 19.2.4 with modern hooks
- **Build Tool**: Vite 7.3.1 for fast development
- **Styling**: Tailwind CSS for responsive design
- **Animations**: Framer Motion for interactive UI
- **Visualization**: Particle network effects and threat dashboards

### 4-Stage Intelligence Pipeline

#### 1. **Reconnaissance (Network Scanning)**
- **Nmap Engine**: Performs comprehensive port scanning, service version detection, OS fingerprinting
- **Scapy Engine**: Custom firewall detection using TCP ACK packet injection
- **TShark Capture**: Optional packet-level analysis for advanced diagnostics
- **Output**: Structured JSON with port states, services, and vulnerability metadata

#### 2. **Firewall Intelligence (Dual-Engine Approach)**
- **Primary**: Scapy-based ACK packet analysis to determine firewall state
- **Fallback**: Intelligent Nmap output inference if Scapy fails (port state patterns, filtered port analysis)
- **Confidence Scoring**: Risk assessment based on open, filtered, and closed port combinations
- **Output**: Firewall detection results with confidence levels and port breakdowns

#### 3. **AI Analysis (Threat Intelligence)**
- **Model**: Google Gemini 2.5 Flash for contextual threat analysis
- **Input**: Sanitized scan data (PII removed by data_sanitizer.py)
- **Processing**: AI correlates open ports with known CVEs, exploitation risks, and business impact
- **Output**: Executive-grade threat report with CVSS scores and remediation steps

#### 4. **Presentation & Insights (React Dashboard)**
- **Real-time Display**: Live scan progress with threat indicators
- **Threat Metrics**: CVSS scoring, risk severity categorization
- **Actionable Reports**: Clear remediation steps and firewall rules
- **History Management**: Scan history with Firebase sync for multi-device access

---

## � Google Technologies Integrated

### **Google Gemini 2.5 Flash** (Threat Intelligence Engine)
| Component | Details |
|-----------|---------|
| **Purpose** | AI-powered threat analysis and vulnerability assessment |
| **Capabilities** | Context-aware analysis of scan data, CVE correlation, remediation guidance |
| **Implementation** | [src/ai_agent/gemini_client.py](src/ai_agent/gemini_client.py) |
| **Prompting** | Specialized security analysis prompts in [src/ai_agent/prompts.py](src/ai_agent/prompts.py) |
| **Integration** | Real-time API calls via `google-generativeai` SDK (v0.8.6+) |

### **Google Firebase** (Auth & Data Persistence)
| Component | Details |
|-----------|---------|
| **Authentication** | Anonymous & email-based authentication for flexible user access |
| **Database** | Firestore for storing scan history, threat reports, and user preferences |
| **Implementation** | [src/database/firebase_auth.py](src/database/firebase_auth.py) and [src/database/firestore_db.py](src/database/firestore_db.py) |
| **Security** | Service account credentials stored securely in `.env` (never committed) |
| **Sync** | Multi-device scan history synchronization with Firestore |

## 📂 Project Directory Structure

```
NetSec_AI_Scanner/
│
├── 📄 server.py                    # FastAPI entry point (core backend)
├── 📄 requirements.txt             # Python dependencies
├── 📄 README.md                    # This file
├── 📄 .env                         # Environment variables (API keys, credentials)
├── 📄 .gitignore                   # Git ignore rules
│
├── 📁 config/                      # Configuration & Credentials
│   ├── settings.py                 # Application configuration
│   └── __init__.py
│
├── 📁 src/                         # Core Application Source Code
│   │
│   ├── ai_agent/                   # AI/Intelligence Module
│   │   ├── gemini_client.py        # Google Gemini API integration
│   │   ├── check_models.py         # Model availability checker
│   │   ├── report_generator.py     # Threat report generation
│   │   └── prompts.py              # AI system prompts & instructions
│   │
│   ├── scanner/                    # Security Scanning Module
│   │   ├── nmap_engine.py          # Nmap port scanning orchestration
│   │   ├── scapy_engine.py         # Firewall detection (ACK packets)
│   │   ├── tshark_capture.py       # Packet capture analysis
│   │   └── vuln_checker.py         # Vulnerability pattern extraction
│   │
│   ├── database/                   # Cloud Database Module
│   │   ├── firebase_auth.py        # Firebase authentication logic
│   │   └── firestore_db.py         # Firestore database operations
│   │
│   ├── ui/                         # Dashboard Components
│   │   ├── dashboard.py            # Frontend integration handlers
│   │   ├── components.py           # UI component utilities
│   │   └── assets/                 # UI assets
│   │
│   └── utils/                      # Utility Functions
│       ├── data_sanitizer.py       # PII redaction & data privacy
│       ├── token_optimizer.py      # API token optimization
│       ├── validators.py           # Input validation
│       └── __init__.py
│
└── 📁 frontend/                    # React Frontend Application
    ├── index.html                  # HTML entry point
    ├── package.json                # npm dependencies (React 19.2.4, Vite 7.3.1)
    ├── package-lock.json           # Lock file for reproducible builds
    ├── vite.config.js              # Vite build configuration
    ├── tailwind.config.js          # Tailwind CSS configuration
    ├── postcss.config.js           # PostCSS configuration
    ├── eslint.config.js            # Code quality configuration
    │
    ├── src/                        # React Source Code
    │   ├── main.jsx                # React entry point
    │   ├── App.jsx                 # Main application component
    │   ├── App.css                 # Application styles
    │   ├── index.css               # Global styles
    │   │
    │   ├── components/             # React Components
    │   │   └── ParticleNetwork.jsx # Interactive particle visualization
    │   │
    │   └── assets/                 # Static assets
    │
    └── public/                     # Static files served as-is

```

### **Notes on Directory Structure:**
- ✅ **Committed to Git**: All source code, configuration templates, documentation
- ❌ **Not Committed** (.gitignore): `node_modules/`, `__pycache__/`, `.venv/`, `logs/`, `.env` (use template)
- 🔐 **Security**: Firebase credentials stored in `.env` (never versioned)
- 🚀 **Production Ready**: Modular architecture, separated frontend/backend, clear concerns

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.12+** (Tested with Python 3.12.6)
- **Nmap** installed and accessible in PATH
- **Npcap** (Windows) or libpcap (Linux/macOS) for Scapy packet injection
- **Node.js 18+** (for frontend development only)

### Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/NetSec_AI_Scanner.git
cd NetSec_AI_Scanner
```

#### 2. Backend Setup (Python)

Create a Python virtual environment:
```bash
python -m venv .venv

# Windows
.\.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate
```

Install Python dependencies:
```bash
pip install -r requirements.txt
```

#### 3. Environment Configuration

Create a `.env` file in the root directory with your credentials:
```env
# Google Gemini API Key (from Google AI Studio)
GOOGLE_API_KEY="your_gemini_api_key_here"

# Firebase Configuration
FIREBASE_WEB_API_KEY="your_firebase_web_api_key"
FIREBASE_TYPE="service_account"
FIREBASE_PROJECT_ID="your_firebase_project_id"
FIREBASE_PRIVATE_KEY_ID="your_private_key_id"
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
FIREBASE_CLIENT_EMAIL="your_service_account_email"
FIREBASE_CLIENT_ID="your_client_id"
FIREBASE_AUTH_URI="https://accounts.google.com/o/oauth2/auth"
FIREBASE_TOKEN_URI="https://oauth2.googleapis.com/token"
FIREBASE_AUTH_PROVIDER_X509_CERT_URL="https://www.googleapis.com/oauth2/v1/certs"
FIREBASE_CLIENT_X509_CERT_URL="your_cert_url"
FIREBASE_UNIVERSE_DOMAIN="googleapis.com"
```

#### 4. Frontend Setup (React) - Optional

If developing the frontend:
```bash
cd frontend
npm install
npm run dev
```

The frontend will be served at `http://localhost:5173`

### Running the Application

#### Start the Backend Server
```bash
python server.py
```

The API will be available at `http://localhost:8000`

**Available Endpoints:**
- `POST /api/scan` - Start a new network scan
- `GET /api/health` - Health check endpoint
- View full API docs at `http://localhost:8000/docs` (Swagger UI)

#### Start the Frontend (Development)
```bash
cd frontend
npm run dev
```

Open `http://localhost:5173` in your browser.

---
## ✨ Key Features

- **🎯 Intelligent Scanning**: Combines Nmap, Scapy, and TShark for comprehensive network analysis
- **🤖 AI-Powered Analysis**: Google Gemini 2.5 Flash correlates vulnerabilities with real-world exploits
- **🔐 Firewall Detection**: Dual-engine approach with fallback inference for robust firewall identification
- **📊 Executive Reports**: Clear, actionable threat reports with remediation guidance
- **☁️ Cloud Sync**: Firebase Firestore integration for multi-device scan history
- **🎨 Modern UI**: React-based dashboard with real-time visualization
- **📈 Threat Scoring**: CVSS-based severity assessment for all discovered vulnerabilities
- **🔒 Privacy-First**: PII redaction in all scanned data before AI analysis

---

## 🔌 API Usage Examples

### Start a Network Scan
```bash
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.0/24",
    "scan_type": "comprehensive",
    "enable_firewall_detection": true
  }'
```

### Response
```json
{
  "scan_id": "scan_abc123",
  "status": "running",
  "target": "192.168.1.0/24",
  "scan_type": "comprehensive",
  "started_at": "2026-01-31T03:18:34.065Z"
}
```

### Check Server Health
```bash
curl "http://localhost:8000/api/health"
```

### View API Documentation
Visit `http://localhost:8000/docs` for interactive Swagger UI documentation of all endpoints.

---
## �️ Technology Stack

### Backend
- **Framework**: FastAPI 0.128.0 (Async web framework)
- **Server**: Uvicorn 0.40.0 (ASGI server)
- **Scanning Tools**: 
  - `python-nmap` - Network reconnaissance
  - `scapy` 2.7.0 - Packet crafting & firewall testing
  - TShark - Packet capture analysis
- **AI Integration**: `google-generativeai` 0.8.6 (Gemini 2.5 Flash)
- **Database**: `firebase-admin` 7.1.0 (Firestore)
- **Data Processing**: pandas, requests
- **Environment**: `python-dotenv` for configuration

### Frontend
- **Framework**: React 19.2.4
- **Build Tool**: Vite 7.3.1
- **Styling**: Tailwind CSS 3.4
- **Animation**: Framer Motion
- **Code Quality**: ESLint, PostCSS
- **Package Manager**: npm

### Cloud Services (Google)
- **Gemini 2.5 Flash** - Threat intelligence
- **Firebase Authentication** - User management
- **Firestore Database** - Persistent storage

---

## 🌐 Deployment

The application is available at: https://netsec-ai-scanner.streamlit.app/

**Note**: The current deployment uses the legacy Streamlit interface. A modernized FastAPI + React version is in active development.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📧 Contact

For questions or support, please open an issue in the repository.