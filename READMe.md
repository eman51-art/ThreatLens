🛡️ ThreatLens

ThreatLens is a simple threat intelligence web app. You give it an IP address, a domain, or a URL, and it tells you whether the target looks Safe, Suspicious, Malicious, or Unknown — with a clear explanation.

It combines real security data (VirusTotal + WHOIS) with an AI model (Google Gemini) that reads that data and explains it in plain language.

What it does
You enter a target (IP, domain, or URL) and pick your knowledge level (Beginner, Intermediate, Expert).
The app collects data from:
VirusTotal – checks if security vendors flag the target as malicious.
WHOIS – checks domain registration details (who owns it, how old it is).
This data is sent to Gemini AI, which studies it and returns:
A verdict (Safe / Suspicious / Malicious / Unknown)
A risk score (0–100)
A short summary
Key findings
A practical recommendation
Everything is shown in a clean, easy-to-read report.
The AI is instructed to only use the real data provided — it does not guess or make up facts, and it never claims something is "100% safe."

Tech Stack
Streamlit – web app interface
VirusTotal API – malware/reputation data
python-whois – domain registration data
Google Gemini API – AI-generated analysis
Python-dotenv – manage API keys locally


Project Files

├── app.py             # Main Streamlit app (UI + Gemini logic)
├── sources.py         # Fetches data from VirusTotal and WHOIS
├── requirements.txt   # Python dependencies
└── README.md          # This file


Notes & Limitations
WHOIS lookups only work for domains and URLs, not raw IP addresses.
VirusTotal's free tier has a rate limit (about 4 requests per minute).
Results are based only on available data — a "Safe" verdict means no bad signs were found, not a guarantee of full safety.
Data (VirusTotal and WHOIS) is cached temporarily to save API calls and speed up repeated checks.
Disclaimer

ThreatLens is a learning/demo project for threat intelligence analysis. It is not a replacement for professional cybersecurity tools or advice. Always use your own judgment before trusting any link, domain, or IP address.
