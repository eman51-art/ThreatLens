# 🛡️ ThreatLens

**ThreatLens** is a simple, intuitive threat intelligence web app. You give it an IP address, a domain, or a URL, and it tells you whether the target looks **Safe**, **Suspicious**, **Malicious**, or **Unknown** — along with a clear, tailored explanation.

It combines real-time security data from **VirusTotal** and **WHOIS** with **Google Gemini AI**, which analyzes the raw indicators and translates them into plain language.

---

## 🎯 What It Does

1. **Enter a Target**: Input any IP address, domain name, or full URL.
2. **Select Knowledge Level**: Choose between **Beginner**, **Intermediate**, or **Expert** to get an explanation tailored to your technical understanding.
3. **Automated Data Collection**:
   * 🦠 **VirusTotal**: Checks if major security vendors flag the target as malicious.
   * 📋 **WHOIS**: Retrieves domain registration details (e.g., owner information, creation date, age).
4. **AI-Powered Assessment**:
   * Data is passed to Google Gemini AI to generate a structured evaluation containing:
     * 🏷️ **Verdict** (*Safe*, *Suspicious*, *Malicious*, or *Unknown*)
     * 📊 **Risk Score** (0–100)
     * 📝 **Short Summary**
     * 🔍 **Key Findings**
     * 💡 **Practical Recommendation**

> **Note on AI Behavior:** The AI is strictly instructed to rely *only* on provided data — it never invents facts, avoids false assurances, and never claims a target is "100% safe."

---

## 💻 Tech Stack

* **Streamlit** – Clean, interactive web UI
* **VirusTotal API** – Threat reputation and detection engine data
* **python-whois** – Domain registration and lookup data
* **Google Gemini API** – Intelligence analysis and natural language reporting
* **Python-dotenv** – Local environment variable management

---

## 📂 Project Structure

```text
ThreatLens/
├── app.py              # Main Streamlit app (UI & Gemini logic)
├── sources.py          # Data fetchers (VirusTotal API & WHOIS logic)
├── requirements.txt    # Python dependencies
└── README.md           # Project documentation
