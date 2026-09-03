import os
import json
import time

import streamlit as st
from google import genai

from sources import (
    validate_target,
    collect_results
)


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="ThreatLens",
    page_icon="🛡️",
    layout="centered"
)


# ==========================================
# GEMINI DATA PREPARATION
# ==========================================

def prepare_gemini_data(source_results):

    prepared = {}

    for source_name, result in source_results.items():

        if result["success"]:

            prepared[source_name] = {
                "success": True,
                "data": result["data"]
            }

        else:

            prepared[source_name] = {
                "success": False,
                "error": result["error"]
            }

    return prepared


# ==========================================
# GEMINI PROMPT
# ==========================================

def build_gemini_prompt(
    target,
    target_type,
    knowledge_level,
    source_data
):

    level_instructions = {

        "Beginner": (
            "Explain the result in very simple language. "
            "Avoid complex cybersecurity terminology. "
            "Clearly explain what the available evidence means."
        ),

        "Intermediate": (
            "Use moderate cybersecurity terminology. "
            "Explain the important security indicators "
            "and what they mean."
        ),

        "Expert": (
            "Provide a technical cybersecurity assessment. "
            "Discuss VirusTotal detections, reputation, "
            "WHOIS information, and other available indicators. "
            "Clearly distinguish evidence from interpretation."
        )
    }

    instructions = level_instructions[
        knowledge_level
    ]

    prompt = f"""
You are a cybersecurity threat intelligence analyst.

Your task is to assess the target using ONLY the
provided VirusTotal and WHOIS data.

IMPORTANT EVIDENCE RULES:

1. Do not invent facts.

2. Do not assume information that is not provided.

3. Clearly distinguish:
   - Evidence: what the sources actually report.
   - Interpretation: what those observations may indicate.
   - Uncertainty: what cannot be determined.

4. VirusTotal "reputation" is NOT automatically a
   security trust score.

5. Do not describe VirusTotal reputation as:
   "trust score", "safety score", or "guaranteed safety".

6. A lack of malicious detections does NOT prove that
   a target is completely safe.

7. WHOIS being unavailable or unsupported for a URL
   must NOT by itself increase the risk score.

8. Do not claim that a website is guaranteed safe.

9. Do not claim that a user can safely interact with
   a target as a certainty.

10. If the available evidence is insufficient,
    use the verdict "Unknown".

TARGET:
{target}

TARGET TYPE:
{target_type}

KNOWLEDGE LEVEL:
{knowledge_level}

EXPLANATION STYLE:
{instructions}

THREAT INTELLIGENCE DATA:
{source_data}

Return ONLY valid JSON.

Use exactly this structure:

{{
    "verdict": "Safe",
    "risk_score": 0,
    "summary": "Short evidence-based explanation",
    "key_findings": [
        "Finding 1",
        "Finding 2"
    ],
    "recommendation": "Practical recommendation"
}}

VERDICT RULES:

- "Safe":
  Use only when the available evidence contains
  no significant malicious or suspicious indicators.

- "Suspicious":
  Use when there are meaningful suspicious indicators
  but the evidence does not clearly establish maliciousness.

- "Malicious":
  Use when the available evidence contains strong
  malicious indicators.

- "Unknown":
  Use when there is not enough reliable evidence
  to make a meaningful assessment.

RISK SCORE:

- Must be an integer from 0 to 100.
- The score must reflect the available evidence.
- Do not assign a high risk score simply because
  WHOIS data is unavailable.
- Do not assign 0 merely because no malicious
  detections were found if other suspicious evidence exists.

SUMMARY:

- Keep it concise.
- State what the available sources actually show.
- Do not make absolute safety claims.

KEY FINDINGS:

- Every finding must be supported by the provided data.
- Do not call VirusTotal reputation a trust score.
- Do not invent dates, organizations, detections,
  or security events.

RECOMMENDATION:

- Give practical advice based on the evidence.
- Avoid absolute statements such as:
  "You can safely visit this website."
"""

    return prompt


# ==========================================
# GEMINI API
# ==========================================

def call_gemini(prompt):

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:

        return {
            "success": False,
            "text": None,
            "error": "Gemini API key is missing."
        }

    client = genai.Client(
        api_key=api_key
    )

    # Valid and supported model endpoints (updated Sept 2026)
    candidate_models = [
        "gemini-3.6-flash",
        "gemini-flash-latest"
    ]

    # How many times to retry a model if it returns a
    # temporary "high demand" (503) error, and how long
    # to wait between attempts (seconds).
    max_retries_per_model = 2
    retry_delay_seconds = 3

    all_errors = []

    for model_name in candidate_models:
        for attempt in range(max_retries_per_model + 1):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt
                )

                return {
                    "success": True,
                    "text": response.text,
                    "error": None
                }
            except Exception as e:
                error_text = str(e)
                all_errors.append(
                    f"[{model_name}, attempt {attempt + 1}] "
                    f"{error_text}"
                )

                is_temporary_overload = (
                    "503" in error_text
                    or "UNAVAILABLE" in error_text
                )

                if (
                    is_temporary_overload
                    and attempt < max_retries_per_model
                ):
                    time.sleep(retry_delay_seconds)
                    continue

                # Non-retryable error, or retries exhausted:
                # move on to the next candidate model.
                break

    combined_error = " | ".join(all_errors)

    return {
        "success": False,
        "text": None,
        "error": (
            f"Gemini request failed for all models: "
            f"{combined_error}"
        )
    }


# ==========================================
# GEMINI JSON PARSER
# ==========================================

def parse_gemini_response(response_text):

    try:

        cleaned = response_text.strip()

        # Remove Markdown code fences
        if cleaned.startswith("```"):

            lines = cleaned.splitlines()

            if lines:
                lines = lines[1:]

            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]

            cleaned = "\n".join(lines).strip()

        # Find JSON object
        start = cleaned.find("{")
        end = cleaned.rfind("}")

        if start == -1 or end == -1:
            raise ValueError("No JSON object found.")

        cleaned = cleaned[start:end + 1]

        data = json.loads(cleaned)

        # Validate verdict
        allowed_verdicts = {
            "Safe",
            "Suspicious",
            "Malicious",
            "Unknown"
        }

        verdict = data.get(
            "verdict",
            "Unknown"
        )

        if verdict not in allowed_verdicts:
            verdict = "Unknown"

        # Validate risk score
        risk_score = data.get(
            "risk_score",
            0
        )

        try:
            risk_score = int(risk_score)
        except Exception:
            risk_score = 0

        risk_score = max(
            0,
            min(100, risk_score)
        )

        # Validate findings
        key_findings = data.get(
            "key_findings",
            []
        )

        if not isinstance(
            key_findings,
            list
        ):
            key_findings = []

        return {
            "verdict": verdict,
            "risk_score": risk_score,
            "summary": data.get(
                "summary",
                "No summary available."
            ),
            "key_findings": key_findings,
            "recommendation": data.get(
                "recommendation",
                "No recommendation available."
            )
        }

    except Exception:

        return {
            "verdict": "Unknown",
            "risk_score": 0,
            "summary": (
                "Unable to parse Gemini response."
            ),
            "key_findings": [],
            "recommendation": (
                "Please try the analysis again."
            )
        }


# ==========================================
# UI
# ==========================================

st.title("🛡️ ThreatLens")

st.subheader(
    "Simple Threat Intelligence Analyzer"
)

st.write(
    "Check whether an IP address, domain, "
    "or URL appears safe or risky."
)


# ==========================================
# INPUTS
# ==========================================

target_type = st.selectbox(
    "Target Type",
    [
        "IP Address",
        "Domain",
        "URL"
    ]
)

knowledge_level = st.selectbox(
    "Knowledge Level",
    [
        "Beginner",
        "Intermediate",
        "Expert"
    ]
)

target = st.text_input(
    "Enter Target",
    placeholder="example.com"
)

analyze = st.button(
    "🔍 Analyze"
)


# ==========================================
# ANALYSIS
# ==========================================

if analyze:

    # ------------------------------
    # VALIDATION
    # ------------------------------

    is_valid, validation_message = (
        validate_target(
            target,
            target_type
        )
    )

    if not is_valid:

        st.error(
            validation_message
        )

        st.stop()

    st.success(
        validation_message
    )


    # ------------------------------
    # COLLECT SOURCE DATA
    # ------------------------------

    with st.spinner(
        "Collecting threat intelligence..."
    ):

        source_results = collect_results(
            target,
            target_type
        )


    # ------------------------------
    # PREPARE GEMINI DATA
    # ------------------------------

    gemini_data = prepare_gemini_data(
        source_results
    )


    # ------------------------------
    # BUILD PROMPT
    # ------------------------------

    prompt = build_gemini_prompt(
        target,
        target_type,
        knowledge_level,
        gemini_data
    )


    # ------------------------------
    # GEMINI ANALYSIS
    # ------------------------------

    with st.spinner(
        "Generating security assessment..."
    ):

        gemini_result = call_gemini(
            prompt
        )


    if not gemini_result["success"]:

        st.error(
            gemini_result["error"]
        )

        st.stop()


    # ------------------------------
    # PARSE RESPONSE
    # ------------------------------

    assessment = parse_gemini_response(
        gemini_result["text"]
    )


    # ==================================
    # DISPLAY ASSESSMENT
    # ==================================

    st.divider()

    st.subheader(
        "🛡️ Security Assessment"
    )


    col1, col2 = st.columns(2)


    with col1:

        st.metric(
            "Verdict",
            assessment["verdict"]
        )


    with col2:

        st.metric(
            "Risk Score",
            f'{assessment["risk_score"]}/100'
        )


    st.write(
        "### Summary"
    )

    st.write(
        assessment["summary"]
    )


    st.write(
        "### Key Findings"
    )

    if assessment["key_findings"]:

        for finding in assessment[
            "key_findings"
        ]:

            st.write(
                f"• {finding}"
            )

    else:

        st.write(
            "No key findings available."
        )


    st.write(
        "### Recommendation"
    )

    st.info(
        assessment["recommendation"]
    )


    # ==================================
    # SOURCE STATUS
    # ==================================

    st.divider()

    st.subheader(
        "📡 Source Status"
    )


    for source_name, result in (
        source_results.items()
    ):

        if result["success"]:

            st.success(
                f"{source_name}: Success"
            )

        else:

            st.warning(
                f"{source_name}: "
                f"{result['error']}"
            )
