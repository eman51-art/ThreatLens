import os
import re
import ipaddress
from urllib.parse import urlparse
import base64

import requests
import whois


# ==========================================
# TARGET VALIDATION
# ==========================================

def validate_target(target, target_type):

    target = target.strip()

    if not target:
        return False, "Target cannot be empty."

    if target_type == "IP Address":

        try:
            ipaddress.ip_address(target)
            return True, "Valid IP address."

        except ValueError:
            return False, "Invalid IP address."

    elif target_type == "Domain":

        if "://" in target or "/" in target:
            return False, "Enter only the domain, for example: example.com"

        domain_pattern = (
            r"^(?=.{1,253}$)"
            r"(?:[a-zA-Z0-9]"
            r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,}$"
        )

        if re.match(domain_pattern, target):
            return True, "Valid domain."

        else:
            return False, "Invalid domain."

    elif target_type == "URL":

        try:

            parsed = urlparse(target)

            if parsed.scheme not in ("http", "https"):
                return False, "URL must start with http:// or https://"

            if not parsed.netloc:
                return False, "Invalid URL."

            return True, "Valid URL."

        except Exception:
            return False, "Invalid URL."

    return False, "Unknown target type."


# ==========================================
# VIRUSTOTAL
# ==========================================

def get_virustotal(target, target_type):

    try:

        api_key = os.getenv("VIRUSTOTAL_API_KEY")

        if not api_key:
            return {
                "source": "VirusTotal",
                "success": False,
                "data": None,
                "error": "VirusTotal API key is missing."
            }

        headers = {
            "x-apikey": api_key
        }

        if target_type == "IP Address":

            url = (
                f"https://www.virustotal.com/api/v3/"
                f"ip_addresses/{target}"
            )

        elif target_type == "Domain":

            url = (
                f"https://www.virustotal.com/api/v3/"
                f"domains/{target}"
            )

        elif target_type == "URL":

            url_id = base64.urlsafe_b64encode(
                target.encode()
            ).decode().strip("=")

            url = (
                f"https://www.virustotal.com/api/v3/"
                f"urls/{url_id}"
            )

        else:

            return {
                "source": "VirusTotal",
                "success": False,
                "data": None,
                "error": "Unsupported target type."
            }

        response = requests.get(
            url,
            headers=headers,
            timeout=15
        )

        if response.status_code != 200:

            return {
                "source": "VirusTotal",
                "success": False,
                "data": None,
                "error": (
                    f"VirusTotal returned HTTP "
                    f"{response.status_code}."
                )
            }

        result = response.json()

        return {
            "source": "VirusTotal",
            "success": True,
            "data": result,
            "error": None
        }

    except requests.exceptions.Timeout:

        return {
            "source": "VirusTotal",
            "success": False,
            "data": None,
            "error": "VirusTotal request timed out."
        }

    except requests.exceptions.RequestException as e:

        return {
            "source": "VirusTotal",
            "success": False,
            "data": None,
            "error": f"Network error: {str(e)}"
        }

    except Exception as e:

        return {
            "source": "VirusTotal",
            "success": False,
            "data": None,
            "error": f"Unexpected error: {str(e)}"
        }


# ==========================================
# WHOIS
# ==========================================

def get_whois(target, target_type):

    try:

        # Extract a plain domain from URL or IP so WHOIS
        # can still run instead of just refusing.
        if target_type == "URL":
            lookup_target = urlparse(target).netloc
            # strip port if present, e.g. example.com:8080
            lookup_target = lookup_target.split(":")[0]

        elif target_type == "Domain":
            lookup_target = target

        else:
            return {
                "source": "WHOIS",
                "success": False,
                "data": None,
                "error": (
                    "WHOIS lookup is not supported "
                    "for IP addresses."
                )
            }

        domain_info = whois.whois(lookup_target)

        if not domain_info:

            return {
                "source": "WHOIS",
                "success": False,
                "data": None,
                "error": "No WHOIS information found."
            }

        data = {
            "domain": target,
            "registrar": domain_info.registrar,
            "creation_date": str(
                domain_info.creation_date
            ),
            "expiration_date": str(
                domain_info.expiration_date
            ),
            "name_servers": domain_info.name_servers
        }

        return {
            "source": "WHOIS",
            "success": True,
            "data": data,
            "error": None
        }

    except Exception as e:

        return {
            "source": "WHOIS",
            "success": False,
            "data": None,
            "error": f"WHOIS lookup failed: {str(e)}"
        }


# ==========================================
# SOURCE REGISTRY
# ==========================================

SOURCES = {

    "VirusTotal": get_virustotal,

    "WHOIS": get_whois

}


# ==========================================
# COLLECT RESULTS
# ==========================================

def collect_results(target, target_type):

    results = {}

    for source_name, source_function in SOURCES.items():

        results[source_name] = source_function(
            target,
            target_type
        )

    return results
