"""
SecureMail - Lightweight Email Security & Threat Analysis Engine
FastAPI application with deterministic heuristic analysis for phishing, spam, and spoofing.
"""

from __future__ import annotations

import email
from email import policy
from email.message import EmailMessage
import html
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI(
    title="SecureMail",
    description="Intuitive, lightweight email security scanner",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

# ==============================================================================
# Heuristic Configuration & Rules
# ==============================================================================

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".vbs", ".iso", ".cmd",
    ".pif", ".hta", ".ps1", ".msi", ".jar", ".wsf", ".cpl", ".reg"
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "cf", "gq", "buzz", "club",
    "work", "loan", "support", "vip", "icu", "click", "rest"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly",
    "ow.ly", "goo.gl", "cutt.ly", "rebrand.ly"
}

# Urgency and phishing keyword patterns
URGENT_CREDENTIAL_PATTERNS = [
    (r"\bverify\s+(your\s+)?(account|identity|email|wallet|bank)\b", "Verification lure", 20),
    (r"\b(account|access|service)\s+(has\s+been\s+)?(suspended|locked|terminated|restricted|disabled)\b", "Account suspension threat", 25),
    (r"\bunauthorized\s+(access|activity|transaction|login|attempt)\b", "Unauthorized access claim", 25),
    (r"\b(password|credential|security)\s+(reset|expired|update|verification)\b", "Credential reset urgency", 20),
    (r"\bwire\s+transfer\b", "Wire transfer request", 25),
    (r"\b(crypto|cryptocurrency|bitcoin|btc|ethereum|eth|wallet)\b", "Cryptocurrency solicitation", 15),
    (r"\b(gift\s*card|itunes|steam\s*card|amazon\s*gift)\b", "Gift card demand", 30),
    (r"\b(urgent|immediate|critical)\s+action\s+required\b", "Manufactured urgency prompt", 15),
    (r"\b(unusual|suspicious)\s+sign-?in\s+(attempt|activity)\b", "Fraudulent login alert", 20),
    (r"\b(update|confirm)\s+your\s+billing\s+(information|details)\b", "Financial harvesting lure", 20),
    (r"\b(past\s*due|overdue|outstanding)\s+(invoice|payment|bill)\b", "Fraudulent invoice/billing prompt", 15),
    (r"\bclick\s+(here|below|this\s+link)\s+to\s+(login|verify|unlock|reactivate)\b", "Call-to-action to external portal", 20),
    (r"\bfailure\s+to\s+respond\s+within\s+\d+\s*(hours|days|mins)\b", "High-pressure deadline coercion", 20),
]

SPAM_KEYWORDS = [
    (r"\b(100%\s*free|free\s*gift|claim\s*your\s*prize|congratulations\s*you\s*won)\b", "Prize / giveaway spam indicator", 15),
    (r"\b(casino|jackpot|poker|slots|viagra|cialis|weight\s*loss)\b", "Unsolicited promotional / pharmaceutical spam", 20),
    (r"\b(opt\s*out|unsubscribe\s+here|click\s+here\s+to\s+unsubscribe)\b", "Commercial mass-mailing signature", 5),
    (r"\b(make\s*money\s*fast|income\s*opportunity|earn\s+\$\d+)\b", "Get-rich-quick financial spam", 20),
]

IP_HOST_REGEX = re.compile(r"^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?$", re.IGNORECASE)
GENERIC_URL_REGEX = re.compile(r'https?://[^\s<>"\')]+', re.IGNORECASE)
EMAIL_EXTRACT_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')


# ==============================================================================
# Data Models
# ==============================================================================

class RedFlag(BaseModel):
    title: str
    description: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    points: int


class AttachmentInfo(BaseModel):
    filename: str
    size: int
    content_type: str
    is_suspicious: bool
    risk_reason: Optional[str] = None


class ExtractedUrl(BaseModel):
    url: str
    display_text: Optional[str] = None
    is_deceptive: bool = False
    is_ip_based: bool = False
    is_suspicious_tld: bool = False
    is_shortener: bool = False
    domain: str = ""
    notes: List[str] = []


class EmailScanResult(BaseModel):
    verdict: str  # "LEGITIMATE", "SPAM", "PHISHING"
    verdict_badge_class: str
    threat_score: int  # 0 to 100
    threat_level: str  # "Low Risk", "Elevated Risk", "Severe Threat"
    rationale: str
    headers: Dict[str, str]
    sender_domain: str
    return_path_domain: str
    auth_status: Dict[str, str]
    attachments: List[AttachmentInfo]
    extracted_urls: List[ExtractedUrl]
    red_flags: List[RedFlag]
    body_excerpt: str
    has_html: bool


# ==============================================================================
# Helper Functions
# ==============================================================================

def clean_domain(addr: str) -> str:
    """Extract and normalize domain from an email address or host string."""
    if not addr:
        return ""
    addr = addr.strip().strip("<>\"' ")
    if "@" in addr:
        addr = addr.split("@")[-1]
    return addr.lower().strip("[]").strip()


def parse_email_address(raw_header: str) -> Tuple[str, str]:
    """Returns (display_name, email_address)."""
    if not raw_header:
        return ("", "")
    realname, addr = email.utils.parseaddr(raw_header)
    return (realname.strip(), addr.strip().lower())


# ==============================================================================
# Core Heuristic Analysis Engine
# ==============================================================================

class EmailHeuristicScanner:
    """
    Deterministic inspection engine checking email MIME structure,
    header authenticity, keywords, URLs, and attachment risks.
    """

    def __init__(self, raw_bytes: bytes):
        self.raw_bytes = raw_bytes
        self.msg: EmailMessage = email.message_from_bytes(
            raw_bytes,
            policy=policy.default
        )
        self.red_flags: List[RedFlag] = []
        self.score: int = 0

    def add_flag(self, title: str, description: str, severity: str, points: int):
        self.red_flags.append(
            RedFlag(
                title=title,
                description=description,
                severity=severity,
                points=points
            )
        )
        self.score += points

    def scan(self) -> EmailScanResult:
        # 1. Parse standard headers
        from_raw = str(self.msg.get("From", "")).strip()
        from_display, from_addr = parse_email_address(from_raw)
        from_domain = clean_domain(from_addr)

        return_path_raw = str(self.msg.get("Return-Path", "")).strip()
        _, return_path_addr = parse_email_address(return_path_raw)
        return_path_domain = clean_domain(return_path_addr)

        reply_to_raw = str(self.msg.get("Reply-To", "")).strip()
        _, reply_to_addr = parse_email_address(reply_to_raw)
        reply_to_domain = clean_domain(reply_to_addr)

        subject = str(self.msg.get("Subject", "")).strip()
        date = str(self.msg.get("Date", "Unknown")).strip()
        message_id = str(self.msg.get("Message-ID", "")).strip()

        # 2. Extract Body and Attachments
        body_text, body_html, attachments = self._extract_payloads()

        # 3. Header Spoofing Checks
        self._check_header_spoofing(
            from_display, from_addr, from_domain,
            return_path_addr, return_path_domain,
            reply_to_addr, reply_to_domain
        )

        # 4. Authentication Checks (SPF, DKIM, DMARC)
        auth_status = self._check_authentication_results()

        # 5. Attachment Checks
        self._check_attachments(attachments)

        # 6. URL & Link Target Analysis
        extracted_urls = self._analyze_urls(body_text, body_html, from_domain)

        # 7. Phishing & Urgency Keyword Checks
        combined_text = f"{subject}\n{body_text}"
        self._check_urgency_keywords(combined_text)

        # 8. Compute Verdict and Final Score
        verdict, badge_class, threat_level, rationale = self._compute_verdict(
            auth_status, attachments, extracted_urls
        )

        # Truncate body excerpt safely for display
        body_excerpt = body_text.strip()
        if len(body_excerpt) > 500:
            body_excerpt = body_excerpt[:497] + "..."

        headers_summary = {
            "From": from_raw or "(Missing)",
            "Return-Path": return_path_raw or "(Missing)",
            "Reply-To": reply_to_raw or "(None specified)",
            "Subject": subject or "(No Subject)",
            "Date": date,
            "Message-ID": message_id or "(Missing)",
        }

        return EmailScanResult(
            verdict=verdict,
            verdict_badge_class=badge_class,
            threat_score=min(100, max(0, self.score)),
            threat_level=threat_level,
            rationale=rationale,
            headers=headers_summary,
            sender_domain=from_domain or "Unknown",
            return_path_domain=return_path_domain or "Unknown",
            auth_status=auth_status,
            attachments=attachments,
            extracted_urls=extracted_urls,
            red_flags=self.red_flags,
            body_excerpt=body_excerpt or "(Empty body content)",
            has_html=bool(body_html),
        )

    def _extract_payloads(self) -> Tuple[str, str, List[AttachmentInfo]]:
        body_text_parts: List[str] = []
        body_html_parts: List[str] = []
        attachments: List[AttachmentInfo] = []

        for part in self.msg.walk():
            # Skip container multipart wrappers
            if part.is_multipart():
                continue

            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            # Check if this part is an attachment
            if "attachment" in content_disposition.lower() or filename:
                fname = filename or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""
                content_type = part.get_content_type()
                attachments.append(
                    AttachmentInfo(
                        filename=fname,
                        size=len(payload),
                        content_type=content_type,
                        is_suspicious=False,
                    )
                )
            else:
                # Text or HTML body part
                content_type = part.get_content_type()
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text_content = payload.decode(charset, errors="replace")
                        if content_type == "text/plain":
                            body_text_parts.append(text_content)
                        elif content_type == "text/html":
                            body_html_parts.append(text_content)
                except Exception:
                    pass

        # If plain text was absent but HTML exists, strip HTML tags for text analysis
        body_text = "\n".join(body_text_parts)
        body_html = "\n".join(body_html_parts)
        if not body_text and body_html:
            clean_re = re.compile(r"<[^>]+>")
            body_text = clean_re.sub(" ", body_html)

        return body_text, body_html, attachments

    def _check_header_spoofing(
        self,
        from_display: str,
        from_addr: str,
        from_domain: str,
        return_path_addr: str,
        return_path_domain: str,
        reply_to_addr: str,
        reply_to_domain: str,
    ):
        # 1. Missing From header
        if not from_addr:
            self.add_flag(
                title="Missing Sender Address",
                description="The email does not contain a valid From address in the headers.",
                severity="HIGH",
                points=30,
            )
            return

        # 2. Display Name Email Spoofing
        # E.g. Display Name contains "support@paypal.com" but From address is "attacker@malicious.com"
        emails_in_display = EMAIL_EXTRACT_REGEX.findall(from_display)
        if emails_in_display:
            display_domain = clean_domain(emails_in_display[0])
            if display_domain and display_domain != from_domain:
                self.add_flag(
                    title="Display Name Spoofing Detected",
                    description=(
                        f"The sender's display name ('{from_display}') mimics an official address ({emails_in_display[0]}), "
                        f"but the actual sending address is {from_addr}."
                    ),
                    severity="CRITICAL",
                    points=35,
                )

        # 3. From vs Return-Path Domain Mismatch
        if return_path_domain and from_domain:
            if from_domain != return_path_domain:
                # Check for shared root domain (e.g., mail.google.com and google.com)
                from_parts = from_domain.split(".")
                return_parts = return_path_domain.split(".")
                root_match = (
                    len(from_parts) >= 2
                    and len(return_parts) >= 2
                    and from_parts[-2:] == return_parts[-2:]
                )

                if not root_match:
                    self.add_flag(
                        title="Sender & Return-Path Domain Mismatch",
                        description=(
                            f"The visible From domain ('{from_domain}') does not match the actual Return-Path domain ('{return_path_domain}'). "
                            "This is a primary indicator of sender header spoofing."
                        ),
                        severity="HIGH",
                        points=30,
                    )

        # 4. Reply-To Domain Divergence
        if reply_to_domain and from_domain and reply_to_domain != from_domain:
            from_parts = from_domain.split(".")
            reply_parts = reply_to_domain.split(".")
            root_match = (
                len(from_parts) >= 2
                and len(reply_parts) >= 2
                and from_parts[-2:] == reply_parts[-2:]
            )
            if not root_match:
                self.add_flag(
                    title="Divergent Reply-To Address",
                    description=(
                        f"Replies are configured to go to '{reply_to_addr}' ({reply_to_domain}), "
                        f"which differs from the sender domain ('{from_domain}')."
                    ),
                    severity="MEDIUM",
                    points=15,
                )

    def _check_authentication_results(self) -> Dict[str, str]:
        auth_status = {"spf": "neutral", "dkim": "neutral", "dmarc": "neutral"}

        auth_headers: List[str] = []
        for h in ["Authentication-Results", "ARC-Authentication-Results", "Received-SPF"]:
            for val in self.msg.get_all(h, []):
                auth_headers.append(str(val).lower())

        combined_auth = " ".join(auth_headers)

        # Check SPF
        if "spf=fail" in combined_auth or "received-spf: fail" in combined_auth:
            auth_status["spf"] = "fail"
            self.add_flag(
                title="SPF Authentication Failed",
                description="The sending mail server is not authorized by the sender domain's SPF record (spf=fail).",
                severity="HIGH",
                points=25,
            )
        elif "spf=softfail" in combined_auth:
            auth_status["spf"] = "softfail"
            self.add_flag(
                title="SPF Softfail Detected",
                description="The sending mail server failed strict SPF validation (spf=softfail).",
                severity="MEDIUM",
                points=15,
            )
        elif "spf=pass" in combined_auth:
            auth_status["spf"] = "pass"

        # Check DKIM
        if "dkim=fail" in combined_auth:
            auth_status["dkim"] = "fail"
            self.add_flag(
                title="DKIM Signature Verification Failed",
                description="The cryptographic DKIM signature on the message could not be verified or was altered in transit (dkim=fail).",
                severity="HIGH",
                points=25,
            )
        elif "dkim=pass" in combined_auth:
            auth_status["dkim"] = "pass"

        # Check DMARC
        if "dmarc=fail" in combined_auth:
            auth_status["dmarc"] = "fail"
            self.add_flag(
                title="DMARC Policy Violation",
                description="The message failed the domain owner's DMARC alignment policy (dmarc=fail).",
                severity="CRITICAL",
                points=35,
            )
        elif "dmarc=pass" in combined_auth:
            auth_status["dmarc"] = "pass"

        return auth_status

    def _check_attachments(self, attachments: List[AttachmentInfo]):
        for att in attachments:
            fname_lower = att.filename.lower()
            name_parts = fname_lower.split(".")

            # Double extension attack (e.g. statement.pdf.exe)
            if len(name_parts) > 2:
                ext = f".{name_parts[-1]}"
                penultimate = f".{name_parts[-2]}"
                if ext in DANGEROUS_EXTENSIONS:
                    att.is_suspicious = True
                    att.risk_reason = f"Dangerous double-extension technique ({penultimate}{ext})"
                    self.add_flag(
                        title=f"Malicious Double Extension: {att.filename}",
                        description=(
                            f"Attachment '{att.filename}' uses a deceptive double extension ({penultimate}{ext}) "
                            "to disguise an executable binary as a document."
                        ),
                        severity="CRITICAL",
                        points=45,
                    )
                    continue

            # Dangerous standalone extension
            for ext in DANGEROUS_EXTENSIONS:
                if fname_lower.endswith(ext):
                    att.is_suspicious = True
                    att.risk_reason = f"Executable / script payload ({ext})"
                    self.add_flag(
                        title=f"Dangerous Attachment: {att.filename}",
                        description=(
                            f"Attachment '{att.filename}' is a high-risk executable or script ({ext}) capable of executing arbitrary code."
                        ),
                        severity="CRITICAL",
                        points=40,
                    )
                    break

            # Macro-enabled document
            for ext in MACRO_EXTENSIONS:
                if fname_lower.endswith(ext):
                    att.is_suspicious = True
                    att.risk_reason = f"Macro-enabled document ({ext})"
                    self.add_flag(
                        title=f"Macro-Enabled Attachment: {att.filename}",
                        description=f"Attachment '{att.filename}' contains embedded VBA macros, often weaponized to deliver malware.",
                        severity="HIGH",
                        points=25,
                    )
                    break

            # Archive file (often used to bypass perimeter filters)
            for ext in ARCHIVE_EXTENSIONS:
                if fname_lower.endswith(ext):
                    att.is_suspicious = True
                    att.risk_reason = f"Compressed archive ({ext})"
                    self.add_flag(
                        title=f"Compressed Archive Attachment: {att.filename}",
                        description=f"Attachment '{att.filename}' is a compressed archive. Verify the payload before extraction.",
                        severity="LOW",
                        points=10,
                    )
                    break

    def _analyze_urls(self, body_text: str, body_html: str, sender_domain: str) -> List[ExtractedUrl]:
        results: List[ExtractedUrl] = []
        seen_urls = set()
        seen_tld_domains = set()
        seen_shorteners = set()

        # 1. Parse HTML links if present: detect text vs href mismatch
        if body_html:
            a_tag_pattern = re.compile(
                r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                re.IGNORECASE | re.DOTALL
            )
            for match in a_tag_pattern.finditer(body_html):
                dest_url = match.group(1).strip()
                raw_display = match.group(2).strip()
                clean_display = re.sub(r"<[^>]+>", "", raw_display).strip()

                if not dest_url.startswith(("http://", "https://")):
                    continue

                if dest_url in seen_urls:
                    continue
                seen_urls.add(dest_url)

                entry = self._inspect_url(dest_url, clean_display, seen_tld_domains, seen_shorteners)
                results.append(entry)

        # 2. Extract plaintext URLs
        raw_text_urls = GENERIC_URL_REGEX.findall(body_text)
        for url in raw_text_urls:
            cleaned_url = url.rstrip(".,;!?'\")>")
            if cleaned_url not in seen_urls:
                seen_urls.add(cleaned_url)
                entry = self._inspect_url(cleaned_url, None, seen_tld_domains, seen_shorteners)
                results.append(entry)

        return results

    def _inspect_url(
        self,
        dest_url: str,
        display_text: Optional[str],
        seen_tld_domains: set,
        seen_shorteners: set,
    ) -> ExtractedUrl:
        notes: List[str] = []
        is_deceptive = False
        is_ip_based = False
        is_suspicious_tld = False
        is_shortener = False

        try:
            parsed = urlparse(dest_url)
            hostname = (parsed.hostname or "").lower()
        except Exception:
            hostname = ""

        # Check IP address as hostname
        if IP_HOST_REGEX.match(dest_url) or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            is_ip_based = True
            notes.append("Raw IP address used instead of domain name")
            self.add_flag(
                title="IP-Based URL Detected",
                description=f"Destination '{dest_url}' connects directly to an IP address ({hostname}), bypassing domain reputation systems.",
                severity="HIGH",
                points=25,
            )

        # Check Deceptive Anchor (Display text shows domain A, but link goes to domain B)
        if display_text:
            disp_url_match = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', display_text)
            if disp_url_match:
                displayed_domain = disp_url_match.group(1).lower()
                if hostname and displayed_domain not in hostname and hostname not in displayed_domain:
                    is_deceptive = True
                    notes.append(f"Deceptive link: text displays '{displayed_domain}' but destination is '{hostname}'")
                    self.add_flag(
                        title="Deceptive Hyperlink Target",
                        description=(
                            f"The visible link text shows '{displayed_domain}', but the actual link destination leads to '{hostname}'. "
                            "This is a hallmark credential harvesting tactic."
                        ),
                        severity="CRITICAL",
                        points=35,
                    )

        # Check Suspicious TLD (deduplicated per domain)
        if hostname:
            parts = hostname.split(".")
            if len(parts) > 1 and parts[-1] in SUSPICIOUS_TLDS:
                is_suspicious_tld = True
                notes.append(f"High-risk Top Level Domain (.{parts[-1]})")
                if hostname not in seen_tld_domains:
                    seen_tld_domains.add(hostname)
                    self.add_flag(
                        title=f"Suspicious TLD in Link (.{parts[-1]})",
                        description=f"Link '{dest_url}' points to domain '{hostname}' using an abuse-prone top-level domain.",
                        severity="MEDIUM",
                        points=15,
                    )

            # Check URL Shortener (deduplicated per shortener host)
            if hostname in URL_SHORTENERS:
                is_shortener = True
                notes.append("URL Shortener disguises true destination")
                if hostname not in seen_shorteners:
                    seen_shorteners.add(hostname)
                    self.add_flag(
                        title="URL Shortener Detected",
                        description=f"The message contains a link shortener ('{hostname}') which obscures the destination URL.",
                        severity="LOW",
                        points=10,
                    )

        return ExtractedUrl(
            url=dest_url,
            display_text=display_text or dest_url,
            is_deceptive=is_deceptive,
            is_ip_based=is_ip_based,
            is_suspicious_tld=is_suspicious_tld,
            is_shortener=is_shortener,
            domain=hostname,
            notes=notes,
        )

    def _check_urgency_keywords(self, text: str):
        # Phishing & Urgency
        for pattern, label, points in URGENT_CREDENTIAL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                self.add_flag(
                    title=f"Phishing Signal: {label}",
                    description=f"Urgent social engineering pattern detected: '{label}'.",
                    severity="HIGH" if points >= 25 else "MEDIUM",
                    points=points,
                )

        # Promotional Spam
        for pattern, label, points in SPAM_KEYWORDS:
            if re.search(pattern, text, re.IGNORECASE):
                self.add_flag(
                    title=f"Spam Signal: {label}",
                    description=f"Promotional spam indicator identified: '{label}'.",
                    severity="LOW",
                    points=points,
                )

    def _compute_verdict(
        self,
        auth_status: Dict[str, str],
        attachments: List[AttachmentInfo],
        extracted_urls: List[ExtractedUrl]
    ) -> Tuple[str, str, str, str]:
        # Phishing-specific signals
        has_critical_flag = any(f.severity == "CRITICAL" for f in self.red_flags)
        has_executable_attachment = any(a.is_suspicious and "Executable" in (a.risk_reason or "") for a in attachments)
        has_double_ext = any(a.is_suspicious and "double-extension" in (a.risk_reason or "").lower() for a in attachments)
        has_deceptive_url = any(u.is_deceptive for u in extracted_urls)
        has_ip_url = any(u.is_ip_based for u in extracted_urls)
        has_spoofing = any("Domain Mismatch" in f.title or "Display Name Spoofing" in f.title for f in self.red_flags)
        has_phishing_lure = any("Phishing Signal" in f.title for f in self.red_flags)
        auth_failed = auth_status["dmarc"] == "fail" or auth_status["dkim"] == "fail" or auth_status["spf"] == "fail"

        # Determine if email has actual phishing / weaponized indicators
        is_phishing_scenario = (
            has_critical_flag
            or has_executable_attachment
            or has_double_ext
            or has_deceptive_url
            or (has_spoofing and (auth_failed or has_phishing_lure))
            or (has_ip_url and has_phishing_lure)
            or (auth_failed and has_phishing_lure)
            or (has_spoofing and self.score >= 35)
        )

        has_spam_signals = any("Spam Signal" in f.title for f in self.red_flags)

        if is_phishing_scenario:
            verdict = "PHISHING"
            badge_class = "badge-phishing"
            threat_level = "Severe Threat"
            # Ensure threat score reflects critical threat (50 - 100)
            final_score = min(100, max(50, self.score))
            reasons = []
            if has_critical_flag:
                reasons.append("critical security violations")
            if has_deceptive_url:
                reasons.append("deceptive hyperlinks disguising the destination")
            if has_executable_attachment or has_double_ext:
                reasons.append("dangerous executable file attachments")
            if has_spoofing:
                reasons.append("sender header spoofing")
            if auth_failed:
                reasons.append("failed email authentication (SPF/DKIM/DMARC)")
            if has_phishing_lure:
                reasons.append("credential harvesting or urgent coercion patterns")
            if not reasons:
                reasons.append("cumulative high-risk indicators")
            rationale = (
                f"This email exhibits high-confidence characteristics of a malicious phishing attack due to "
                + ", ".join(reasons)
                + ". Do not click links, open attachments, or disclose credentials."
            )
            self.score = final_score
        elif has_spam_signals or self.score >= 25:
            verdict = "SPAM"
            badge_class = "badge-spam"
            threat_level = "Elevated Risk"
            # Scale spam score cleanly into 25-48 range
            final_score = min(48, max(25, 20 + len(self.red_flags) * 7))
            rationale = (
                "This email contains promotional spam signals, commercial mass-mailing patterns, "
                "or marketing domains. While not showing active credential theft or malware, "
                "it is classified as unsolicited bulk email."
            )
            self.score = final_score
        else:
            verdict = "LEGITIMATE"
            badge_class = "badge-legitimate"
            threat_level = "Low Risk"
            self.score = min(24, max(0, self.score))
            rationale = (
                "No critical threat indicators were identified. Sender headers, authentication records, "
                "and link targets appear consistent and legitimate."
            )

        return verdict, badge_class, threat_level, rationale


# ==============================================================================
# Sample Emails for Instant Testing
# ==============================================================================

SAMPLE_EMAILS = {
    "legitimate": """From: "GitHub Notification" <notifications@github.com>
To: developer@example.com
Subject: [GitHub] A personal access token has expired
Date: Tue, 15 Sep 2026 10:00:00 +0000
Message-ID: <123456789.notifications@github.com>
Return-Path: <notifications@github.com>
Authentication-Results: mx.example.com;
    spf=pass smtp.mailfrom=notifications@github.com;
    dkim=pass header.i=@github.com;
    dmarc=pass action=none header.from=github.com
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body>
  <h2>GitHub Notification</h2>
  <p>Hello Developer,</p>
  <p>Your personal access token <strong>Production-Deploy-Key</strong> expired today.</p>
  <p>You can generate a replacement token securely at any time by visiting your GitHub account settings.</p>
  <p><a href="https://github.com/settings/tokens">Review your active tokens on GitHub</a></p>
  <p>Regards,<br>The GitHub Team</p>
</body>
</html>
""",

    "phishing_suspension": """From: "Chase Bank Security Alert" <support@chase-security-update.xyz>
To: victim@example.com
Subject: URGENT: Unauthorized Access Detected - Account Suspended
Date: Tue, 15 Sep 2026 11:20:00 +0000
Message-ID: <alert.9942@chase-security-update.xyz>
Return-Path: <bounce@unrelated-server.top>
Authentication-Results: mx.example.com;
    spf=fail smtp.mailfrom=bounce@unrelated-server.top;
    dkim=fail header.i=@chase-security-update.xyz;
    dmarc=fail action=reject header.from=chase-security-update.xyz
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body>
  <div style="font-family: Arial, sans-serif;">
    <h2 style="color: #991b1b;">Security Alert: Account Temporarily Suspended</h2>
    <p>Dear Customer,</p>
    <p>We detected an <strong>unauthorized access attempt</strong> from an unknown IP address on your Chase Online Banking profile.</p>
    <p><strong>Immediate action required:</strong> Your account will be permanently closed within 24 hours unless you verify your identity.</p>
    <p>Please confirm your credentials immediately to restore full access:</p>
    <p>
      <!-- Deceptive link: text displays chase.com, destination is malicious IP -->
      <a href="http://185.220.101.5/chase-login/verify.php">https://www.chase.com/verify-account</a>
    </p>
    <p>Failure to respond within 24 hours will result in permanent loss of funds.</p>
    <p>Chase Fraud Prevention Operations</p>
  </div>
</body>
</html>
""",

    "malicious_attachment": """From: "Accounts Payable Department" <billing@contractor-portal.com>
To: accounting@company.com
Subject: Past Due Overdue Invoice #INV-88219 - Wire Transfer Required
Date: Tue, 15 Sep 2026 12:45:00 +0000
Message-ID: <msg.77123@contractor-portal.com>
Return-Path: <spammer@evil-relay.club>
Authentication-Results: mx.company.com;
    spf=softfail smtp.mailfrom=spammer@evil-relay.club;
    dmarc=fail header.from=contractor-portal.com
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="===============789123456789=="

--===============789123456789==
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Please find attached the past due outstanding invoice INV-88219.
Immediate wire transfer is required to avoid legal escalation.
Open the attached payment voucher to confirm banking instructions.

--===============789123456789==
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="Invoice_September2026.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAA=
--===============789123456789==--
""",

    "spam_promo": """From: "Super Savings Club" <deals@marketing-promos.buzz>
To: recipient@example.com
Subject: 100% Free Gift! Claim your prize today and win big!
Date: Tue, 15 Sep 2026 14:00:00 +0000
Message-ID: <promo.10091@marketing-promos.buzz>
Return-Path: <deals@marketing-promos.buzz>
Authentication-Results: mx.example.com;
    spf=pass;
    dkim=pass;
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body>
  <h2>Congratulations! You won a $500 Gift Card!</h2>
  <p>Make money fast with our exclusive bonus opportunities. 100% free gift awaits!</p>
  <p><a href="http://marketing-promos.buzz/claim">Click here to claim your reward</a></p>
  <p style="font-size: 11px; color: #666;">
    If you wish to opt out, <a href="http://marketing-promos.buzz/unsubscribe">unsubscribe here</a>.
  </p>
</body>
</html>
"""
}


# ==============================================================================
# FastAPI Routes (2-Page Consolidated Flow: Home & About Us)
# ==============================================================================

@app.get("/", response_class=HTMLResponse)
async def index_view(request: Request):
    """Render the Home page with email upload dropzone and raw text accordion."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "active_page": "home",
            "result": None,
            "error": None,
            "raw_input": "",
            "filename": "",
        }
    )


@app.post("/", response_class=HTMLResponse)
async def index_scan(
    request: Request,
    email_file: Optional[UploadFile] = File(None),
    raw_email: Optional[str] = Form(None)
):
    """
    Handle email scan input on Home page, run EmailHeuristicScanner,
    and render results inline below the scanner on the same page.
    Supports JSON AJAX responses if requested.
    """
    raw_bytes: bytes = b""
    filename = ""

    # Check if a file was uploaded
    if email_file and email_file.filename:
        filename = email_file.filename
        raw_bytes = await email_file.read()

    # Fallback to pasted raw text
    if not raw_bytes and raw_email and raw_email.strip():
        raw_bytes = raw_email.strip().encode("utf-8", errors="replace")

    # If no content provided, return validation error on Home page
    if not raw_bytes:
        error_msg = "Please upload an .eml file or paste raw email MIME content to scan."
        if "application/json" in request.headers.get("accept", "") or request.headers.get("x-requested-with") == "XMLHttpRequest":
            return JSONResponse(status_code=400, content={"error": error_msg})
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "active_page": "home",
                "result": None,
                "error": error_msg,
                "raw_input": "",
                "filename": "",
            }
        )

    # Perform deterministic heuristic analysis
    scanner = EmailHeuristicScanner(raw_bytes)
    result = scanner.scan()

    # If JSON requested, return serialized model
    if "application/json" in request.headers.get("accept", "") or request.headers.get("x-requested-with") == "XMLHttpRequest":
        return JSONResponse(content=result.model_dump())

    # Render results inline on Home page
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "active_page": "home",
            "result": result,
            "error": None,
            "raw_input": raw_email or "",
            "filename": filename,
        }
    )


@app.post("/scan", response_class=HTMLResponse)
async def scan_alias(
    request: Request,
    email_file: Optional[UploadFile] = File(None),
    raw_email: Optional[str] = Form(None)
):
    """Backwards-compatible scan route delegating to index_scan."""
    return await index_scan(request=request, email_file=email_file, raw_email=raw_email)


@app.get("/about", response_class=HTMLResponse)
async def about_view(request: Request):
    """Render the About Us page dedicated exclusively to Who We Are (team/developers)."""
    return templates.TemplateResponse(
        request=request,
        name="about.html",
        context={
            "active_page": "about",
        }
    )


@app.get("/api/sample/{sample_id}")
async def get_sample(sample_id: str):
    """Return pre-configured test emails for instant demonstration."""
    if sample_id not in SAMPLE_EMAILS:
        return JSONResponse(status_code=404, content={"error": f"Sample '{sample_id}' not found."})
    return JSONResponse(content={"id": sample_id, "content": SAMPLE_EMAILS[sample_id]})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
