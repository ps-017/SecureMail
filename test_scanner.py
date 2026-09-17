"""
Test suite for SecureMail heuristic engine and FastAPI endpoints.
"""

from pathlib import Path
from starlette.testclient import TestClient

from app import EmailHeuristicScanner, app

client = TestClient(app)
SAMPLES_DIR = Path(__file__).parent / "samples"


def test_legitimate_email_analysis():
    eml_bytes = (SAMPLES_DIR / "legitimate_order.eml").read_bytes()
    scanner = EmailHeuristicScanner(eml_bytes)
    result = scanner.scan()

    assert result.verdict == "LEGITIMATE", f"Expected LEGITIMATE, got {result.verdict}"
    assert result.threat_score < 25, f"Expected threat_score < 25, got {result.threat_score}"
    assert result.verdict_badge_class == "badge-legitimate"
    assert result.auth_status["spf"] == "pass"
    assert result.auth_status["dkim"] == "pass"
    assert result.auth_status["dmarc"] == "pass"
    assert len(result.red_flags) == 0


def test_phishing_account_suspension():
    eml_bytes = (SAMPLES_DIR / "phishing_account_suspension.eml").read_bytes()
    scanner = EmailHeuristicScanner(eml_bytes)
    result = scanner.scan()

    assert result.verdict == "PHISHING", f"Expected PHISHING, got {result.verdict}"
    assert result.threat_score >= 50, f"Expected threat_score >= 50, got {result.threat_score}"
    assert result.verdict_badge_class == "badge-phishing"

    # Check for specific red flags
    flag_titles = [f.title for f in result.red_flags]
    assert any("Domain Mismatch" in t for t in flag_titles), "Sender mismatch should be flagged"
    assert any("SPF" in t for t in flag_titles), "SPF failure should be flagged"
    assert any("DMARC" in t for t in flag_titles), "DMARC failure should be flagged"
    assert any("Deceptive Hyperlink" in t for t in flag_titles), "Deceptive link should be flagged"
    assert any("Phishing Signal" in t for t in flag_titles), "Urgency lure should be flagged"

    # Verify deceptive URL detection
    deceptive_urls = [u for u in result.extracted_urls if u.is_deceptive]
    assert len(deceptive_urls) >= 1, "Expected at least 1 deceptive URL flagged"
    assert "paypal.com" in deceptive_urls[0].display_text.lower()


def test_malicious_executable_attachment():
    eml_bytes = (SAMPLES_DIR / "malicious_executable_attachment.eml").read_bytes()
    scanner = EmailHeuristicScanner(eml_bytes)
    result = scanner.scan()

    assert result.verdict == "PHISHING", f"Expected PHISHING, got {result.verdict}"
    assert result.verdict_badge_class == "badge-phishing"
    assert len(result.attachments) == 1
    assert result.attachments[0].is_suspicious is True
    assert "double-extension" in result.attachments[0].risk_reason.lower() or "executable" in result.attachments[0].risk_reason.lower()

    flag_titles = [f.title for f in result.red_flags]
    assert any("Double Extension" in t or "Dangerous Attachment" in t for t in flag_titles)


def test_promotional_spam():
    eml_bytes = (SAMPLES_DIR / "promotional_spam.eml").read_bytes()
    scanner = EmailHeuristicScanner(eml_bytes)
    result = scanner.scan()

    assert result.verdict == "SPAM", f"Expected SPAM, got {result.verdict}"
    assert 20 <= result.threat_score < 50
    assert result.verdict_badge_class == "badge-spam"


def test_fastapi_index_route():
    response = client.get("/")
    assert response.status_code == 200
    assert "SecureMail" in response.text
    assert "Email Analyzer" in response.text
    # Verify no "Engine Active" indicator is in the HTML
    assert "Engine Active" not in response.text
    # Verify new sections and removal of gauge/terminal graphics
    assert "Score Threshold Categorization Guide" in response.text
    assert "What Is an Email Header Analyzer?" in response.text
    assert "Key Detection Highlights" in response.text
    assert "Every email transmitted across the internet carries a hidden record of technical metadata" in response.text
    assert "An email header analyzer automatically parses and evaluates this dense block of raw code" in response.text
    assert "By inspecting envelope return paths against displayed sender identities" in response.text
    assert "explainer-navy-card" in response.text
    assert "bordered-table" in response.text
    assert "gauge-svg" not in response.text
    assert "mock-terminal" not in response.text
    assert "rfc822-inspector" not in response.text
    # Verify new Navy footer copy
    assert "SecureMail — Phishing and Spam Email Detection System" in response.text
    assert "No email content is stored or logged" in response.text



def test_fastapi_about_route():
    response = client.get("/about")
    assert response.status_code == 200
    assert "About SecureMail" in response.text
    assert "Defensive Email Analysis & Threat Detection Platform" in response.text
    assert "SecureMail is a lightweight, protocol-level email forensic utility" in response.text
    assert "RFC 5322 MIME Decomposition" in response.text
    assert "Cryptographic Auth Verification (SPF, DKIM, DMARC)" in response.text
    assert "Domain & Envelope Alignment Auditing" in response.text
    assert "Heuristic Threat & Social Engineering Detection" in response.text
    assert "In-Memory Threat Evaluation" in response.text
    assert "Why SecureMail Was Built" in response.text
    assert "The Blind Spot" in response.text
    assert "Under the Hood: Detection Pipeline" in response.text
    assert "MIME & Protocol Parsing" in response.text
    assert "Privacy First: In-Memory Analysis" in response.text
    assert "Zero Data Persistence" in response.text
    # Verify developer bio has been replaced
    assert "Praveen Kumar" not in response.text
    assert "Why SecureMail Exists" not in response.text


def test_fastapi_sample_api():
    response = client.get("/api/sample/legitimate")
    assert response.status_code == 200
    data = response.json()
    assert "content" in data
    assert "GitHub Notification" in data["content"]

    response_404 = client.get("/api/sample/non_existent_sample")
    assert response_404.status_code == 404


def test_fastapi_scan_raw_text_json():
    raw_content = (SAMPLES_DIR / "phishing_account_suspension.eml").read_text(encoding="utf-8")
    response = client.post(
        "/",
        data={"raw_email": raw_content},
        headers={"Accept": "application/json"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "PHISHING"
    assert data["threat_score"] >= 50
    assert "red_flags" in data
    assert len(data["red_flags"]) > 0


def test_fastapi_scan_file_upload_html():
    eml_bytes = (SAMPLES_DIR / "legitimate_order.eml").read_bytes()
    response = client.post(
        "/",
        files={"email_file": ("test.eml", eml_bytes, "message/rfc822")}
    )
    assert response.status_code == 200
    assert "LEGITIMATE" in response.text
    assert "Acme Cloud Services" in response.text
    assert "Score Threshold Categorization Guide" in response.text
    assert "Legitimate (Safe)" in response.text
    assert "0 – 24" in response.text
    assert "Extracted Attachments" in response.text


if __name__ == "__main__":
    test_legitimate_email_analysis()
    test_phishing_account_suspension()
    test_malicious_executable_attachment()
    test_promotional_spam()
    test_fastapi_index_route()
    test_fastapi_about_route()
    test_fastapi_sample_api()
    test_fastapi_scan_raw_text_json()
    test_fastapi_scan_file_upload_html()
    print("All SecureMail automated tests passed successfully!")
