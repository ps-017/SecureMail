# SecureMail: Phishing and Spam Email Detection System

An intuitive, lightweight email security scanner built with **Python 3**, **FastAPI**, **Jinja2**, and standard library `email` MIME parsing (`email.policy.default`). It deterministically inspects `.eml` files or raw email text to classify messages as **Legitimate**, **Spam**, or **Phishing**, highlighting specific risk indicators and forensic metadata.

---

## 🧭 Streamlined 2-Page Architecture

SecureMail merges inspection and results into an intuitive 2-page flow:

1. **Home / Scanner (`/`)**:
   - **Scan Area**: Drag-and-drop zone for `.eml` files, alternative collapsible raw MIME text box, quick-test scenario buttons, and primary Navy **"Scan Email"** button.
   - **Inline Results (Appears below scanner upon scanning)**:
     - Prominent verdict badge (`LEGITIMATE`, `SPAM`, or `PHISHING`).
     - **Visual Threat Score Meter & Threshold Reference Guide**: Shows the calculated score (0 to 100) alongside the categorization reference (`0–24` Legitimate, `25–49` Spam, `50–100` Phishing) with the active tier highlighted.
     - Extracted email headers & authentication status pills (SPF, DKIM, DMARC).
     - Security red flags list with severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
     - Attachments and extracted links inspection tables.
     - "Scan Another Email", "Copy Report Summary", and "Download JSON Report" utilities.

2. **About Us (`/about`)**:
   - Dedicated exclusively to **Who We Are** (team and developer profiles, roles, technical specialties, and GitHub/contact links).

---

## 🎨 Design System & Branding

- **Project Title**: *"SecureMail: Phishing and Spam Email Detection System"*
- **Header**: Clean navbar with full project title, Home and About Us navigation links, and no distracting status badges.
- **Palette**: Deep Navy (`#0f172a` / `#1e293b`), crisp off-white background (`#f8fafc`), and pure white cards (`#ffffff`).
- **Verdict Badges**:
  - **Legitimate**: Soft green pill (`#dcfce7`, text `#166534`, border `#86efac`)
  - **Spam**: Soft amber pill (`#fef3c7`, text `#92400e`, border `#fde047`)
  - **Phishing**: Soft crimson pill (`#fee2e2`, text `#991b1b`, border `#fca5a5`)
- **Footer**: Minimal Navy-themed footer with copyright and notice: *"In-Memory Secure Scan — No emails stored."*

---

## 🚀 Running the Server Locally

### Windows (PowerShell):
```powershell
# 1. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 2. Run the server
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

### macOS / Linux:
```bash
# 1. Activate virtual environment
source venv/bin/activate

# 2. Run the server
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser at:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## 🧪 Running Automated Tests

```powershell
python test_scanner.py
```

All 9 test cases verify:
- Heuristic classification rules (Legitimate `< 25`, Phishing `≥ 50`, Spam `25–49`).
- Header spoofing, auth failures, deceptive URLs, and dangerous attachments.
- Consolidated multi-page routes: `GET /`, `POST /` (with inline results & threshold guide), `GET /about`, and `GET /api/sample/{id}`.
