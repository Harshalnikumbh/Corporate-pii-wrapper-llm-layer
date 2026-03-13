# 🛡️ Intelligent Context-Aware PII Redaction System

> An enterprise-grade, multi-modal PII detection and redaction pipeline powered by LLMs, NLP, and Computer Vision — compliant with **GDPR**, **DPDP Act (India)**, **HIPAA**, and **ISO 27701**.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Component Reference](#component-reference)
- [Supported PII Types](#supported-pii-types)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Intent Preservation Engine](#intent-preservation-engine)
- [Redaction Policy Engine](#redaction-policy-engine)
- [Multi-Language Support](#multi-language-support)
- [File Type Support](#file-type-support)
- [Output & Audit Trail](#output--audit-trail)
- [Compliance](#compliance)

---

## Overview

This system provides **intelligent, context-aware PII redaction** across text, PDFs, Excel spreadsheets, and images. Unlike rule-based systems, it uses a combination of:

- **LLM classification** (Groq / LLaMA 3.3 70B) to understand *context* (e.g., differentiating "my colleague Arjun" from "Arjun Kapoor the actor")
- **Presidio NLP engine** with custom recognizers for Indian, medical, and multilingual PII
- **Computer Vision** (OpenCV + EasyOCR + YOLOv8) for image-based redaction
- **Intent Preservation** so that redaction respects *why* you're processing the file

---

## Key Features

| Feature | Description |
|---|---|
| 🧠 **Context-Aware Classification** | LLM understands if a name is an employee, colleague, client, or public figure |
| 🎯 **Intent Preservation** | Describe *why* you're sharing the file — the system redacts accordingly |
| 🌍 **Multi-Language Support** | 11 languages: EN, HI, MR, ES, FR, DE, ZH, JA, KO, PT, AR |
| 🖼️ **Image Redaction** | Faces, ID documents (field-level), screens, logos, whiteboards |
| 📄 **PDF Support** | Text-based AND scanned/OCR PDFs |
| 📊 **Excel/CSV** | Column-semantic-aware redaction with safe column exclusions |
| 🏥 **Medical PII** | HIPAA-aligned: MRN, ABHA, ICD codes, prescriptions, lab reports |
| 🔄 **De-anonymization** | Reversible redaction with placeholder mapping |
| 📋 **Audit Trail** | JSON report per run with entity counts, categories, and compliance notes |
| 🔁 **Retry Resilience** | Decorator-based retry on all LLM/OCR operations |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    IntelligentPIIPipeline                           │
│                                                                     │
│   ┌─────────────┐   ┌──────────────────┐   ┌───────────────────┐  │
│   │  GroqClient │   │  ContextAwarePII │   │  IntentPreservation│  │
│   │  (LLM API)  │──▶│     Guard        │◀──│     Engine        │  │
│   └─────────────┘   └────────┬─────────┘   └───────────────────┘  │
│                              │                                      │
│          ┌───────────────────┼────────────────────┐               │
│          ▼                   ▼                     ▼               │
│   ┌─────────────┐   ┌──────────────┐   ┌──────────────────┐      │
│   │ PDFHandler  │   │Spreadsheet   │   │ ProductionImage  │      │
│   │             │   │Handler       │   │ Redactor         │      │
│   └──────┬──────┘   └──────┬───────┘   └────────┬─────────┘      │
│          │                 │                     │                 │
│    Text / OCR         Excel / CSV           Image Pipeline         │
└──────────┼─────────────────┼─────────────────────┼────────────────┘
           │                 │                     │
           ▼                 ▼                     ▼
    ┌─────────────┐   ┌───────────────┐   ┌───────────────────────┐
    │  fitz (PDF) │   │   openpyxl    │   │  ┌─────────────────┐  │
    │  EasyOCR    │   │   pandas      │   │  │ FaceDetector    │  │
    └─────────────┘   └───────────────┘   │  │ (Haar Cascade)  │  │
                                          │  ├─────────────────┤  │
                                          │  │ IDDocDetector   │  │
                                          │  │ (OCR + YOLOv8)  │  │
                                          │  ├─────────────────┤  │
                                          │  │ ScreenDetector  │  │
                                          │  ├─────────────────┤  │
                                          │  │ WhiteboardDoc   │  │
                                          │  │ Detector        │  │
                                          │  └─────────────────┘  │
                                          └───────────────────────┘
```

### NLP Detection Stack

```
Input Text
    │
    ▼
┌───────────────────────────────────────────────────────┐
│             ContextAwarePIIGuard                      │
│                                                       │
│  1. Language Detection (langdetect)                   │
│       │                                               │
│       ▼                                               │
│  2. Presidio AnalyzerEngine                          │
│     ├── spaCy NLP (en_core_web_trf)                  │
│     ├── Indian Recognizers (Aadhaar, PAN, Phone)     │
│     ├── Corporate Recognizers (EmpID, Salary, IFSC)  │
│     ├── Medical Recognizers (MRN, ICD, ABHA, Rx)     │
│     └── Multilingual Recognizers (ES/FR/DE/ZH/JA...) │
│       │                                               │
│       ▼                                               │
│  3. ContextAwareClassifier (LLM)                     │
│     └── Classifies each entity by role:              │
│         EMPLOYEE_PII / COLLEAGUE_PII /               │
│         CLIENT_SENSITIVE / PUBLIC_FIGURE / KEEP      │
│       │                                               │
│       ▼                                               │
│  4. PublicEntityVerifier                             │
│     ├── Wikipedia API check                          │
│     └── LLM fallback verification                    │
│       │                                               │
│       ▼                                               │
│  5. DirectiveAwareFilter (Intent Engine)             │
│     └── Keep / Force-Redact per user intent          │
│       │                                               │
│       ▼                                               │
│  6. Anonymizer → Placeholder replacement             │
│     └── <MY_NAME>, <COLLEAGUE_1>, <EMAIL_1>...       │
└───────────────────────────────────────────────────────┘
```

### Intent Preservation Flow

```
User Intent (natural language)
    │   "Share with external auditors, they need salary data only"
    ▼
┌──────────────────────────────────────┐
│       IntentPreservationEngine       │
│   LLaMA 3.3 70B Analysis             │
│                                      │
│   Output:                            │
│   keep_categories: [SALARY_INFO]     │
│   force_redact: [PERSON, EMAIL, ...]  │
│   safe_columns: [department, grade]  │
│   sensitive_columns: [aadhaar, pan]  │
└──────────────────────────────────────┘
    │
    ▼
RedactionDirective
    │
    ├──▶ PDFHandler (process_pdf)
    ├──▶ SpreadsheetHandler (process_excel)
    └──▶ ProductionImageRedactor (redact_image)
```

---

## Component Reference

### `IntelligentPIIPipeline`
Top-level orchestrator. Entry point for all file types.

| Method | Description |
|---|---|
| `process_text(text)` | Redact PII in plain text, call LLM, return de-anonymized response |
| `process_file(path, intent)` | Auto-detect file type and route to correct handler |
| `process_image(path)` | Full image redaction pipeline |

---

### `ContextAwarePIIGuard`
Core NLP engine wrapping Microsoft Presidio with custom recognizers.

| Method | Description |
|---|---|
| `anonymize(text)` | Detect + redact PII, return text with placeholders |
| `deanonymize(text)` | Replace placeholders with original values |
| `classify_pii_intent(text)` | LLM call to determine if PII is needed for computation |
| `get_redaction_report()` | Returns per-category redaction summary |

---

### `IntentPreservationEngine`
Translates natural-language user intent into a structured `RedactionDirective`.

```python
directive = engine.analyze(
    user_intent="Share with auditors, keep salary data",
    file_type="xlsx",
    detected_columns=["Name", "Salary", "Aadhaar"]
)
# directive.keep_categories → ["SALARY_INFO"]
# directive.force_redact_categories → ["PERSON", "EMAIL_ADDRESS", ...]
```

---

### `ProductionImageRedactor`
Multi-phase image redaction pipeline.

| Phase | Target | Method |
|---|---|---|
| 1 | Identity document fields | BLACKOUT (field-level) |
| 2 | Computer screens/dashboards | BLACKOUT |
| 3 | Faces | Heavy Gaussian blur |
| 4 | OCR-detected text PII | BLACKOUT |
| 5 | Client logos | Medium blur |
| 6 | Whiteboards / printed docs | BLACKOUT / blur |

---

### `IDDocumentDetector`
Detects Indian identity documents (Aadhaar, PAN, Passport, DL) and redacts individual PII fields:

- Name (English + Regional/Devanagari)
- Date of Birth
- Aadhaar number
- Address
- Gender
- QR code (contour-based detection)
- Signature (YOLOv8 → advanced CV fallback)

---

### `PDFHandler`
Handles both native-text and scanned PDFs.

```
PDF Input
    │
    ├── Has selectable text? ──YES──▶ Presidio text pipeline
    │                                 → page.search_for() redaction
    │
    └── NO (scanned) ────────────────▶ EasyOCR (200 DPI render)
                                       → PII detection on OCR output
                                       → add_redact_annot() per region
```

---

### `SpreadsheetHandler`
Excel redaction with column semantics.

| Column Type | Action |
|---|---|
| `SAFE_NUMERIC` (salary, income, revenue) | **Skipped** — not redacted |
| `PII_PERSONAL` (name, employee name) | Redacted via full anonymize pipeline |
| `PII_CONTACT` (mobile, email) | Pattern-matched redaction |
| `PII_IDENTITY` (PAN, Aadhaar, EmpID) | Pattern-matched redaction |
| `PII_LOCATION` (address, pincode) | Redacted |

---

## Supported PII Types

### Indian / Corporate
| Entity | Example |
|---|---|
| `AADHAAR_NUMBER` | `1234 5678 9012` |
| `PAN_NUMBER` | `ABCDE1234F` |
| `INDIAN_PHONE` | `+91 9876543210` |
| `EMPLOYEE_ID` | `EMP-12345` |
| `BANK_ACCOUNT` | 9–18 digit account number |
| `IFSC_CODE` | `HDFC0001234` |
| `SALARY_INFO` | `₹12,00,000 CTC` |
| `PASSPORT` | `A1234567` |
| `PROJECT_CODE` | `PROJ-ALPHA001` |
| `HOME_ADDRESS` | Full address with pincode |
| `PIN_CODE` | `400001` |

### Medical (HIPAA / DPDP)
| Entity | Example |
|---|---|
| `MEDICAL_RECORD_NUMBER` | `MRN-98765`, `UHID 1234567890` |
| `HEALTH_INSURANCE_ID` | Policy no., PMJAY ID |
| `PRESCRIPTION_NUMBER` | `Rx-A12345` |
| `DOCTOR_REGISTRATION_NUMBER` | `MCI-12345`, `NPI-1234567890` |
| `DIAGNOSIS_CODE` | `E11.9` (ICD-10) |
| `LAB_REPORT_NUMBER` | `LAB-20240101` |
| `DISABILITY_CERTIFICATE` | `UDID-MH12345678` |
| `BLOOD_TYPE` | `Blood Group: O+` |

### Multilingual
| Language | Entities |
|---|---|
| Spanish | `ES_DNI`, `ES_NIE`, `ES_PHONE` |
| French | `FR_NIR` (Sécu), `FR_PHONE` |
| German | `DE_TAX_ID`, `DE_PHONE` |
| Chinese | `CN_ID`, `CN_PHONE`, `CN_PERSON` |
| Japanese | `JP_PHONE`, `JP_PERSON` |
| Korean | `KR_PERSON` |
| Portuguese / Brazilian | `BR_CPF`, `PT_PHONE` |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/pii-redaction-system.git
cd pii-redaction-system

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download spaCy model
python -m spacy download en_core_web_trf

# Download YOLOv8 model (for signature detection)
# Place yolov8s.pt in the project root directory
wget https://github.com/ultralytics/assets/releases/download/v0.0.0/yolov8s.pt
```

### `requirements.txt`
```
groq
presidio-analyzer
presidio-anonymizer
spacy
easyocr
opencv-python
pillow
pymupdf
openpyxl
pandas
numpy
python-dotenv
langdetect
requests
ultralytics
```

---

## Configuration

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_groq_api_key_here
```

The `Config` dataclass provides defaults:

```python
@dataclass
class Config:
    groq_api_key: str
    groq_model: str = "llama-3.3-70b-versatile"
    spacy_model: str = "en_core_web_trf"
    language: str = "en"
    face_detection_model: str = "haarcascade_frontalface_default.xml"
```

---

## Usage

### CLI

```bash
python pii_redaction.py
```

**Menu options:**
```
1. Process text input
2. Process file (PDF/Excel/CSV/Image)
3. Batch process directory
4. Exit
```

### Programmatic API

```python
from pii_redaction import IntelligentPIIPipeline, Config
import os

config = Config(groq_api_key=os.getenv("GROQ_API_KEY"))
pipeline = IntelligentPIIPipeline(config)

# ── Text ──────────────────────────────────────────────────────────
result = pipeline.process_text(
    "Hi, I am Priya Sharma. My Aadhaar is 1234 5678 9012. "
    "Contact me at priya@example.com or +91 9876543210."
)
print(result["final_response"])

# ── PDF ───────────────────────────────────────────────────────────
result = pipeline.process_file(
    "employee_contract.pdf",
    user_intent="Share with legal team, remove all personal contacts"
)

# ── Excel ─────────────────────────────────────────────────────────
result = pipeline.process_file(
    "payroll.xlsx",
    user_intent="Send to auditors, they only need salary figures"
)

# ── Image ─────────────────────────────────────────────────────────
result = pipeline.process_image("aadhaar_scan.jpg")
```

---

## Intent Preservation Engine

Describe your purpose in plain English — the system adapts redaction accordingly.

| Intent Example | Effect |
|---|---|
| `"Share with external auditors, need salary data only"` | Keeps `SALARY_INFO`, redacts names/contacts |
| `"Internal HR review, keep employee IDs"` | Keeps `EMPLOYEE_ID`, redacts phones/emails |
| `"Publish as anonymised dataset"` | Redacts everything personal |
| `"Send to compliance, mask only Aadhaar and PAN"` | Force-redacts `AADHAAR_NUMBER`, `PAN_NUMBER` only |
| `"Share resume for job application"` | Skips face/logo redaction if flagged |

The LLM returns a structured `RedactionDirective`:

```python
RedactionDirective(
    keep_categories=["SALARY_INFO"],
    force_redact_categories=["PERSON", "EMAIL_ADDRESS", "AADHAAR_NUMBER"],
    safe_columns=["department", "grade"],
    sensitive_columns=["aadhaar", "pan"],
    skip_face_redaction=False,
    skip_logo_redaction=False,
    reason="Sharing with auditor - personal identifiers not needed",
    confidence=0.92
)
```

---

## Redaction Policy Engine

The `RedactionPolicy` class encodes enterprise rules aligned with GDPR, DPDP Act, and ISO 27701.

```
RedactionSeverity:
  CRITICAL  → Full BLACKOUT       (IDs, credentials, medical)
  HIGH      → Heavy blur / BLACK  (faces, screens, OCR PII)
  MEDIUM    → Medium blur         (client logos, whiteboards)
  LOW       → Light blur          (name plates)
  NONE      → No redaction        (furniture, walls, plants)

RedactionMethod:
  BLACKOUT      → cv2.rectangle fill (0,0,0)
  BLUR_HEAVY    → GaussianBlur 99x99
  BLUR_MEDIUM   → GaussianBlur 51x51
  BLUR_LIGHT    → GaussianBlur 25x25
  PIXELATE      → Downscale + upscale
```

---

## Multi-Language Support

The system auto-detects language (via `langdetect`) and:
1. Switches the spaCy NLP model accordingly
2. Activates language-specific pattern recognizers
3. Falls back to English for unsupported languages

| Language | spaCy Model | Custom Recognizers |
|---|---|---|
| English | `en_core_web_trf` | All Indian + Corporate + Medical |
| Spanish | `es_core_news_lg` | DNI, NIE, ES phone |
| French | `fr_core_news_lg` | NIR (Sécu), FR phone |
| German | `de_core_news_lg` | Steuer-ID, DE phone |
| Chinese | `zh_core_web_lg` | National ID, CN phone, CN names |
| Japanese | `ja_core_news_lg` | JP phone, Kanji/Kana names |
| Portuguese | `pt_core_news_lg` | CPF, BR/PT phone |
| Korean | `en_core_web_trf`* | Hangul names |
| Hindi/Marathi | `en_core_web_trf`* | Devanagari in image OCR |

\* Fallback to English NLP engine

---

## File Type Support

| Format | Detection Method | Notes |
|---|---|---|
| `.txt` / plain text | Presidio + LLM | Full context-aware pipeline |
| `.pdf` (text-based) | fitz + Presidio | `page.search_for()` redaction |
| `.pdf` (scanned) | EasyOCR + fitz | 200 DPI render → OCR → redact annotations |
| `.xlsx` / `.xls` | openpyxl + Presidio | Column-semantic-aware |
| `.csv` | pandas + Presidio | Row-by-row processing |
| `.jpg` / `.jpeg` / `.png` | OpenCV + EasyOCR + YOLO | Full image pipeline |

---

## Output & Audit Trail

Every run produces:

1. **Redacted file** — saved as `<original>_REDACTED.<ext>` 
2. **JSON report** — saved to `output/result_<timestamp>.json`

```json
{
  "type": "pdf",
  "input_file": "contract.pdf",
  "output_file": "contract_REDACTED.pdf",
  "stats": {
    "total_pages": 5,
    "text_based_pages": 4,
    "ocr_pages": 1,
    "total_redactions": 23,
    "redactions_per_page": {
      "page_1": 8,
      "page_2": 5
    }
  },
  "intent_classification": {
    "intent": "REDACTION_REQUIRED",
    "reason": "Casual mention of PII"
  },
  "pii_found": {
    "<PERSON_1>": "Priya Sharma",
    "<EMAIL_ADDRESS_1>": "priya@example.com"
  },
  "entities_kept": ["Rahul Gandhi", "Google"],
  "timestamp": "2024-11-15T14:32:01.123456"
}
```

---

## Compliance

| Regulation | Coverage |
|---|---|
| **GDPR Art. 9** | Biometric (faces), special category data (medical), data minimization |
| **DPDP Act India** | Aadhaar, PAN, phone numbers, addresses |
| **HIPAA** | MRN, health insurance IDs, prescriptions, diagnosis codes, lab reports |
| **ISO 27701** | Audit trail, policy-driven redaction, purpose limitation via Intent Engine |
| **NDA / Confidentiality** | Client logo blurring, whiteboard/document redaction |

---

## Project Structure

```
pii-redaction-system/
├── pii_redaction.py          # Main script (all components)
├── yolov8s.pt                # YOLOv8 model for signature detection
├── public_entities_cache.json # Cached public figure verifications
├── pii_redaction.log          # Runtime log
├── .env                       # API keys (not committed)
├── requirements.txt
├── output/                    # JSON audit reports
│   └── result_<timestamp>.json
└── README.md
```

---

## License

This project is intended for internal enterprise use. Ensure compliance with your organization's data governance policies before processing real PII.