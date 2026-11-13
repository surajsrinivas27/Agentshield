
# AgentShield Privacy API

## Endpoint

POST /api/privacy/analyze

## Purpose

Detect sensitive information in user-submitted text
using Regex and Microsoft Presidio.

## Request

Content-Type: application/json

{
  "request_id": "REQ_001",
  "text": "Employee Rahul, email rahul@example.com"
}

## Response

{
  "request_id": "REQ_001",
  "status": "success",
  "entities": [
    {
      "start": 9,
      "end": 14,
      "type": "PERSON",
      "confidence": 0.85
    },
    {
      "start": 22,
      "end": 39,
      "type": "EMAIL",
      "confidence": 0.99
    }
  ]
}

## Supported entity categories

- PERSON
- EMAIL
- PHONE
- CREDIT_CARD
- API_KEY
- TOKEN
- LOCATION
- IBAN_CODE
- US_SSN

## Position conventions

- start is inclusive.
- end is exclusive.
- Positions refer to the original input string.
- The current implementation uses Python string
  offsets (Unicode code points).
- Verify Unicode offset handling with Person 1
  before multilingual integration.

## Privacy rules

1. Backend returns entity spans, not original values.
2. Frontend performs masking.
3. Original-to-placeholder mapping stays in frontend.
4. Do not send original PII to Sarvam AI.
5. Sarvam performs contextual classification only.
6. Sarvam never makes authorization decisions.

## Testing

Run:

python -m pytest tests/ -v

## Local development

Run from project root:

python -m uvicorn backend.privacy.dev_app:app --reload

Swagger:

http://127.0.0.1:8000/docs


## Installation and Setup

### 1. Create virtual environment

python -m venv .venv

### 2. Activate environment (Windows)

.venv\Scripts\Activate.ps1

### 3. Install dependencies

pip install -r requirements.txt

### 4. Install English language model

python -m spacy download en_core_web_sm

### 5. Run Privacy API

python -m uvicorn backend.privacy.dev_app:app --reload

### 6. Open API documentation

http://127.0.0.1:8000/docs

### 7. Run unit tests

python -m pytest tests/ -v
