
# AgentShield Privacy API

## 1. Endpoint

POST /api/privacy/analyze

## 2. Purpose

Detect sensitive information in user-submitted text using:
- Regular Expressions (Regex)
- Microsoft Presidio
- Custom sensitive-data rules

The API returns entity positions, categories, and confidence scores.

## 3. Request

Content-Type: application/json

```json
{
  "request_id": "REQ_001",
  "text": "Employee Rahul, email rahul@example.com"
}
```

## 4. Response

```json
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
```

## 5. Supported Entity Categories

- PERSON
- EMAIL
- PHONE
- CREDIT_CARD
- API_KEY
- TOKEN
- LOCATION
- IBAN_CODE
- US_SSN
- OTHER_CONFIGURED

## 6. Custom Sensitive-Data Rules

Custom rules are configured in:

backend/privacy/custom_rules.json

Example:

```json
{
  "rules": [
    {
      "value": "Project Falcon",
      "type": "OTHER_CONFIGURED",
      "confidence": 0.95
    }
  ]
}
```

Custom rules detect configured phrases without case sensitivity.

## 7. Position Conventions

- start is inclusive.
- end is exclusive.
- Positions refer to the original input string.
- The implementation uses Python string offsets (Unicode code points).
- Frontend must use the original submitted text when applying these positions.
- Verify Unicode offset handling before multilingual integration.

## 8. Frontend Integration and Masking

1. React sends the original text to POST /api/privacy/analyze.
2. Backend detects sensitive entities.
3. Backend returns entity positions, types, and confidence scores.
4. Frontend uses start and end positions to identify sensitive text.
5. Frontend replaces detected values with placeholders such as [PERSON_1] and [EMAIL_1].
6. Original-to-placeholder mapping stays in the frontend.
7. Only sanitized text should be sent to the AI workflow.

Important:
- Apply masking using the original text and returned offsets.
- Do not send original PII to Sarvam AI.
- Do not rely on the backend response to contain original sensitive values.

## 9. Sarvam AI Privacy Rules

- Local Regex and Presidio detection run first.
- Sarvam contextual analysis is used only when appropriate.
- Never send raw original PII to Sarvam.
- Validate Sarvam responses before using them.
- Use local fallback when Sarvam is unavailable.
- Track API usage.
- Sarvam does not make authorization decisions.

## 10. Testing

Run all unit tests:

```bash
python -m pytest tests/ -v
```

## 11. Local Development

Run from the project root:

```bash
python -m uvicorn backend.privacy.dev_app:app --host 127.0.0.1 --port 8001
```

Swagger documentation:

http://127.0.0.1:8001/docs

API endpoint:

http://127.0.0.1:8001/api/privacy/analyze

## 12. Installation and Setup

Create virtual environment:

```bash
python -m venv .venv
```

Activate environment (Windows):

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Install English language model:

```bash
python -m spacy download en_core_web_sm
```

Run unit tests:

```bash
python -m pytest tests/ -v
```
