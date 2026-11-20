# Serverless PII Redaction Pipeline

An event-driven AWS pipeline that automatically finds and redacts personally identifiable information (PII) in uploaded files.

Upload a file to S3, and a Python Lambda function detects SSNs, emails, phone numbers, credit card numbers, and IP addresses, then saves a redacted copy, logs what it found, and sends an alert. The goal is a small, production-style example of secure serverless design on AWS.

> **Status: In progress (target: December 2026).** The detection engine and its tests are complete. AWS deployment is under construction. See the [roadmap](#roadmap).

## Architecture

```
Upload ──► S3 raw bucket (KMS-encrypted, private)
              │  ObjectCreated event
              ▼
         Lambda (Python) ── detect PII ── redact / mask
              │                    │                     │
              ▼                    ▼                     ▼
    S3 redacted bucket    DynamoDB findings log     SNS alert
                          (counts by type, never    (when PII is found)
                           the sensitive values)
         CloudWatch Logs + alarm on Lambda errors
   Infrastructure: AWS SAM (CloudFormation) · CI/CD: GitHub Actions
```

## What works today

The detection engine (`src/pii_redactor/`) is plain Python with no AWS dependencies, so it can be tested locally and reused inside Lambda.

| PII type | Example | How it's detected |
|---|---|---|
| SSN | `123-45-6789` | Pattern, excluding numbers the SSA never issues (000, 666, 9xx) |
| Email | `jane@example.com` | Pattern |
| US phone | `(215) 555-0123`, `+1 215 555 0123` | Pattern, several formats |
| Credit card | `4111 1111 1111 1111` | Pattern **plus Luhn checksum**, so order numbers aren't flagged |
| IP address | `192.168.10.25` | Pattern with valid octet ranges |

Two output modes:

- **redact**: `SSN: [SSN]`
- **mask**: `SSN: ***-6789` (keeps a non-sensitive hint for review)

## Run it locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

# Run the tests
python -m pytest

# Try it on the fake sample file
PYTHONPATH=src python -m pii_redactor samples/sample_input.txt
PYTHONPATH=src python -m pii_redactor samples/sample_input.txt --mask
```

## Security decisions

- **Encryption at rest:** both S3 buckets use SSE-KMS with a customer-managed key.
- **No public access:** S3 Block Public Access is on for every bucket.
- **Least privilege:** the Lambda role can read only the raw bucket, write only the redacted bucket, and write only to its own DynamoDB table and SNS topic.
- **No sensitive values in logs:** findings are stored as counts by type, never the original values.
- **Fake data only:** every sample in this repo is made up.

## Roadmap

- [x] PII detection engine (SSN, email, phone, credit card with Luhn check, IP address)
- [x] Redact and mask modes
- [x] Unit tests (pytest)
- [ ] Lambda handler triggered by S3 uploads
- [ ] AWS SAM template: KMS-encrypted S3 buckets, DynamoDB, SNS, least-privilege IAM
- [ ] Unit tests for the Lambda handler with mocked AWS services
- [ ] GitHub Actions: run tests on every push, deploy on merge to `main`
- [ ] CloudWatch alarm on Lambda errors
- [ ] Optional: compare regex detection with Amazon Comprehend PII detection (catches names and addresses, which regex can't)

## Tech

Python · AWS Lambda · S3 · KMS · DynamoDB · SNS · CloudWatch · AWS SAM (CloudFormation) · GitHub Actions · pytest
