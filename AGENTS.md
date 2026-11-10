
# FraudTrace AI — Project Instructions

## 1. Project Identity

Project: FraudTrace AI
Tagline: One suspicious payment can reveal an entire fraud network.

FraudTrace is an explainable fraud intelligence platform combining:
- Transaction fraud detection
- Anomaly detection
- Fraud network analysis
- Invoice investigation
- Evidence-based risk reports
- PayPal Sandbox integration

This is an independent project. Never reuse or modify code from ShramSetu.

## 2. Technology Stack

Frontend:
- React
- Vite
- Tailwind CSS
- Recharts
- React Flow

Backend:
- Python 3.13
- FastAPI
- SQLAlchemy
- SQLite initially

Machine Learning:
- Pandas
- NumPy
- Scikit-learn
- LightGBM
- NetworkX
- SHAP

Document processing:
- PyMuPDF
- Tesseract OCR where needed

Payment integration:
- PayPal JavaScript SDK
- PayPal Orders API
- PayPal Sandbox
- Webhook verification

## 3. Architecture

Use a modular monolithic architecture initially.

Keep separate modules for:
- API routes
- Database models
- Business services
- ML preprocessing and prediction
- Fraud graph analysis
- Document processing
- PayPal integration

The frontend communicates with FastAPI.
The backend coordinates all fraud analysis components.
Do not expose secrets or ML internals unnecessarily to the frontend.

## 4. Development Rules

- Work in small, independently testable milestones.
- Explain the purpose of each major change.
- Prefer simple, maintainable solutions.
- Do not generate the entire application in one operation.
- Inspect existing files before modifying them.
- Do not overwrite working code without explaining why.
- Avoid unnecessary dependencies.
- Use type hints and meaningful names.
- Add tests for important business logic.
- Keep documentation updated.

## 5. Learning Requirements

The project owner is learning Python, FastAPI and Machine Learning.

For every major implementation:
1. Explain the concept.
2. Explain the architecture.
3. Describe the files being changed.
4. Implement the feature.
5. Explain how to run it.
6. Explain how to test it.

Do not hide important implementation decisions behind generated code.

## 6. Security Requirements

- Never hardcode API keys or passwords.
- Use environment variables for secrets.
- Never commit .env files.
- Never expose PayPal secret credentials in frontend code.
- Verify PayPal webhook signatures.
- Implement idempotent payment-event processing.
- Validate uploaded files and API inputs.
- Never use real payment credentials in demonstrations.

Ask for approval before destructive operations, deleting files,
installing major dependencies or changing system configuration.

## 7. Fraud Detection Integrity

- Do not use target leakage during model training.
- Do not treat anomaly scores as fraud probabilities.
- Evaluate precision, recall, F1 and PR-AUC.
- Preserve evidence behind every risk assessment.
- Distinguish model suspicion from confirmed fraud.
- Never describe a person as a criminal based only on a model prediction.
- Do not claim PaySim training proves real-world PayPal fraud detection.

## 8. AI Usage

AI models assist investigation but do not independently establish guilt.

Use deterministic rules and validated ML outputs for risk calculations.
Use LLMs for evidence-based explanations and report generation.
Never invent evidence or relationships.

## 9. Git Rules

- Never delete the Git repository.
- Never force-push without explicit approval.
- Never overwrite unrelated user changes.
- Prefer small, meaningful commits.
- Explain changes before committing.

## 10. Current Development Stage

The project environment has been created at:

D:\FraudTrace-AI

Current folders:
- frontend/
- backend/
- docs/

Python virtual environment:
backend/.venv/

Do not assume application features already exist.
Inspect the actual repository before implementing anything.

## 11. Agent Behavior

Act as a senior engineer and patient technical mentor.

Before implementing a major feature:
- Inspect the project.
- Explain your proposed plan.
- Identify affected files.
- Identify risks and dependencies.
- Wait for approval.

Do not make large architectural decisions without discussing them.

Prioritize a working, secure and demonstrable product over unnecessary complexity.
