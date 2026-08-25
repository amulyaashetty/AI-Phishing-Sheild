# AI Phishing Shield

AI Phishing Shield is a local Flask web application for analyzing email content for phishing indicators. It combines deterministic security checks with optional local AI reasoning, presents an explainable risk assessment, and stores analysis results in SQLite for later review.

The project is designed for cybersecurity education, controlled demonstrations, and local experimentation. It is not a replacement for an enterprise email security gateway or a professional incident-response process.

## Contents

- [Why This Project Exists](#why-this-project-exists)
- [What the Project Does](#what-the-project-does)
- [Key Features](#key-features)
- [How the Application Works](#how-the-application-works)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [Using the Application](#using-the-application)
- [API Endpoints](#api-endpoints)
- [Database Storage](#database-storage)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Security and Privacy](#security-and-privacy)
- [Educational Value](#educational-value)
- [Limitations and Future Work](#limitations-and-future-work)

## Why This Project Exists

Phishing messages use social engineering, suspicious links, impersonation, urgency, and malicious files to influence users. A single indicator is not always enough to identify an attack, so this project demonstrates how multiple signals can be combined into one explainable assessment.

The application is also intended as a learning tool. It shows how a web interface, a Python backend, text parsers, detection modules, an AI service, and a database can work together in one full-stack security application.

## What the Project Does

The application accepts raw email content through a browser. It then:

1. Parses useful email fields such as sender, subject, links, and attachments.
2. Runs keyword, URL, regular-expression, sender, and attachment checks.
3. Optionally asks a local Ollama/Mistral model for contextual reasoning.
4. Combines detector scores into a final risk score from 0 to 100.
5. Assigns a risk level: Low, Moderate, High, or Critical.
6. Displays indicators, recommendations, detector scores, and an explanation.
7. Saves the result and relevant email information to SQLite.

## Key Features

### Email analysis

- Paste raw email text into the analyzer.
- Upload `.txt` or `.eml` files.
- Extract sender, subject, URLs, email addresses, and attachment information.

### Multi-detector analysis

- Keyword analysis for urgency, fear, and credential-request language.
- URL analysis for shortened URLs, IP-based links, and suspicious domains.
- Regular-expression matching for known phishing patterns.
- Sender reputation checks for suspicious domains and impersonation patterns.
- Attachment checks for dangerous extensions and macro-enabled files.
- Optional AI reasoning through the locally hosted Mistral model.

### Explainable results

- Final numerical risk score.
- Risk-level classification.
- Individual detector scores and descriptions.
- Detected indicators.
- Recommendations for safe next steps.
- AI explanation when Ollama is available.

### History and dashboard

- Store analyses in a local SQLite database.
- Review previous results with date, sender, subject, score, and risk level.
- Search and filter history.
- Export history as CSV.
- View aggregate counts and recent analyses on the dashboard.

### Education

The application includes pages explaining phishing types, common warning signs, protection practices, and actions to take after a possible compromise.

## How the Application Works

```text
Browser
   |
   | HTML forms and JavaScript requests
   v
Flask application (app.py)
   |
   +--> EmailParser
   +--> KeywordDetector
   +--> URLDetector
   +--> RegexDetector
   +--> SenderDetector
   +--> AttachmentDetector
   +--> AIAnalyzer --> Ollama/Mistral, when available
   +--> RiskCalculator
   |
   +--> DatabaseManager --> SQLite
   |
   v
JSON response and rendered results
```

The main analysis route is `POST /api/analyze`. The Flask route accepts JSON, form data, or an uploaded file, invokes `PhishingDetectionEngine`, saves the result, and returns a JSON response for the analyzer page.

## Technology Stack

### Backend

- Python 3.9 or newer
- Flask 3.1.0
- SQLite
- Requests for communication with Ollama
- python-dotenv for local environment configuration

### Frontend

- HTML5 templates with Jinja2
- CSS3 in `static/css/style.css`
- JavaScript for form handling, API calls, filtering, and dynamic results
- Font Awesome for interface icons

### Optional AI service

- Ollama running locally at `http://localhost:11434`
- Mistral model

The application remains usable with rule-based detection if Ollama is unavailable.

## Project Structure

```text
AI-Phishing-Shield/
|
|-- app.py                         Flask routes and application entry point
|-- requirements.txt               Python dependencies
|-- README.md                      Project documentation
|
|-- database/
|   |-- __init__.py
|   `-- db_manager.py              SQLite schema and database operations
|
|-- models/
|   |-- __init__.py
|   `-- detection_engine.py        Detector pipeline and result aggregation
|
|-- utils/
|   |-- helpers.py                 Shared rendering or utility helpers
|   |-- analyzers/
|   |   |-- ai_analyzer.py         Ollama integration and AI fallback
|   |   `-- risk_calculator.py     Risk score and risk-level calculation
|   |-- detectors/
|   |   |-- keyword_detector.py    Suspicious language detection
|   |   |-- regex_detector.py      Pattern matching
|   |   `-- url_detector.py        URL inspection
|   `-- parsers/
|       |-- email_parser.py        Sender, subject, links, and body parsing
|       `-- amulya.txt             Parser-related reference data
|
|-- templates/
|   |-- base.html                  Shared Jinja layout
|   |-- index.html                 Home page
|   |-- analyzer.html              Email analysis interface
|   |-- dashboard.html             Statistics and recent analyses
|   |-- history.html               Stored analysis history
|   |-- about.html                 Project overview
|   |-- education.html             Phishing education guide
|   |-- 404.html                   Missing-page error page
|   `-- 500.html                   Server-error page
|
|-- static/
|   |-- css/style.css              Application styling
|   |-- script.js                  Shared browser utilities
|   |-- analyzer.js                Analyzer implementation reference
|   |-- dashboard.js               Dashboard implementation reference
|   `-- history.js                 History implementation reference
|
|-- uploads/                       Uploaded email files
`-- database/phishing.db           Created automatically at runtime
```

The active analyzer, dashboard, and history behavior is currently implemented in inline script blocks inside their corresponding templates. `static/script.js` is loaded globally from `base.html`; the page-specific JavaScript files remain useful reference implementations unless they are explicitly linked into the templates.

## Installation

### Prerequisites

- Python 3.9 or newer
- `pip`
- A modern web browser
- Git, if cloning the project
- Ollama, only if local AI reasoning is required

### macOS and Linux

From the project directory:

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Windows

```powershell
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

The database directory and SQLite database are created automatically when the application starts. The `uploads/` directory is also created automatically by `app.py`.

## Running the Application

Activate the virtual environment first, then run:

```bash
python3 app.py
```

On Windows, use:

```powershell
python app.py
```

Open the application at:

```text
http://127.0.0.1:5000
```

The current development configuration binds Flask to `127.0.0.1` on port `5000` with debug mode enabled.

### Run with local AI support

Install Ollama from [ollama.com](https://ollama.com), then run:

```bash
ollama pull mistral
ollama serve
```

Keep Ollama running in one terminal and start Flask in another. If Ollama is not running, the application uses its fallback analysis and continues to provide rule-based results.

### Stop the application

Press `Ctrl+C` in the terminal running Flask.

If port 5000 remains occupied on macOS or Linux, identify the process:

```bash
lsof -i :5000
```

Then stop the relevant process using its PID:

```bash
kill <PID>
```

Use `kill -9 <PID>` only when a normal termination does not work and you have confirmed the process belongs to this application.

## Using the Application

### Analyze an email

1. Open the Email Detector page.
2. Paste raw email content into the text area or upload a `.txt`/`.eml` file.
3. Include `From`, `To`, `Subject`, and the message body when possible.
4. Select Analyze Email.
5. Review the risk score, detector results, indicators, AI explanation, and recommendations.

### Review history

1. Open the History page.
2. Review the date, sender, subject, score, and risk level.
3. Search by sender or subject.
4. Filter records by risk level.
5. Export the filtered records as CSV when needed.

### Read educational material

Use the Education page to study phishing types, warning signs, protection steps, and response actions.

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/analyze` | Analyze pasted or uploaded email content and save the result |
| `GET` | `/api/analyses` | Return saved analyses for the history page |
| `GET` | `/api/analyses?limit=5` | Return a limited set of recent analyses |
| `GET` | `/api/stats` | Return aggregate analysis statistics |
| `GET` | `/api/analysis/<id>` | Return one complete analysis by ID |
| `POST` | `/api/analysis/<id>/delete` | Delete one saved analysis |

Example JSON request:

```json
{
  "email_content": "From: sender@example.com\nSubject: Verify your account\n\nPlease review your account."
}
```

## Database Storage

The application uses SQLite at:

```text
database/phishing.db
```

The main table is `phishing_analysis`:

```sql
CREATE TABLE phishing_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_type TEXT NOT NULL,
    input_content TEXT NOT NULL,
    risk_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    detected_indicators TEXT NOT NULL,
    ai_explanation TEXT NOT NULL,
    recommendations TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sender TEXT,
    subject TEXT
);
```

Lists such as detected indicators and recommendations are stored as JSON text and converted back into Python lists when a record is read.

The sender and subject are extracted by the email parser and stored directly in the database. This allows the history page to show accurate email information without trying to reconstruct headers from the message body.

To reset local history during development, stop the application and remove the database:

```bash
rm database/phishing.db
```

The database will be recreated the next time Flask starts. Do not delete the database if its records are needed.

## Configuration

The core application does not require an API key. Ollama is local and is accessed at:

```text
http://localhost:11434/api/chat
```

The application currently uses the `mistral` model. Configuration values can be moved to a `.env` file as the project evolves. Never commit credentials, private email content, or other sensitive values to version control.

## Troubleshooting

### `ModuleNotFoundError`

Confirm that the virtual environment is active and install dependencies again:

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Port 5000 is already in use

Check which process owns the port:

```bash
lsof -i :5000
```

Stop only the application process, or change the port in the `app.run()` configuration.

### AI analysis is unavailable

Verify that Ollama is running and that the Mistral model is installed:

```bash
ollama serve
ollama list
```

Rule-based detection continues to work when the AI service is unavailable.

### History shows old or incomplete sender information

Records created before sender and subject storage was added may not contain those fields. New analyses store the fields directly. Existing records cannot be reconstructed reliably if the original headers were not saved.

### Browser shows an old page

Refresh the page. During development, a hard refresh can clear cached frontend assets:

- macOS: `Cmd+Shift+R`
- Windows/Linux: `Ctrl+Shift+R`

## Security and Privacy

- This is an educational and local analysis tool, not a production security control.
- Do not upload confidential, regulated, or real incident data unless the environment has been approved for it.
- Treat all email content as untrusted input.
- Do not click links or open attachments from messages merely because the tool assigns a low score.
- Keep `.env` files and private database contents out of source control.
- Use a production WSGI server and hardened configuration before deploying beyond localhost.
- Detection results can contain false positives and false negatives.

## Educational Value

This project demonstrates:

- Flask routing and JSON API design.
- Jinja template inheritance and reusable layouts.
- HTML forms and browser-side JavaScript.
- Email parsing and regular-expression matching.
- Modular detector design.
- Combining weighted signals into a risk score.
- Local AI service integration with a fallback path.
- SQLite schema design and JSON serialization.
- Input validation, error handling, and safe rendering of untrusted content.

## Limitations and Future Work

Current limitations include:

- The application is intended for local development and education.
- AI quality depends on the installed Ollama model and local resources.
- Some detector rules are heuristic and require ongoing tuning.
- SMS and standalone URL detection pages are not implemented.
- The history detail action is currently a placeholder in the active template.
- Page-specific JavaScript is duplicated between inline template scripts and reference files in `static/`.

Possible future improvements include:

- Consolidating page JavaScript into the external files in `static/`.
- Adding automated tests for routes, detectors, and database operations.
- Implementing full history detail views and safer HTML rendering throughout.
- Adding authentication and role-based access for multi-user deployments.
- Adding structured logging, pagination at the API layer, and production deployment configuration.
- Supporting SMS, URL, and website analysis as separate workflows.

## License and Contributions

This repository is maintained as an educational project. Contributions that improve detection accuracy, documentation, accessibility, testing, or secure coding practices are welcome.
