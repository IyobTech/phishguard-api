# PhishGuard — Render API

This folder is the deployment template for the phishing URL detector trained in Google Colab.

## Required files

Place the following files in this folder before deploying:

- `phishing_url_detector.joblib` — downloaded from Colab
- `url_features.py`
- `app.py`
- `requirements.txt`
- `.python-version`
- `render.yaml`

The API analyzes only the submitted URL string. It does **not** fetch the target website, so the endpoint is not designed to browse or inspect pages.

## Local test

```bash
python -m pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000/docs`.

## API request

`POST /predict`

```json
{"url":"https://example.com/login"}
```

The response contains `prediction`, `is_phishing`, `risk_score`, `decision_score`, and lexical warning `signals`.
