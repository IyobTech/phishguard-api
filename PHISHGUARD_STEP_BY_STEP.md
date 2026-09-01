# PhishGuard — Complete Step-by-Step Build, Training, Render Deployment, and Chrome Integration

## 1. What you are building

The final system is:

`Chrome Extension / Web UI → HTTPS FastAPI endpoint on Render → Joblib model → URL-only feature extraction → prediction`

The model analyzes the URL text only. It does not visit the target website.

### Final classes

- `Likely legitimate`
- `Potential phishing`

## 2. Why the uploaded dataset is handled differently

Your uploaded `url1.csv` contains verified PhishTank records and all rows are phishing. A binary classifier cannot learn the legitimate class from that file alone.

Therefore the training notebook uses the **UCI PhiUSIIL Phishing URL Dataset (ID 967)** as the binary training source because it contains both legitimate and phishing URLs. Your uploaded PhishTank data is retained as an additional, non-training phishing generalization check.

This is methodologically stronger than manufacturing legitimate labels from assumptions.

## 3. Download the package

Use:

- `train_phishing_detector.ipynb` — complete Colab training notebook
- `url_features.py` — shared feature implementation
- `app.py` — Render FastAPI server
- `requirements.txt` — pinned server dependencies
- `.python-version` — Python version for Render
- `render.yaml` — optional Render infrastructure configuration
- `chrome_extension/` — Manifest V3 extension

## 4. Google Colab — exact order

### Step 1 — Open Colab

Open a new Google Colab notebook and upload `train_phishing_detector.ipynb`.

### Step 2 — Run cells from top to bottom

Do not skip the cells. The notebook intentionally performs the process in this order:

1. Install pinned dependencies.
2. Import libraries and set the random seed.
3. Write the shared `url_features.py` module.
4. Upload `url1.csv`.
5. Inspect the uploaded data.
6. Download/load UCI PhiUSIIL.
7. Clean and deduplicate URLs.
8. Build a domain-aware train/validation/test split.
9. Build the hybrid URL feature representation.
10. Scale the sparse features.
11. Tune SVM `C` on a controlled tuning sample.
12. Select the decision threshold from validation data.
13. Retrain on train + validation.
14. Evaluate on the untouched test set.
15. Run an external PhishTank phishing-recall check.
16. Run sanity-check URLs.
17. Save the complete Joblib artifact.
18. Reload the artifact and perform a deployment self-test.
19. Download the model, metadata, and feature module.
20. Optionally create a deployment ZIP.

### Step 3 — Watch the dataset checks

The notebook should explicitly show:

- UCI class counts after mapping.
- Train/validation/test sizes.
- Domain-group overlap checks.
- Model tuning results.
- Validation threshold.
- Accuracy, precision, recall, F1, ROC-AUC, PR-AUC.
- Confusion matrix.
- Uploaded PhishTank external phishing recall.

Do not judge the detector from accuracy alone.

## 5. What the model actually learns

### Character-level representation

A character `3–5` gram hashing representation captures URL spelling and structural patterns without storing a very large vocabulary. This helps recognize mutations, unusual separators, suspicious path text, encoded material, and other lexical patterns.

### Engineered URL features

The shared extractor adds 49 numeric features covering:

- total URL length
- hostname/path/query/fragment length
- counts of `.`, `-`, `_`, `/`, `?`, `=`, `&`, `@`, `%`, `#`, `:`, `\\`, `;`, `+`, `,`
- total digits and letters
- special-character ratio
- digit ratio
- host digit ratio
- path/query digit counts
- HTTP vs HTTPS
- IP-address hostname
- punycode hostname
- explicit port
- subdomain depth
- TLD length
- suspicious TLD indicator
- path segment count
- query parameter count
- security/account keyword count
- brand-like keyword count
- percent-encoding count
- repeated separator indicator
- Shannon entropy of URL and hostname
- suspicious nested `//` pattern

These features complement the learned character patterns rather than replacing them.

## 6. The downloaded model file

The important file is:

`phishing_url_detector.joblib`

It contains all components needed for inference:

- feature preprocessor
- scaler
- trained classifier
- locked decision threshold
- model version

Do not deploy only the classifier coefficients. The preprocessing must match training exactly.

## 7. Before deployment — required local folder

Make a folder named `phishguard-api` containing:

```text
phishguard-api/
├── app.py
├── url_features.py
├── phishing_url_detector.joblib
├── model_metadata.json
├── requirements.txt
├── .python-version
└── render.yaml
```

The first four files are essential. The last three make deployment reproducible.

## 8. Render deployment

### Step 1 — Create a GitHub repository

Create a repository containing the `phishguard-api` files above.

Do not put any API keys or secrets into the repository.

### Step 2 — Connect the repository to Render

Create a new **Web Service** and select the repository.

Use:

- **Language:** Python 3
- **Build command:** `pip install -r requirements.txt`
- **Start command:** `uvicorn app:app --host 0.0.0.0 --port $PORT`
- **Python:** `3.12.7`
- **Environment variable:** `ALLOWED_ORIGINS=*` for the first test

Render's current FastAPI guide uses the same basic build/start pattern and requires the service to listen on `0.0.0.0` and the supplied port.

### Step 3 — Deploy

Wait for a successful deployment and copy the HTTPS Render URL.

### Step 4 — Test health

Open:

`https://YOUR-SERVICE.onrender.com/health`

Expected structure:

```json
{
  "status": "healthy",
  "model_loaded": true
}
```

### Step 5 — Test interactive API documentation

Open:

`https://YOUR-SERVICE.onrender.com/docs`

Use `POST /predict` with:

```json
{
  "url": "https://example.com/login"
}
```

The response includes the prediction, risk score, decision score, threshold, signals, and model version.

## 9. Why the API does not visit URLs

This is intentional. The API only receives a string such as:

`https://example.com/account/login`

It extracts lexical features locally. It does not make an outbound request to that URL.

This makes the service safer and avoids creating a server-side URL-fetching/SSRF component.

## 10. Connect the Chrome extension

The package contains a Manifest V3 extension.

### Step 1 — Edit `manifest.json`

Replace:

`https://YOUR-RENDER-SERVICE.onrender.com/*`

with your exact Render API origin.

### Step 2 — Edit `popup.js`

Replace:

`https://YOUR-RENDER-SERVICE.onrender.com`

with exactly the same HTTPS origin.

### Step 3 — Load the extension

1. Open Chrome.
2. Open `chrome://extensions`.
3. Turn on **Developer mode**.
4. Choose **Load unpacked**.
5. Select the `chrome_extension` folder.
6. Open a normal web page.
7. Click the PhishGuard extension icon.

The popup reads the current tab URL, sends only that URL to Render, and displays the returned result.

## 11. Extension permission design

The extension uses `activeTab` instead of requesting blanket read access to every website. The remote Render API origin is declared as a host permission because Chrome requires host permission for extension-origin cross-site `fetch()` requests.

## 12. Important behavior limitations

This is a URL-based ML detector, not a complete browser security engine.

A legitimate website can have a suspicious-looking URL. A phishing website can also use HTTPS and a normal-looking URL. HTTPS is therefore one feature, not proof of legitimacy.

The model does not know whether a site is currently online, who owns the domain, whether a certificate is valid, or what the page actually renders unless those signals are separately added in a future architecture.

Do not describe a prediction as a guaranteed security verdict. Use wording such as **Likely legitimate** and **Potential phishing**.

## 13. Recommended future upgrade path

A future version can add carefully controlled live intelligence such as:

- DNS/domain-age reputation signals
- certificate metadata
- redirect-chain metadata
- domain registration features
- webpage HTML/DOM features fetched by a controlled sandbox
- threat-intelligence reputation feeds
- user feedback and monitored retraining

Those should be added as separate, auditable features rather than silently changing the URL-only model.

## 14. Monitoring and retraining

After deployment, record aggregate model statistics without collecting sensitive browsing data unnecessarily. Useful monitoring signals include:

- prediction volume
- high-risk prediction rate
- user-confirmed false positives/false negatives
- feature distribution drift
- external phishing recall over new datasets
- model version and training date

Retrain only from a versioned, reviewed dataset. Never overwrite a production model without recording the evaluation results.

## 15. Most common failures and exact fixes

### `ModuleNotFoundError: url_features`

Make sure `url_features.py` is in the same folder as `app.py` and the `.joblib` file.

### `FileNotFoundError: phishing_url_detector.joblib`

Copy the downloaded Joblib file into the Render project root.

### `ValueError` while loading Joblib

Use the same scikit-learn/joblib versions specified by `requirements.txt`. Do not train with one version and deploy with an unrelated newer version.

### Render says the port is not bound

Keep the start command exactly:

`uvicorn app:app --host 0.0.0.0 --port $PORT`

### Extension says `Failed to fetch`

Check both places:

- `manifest.json` → `host_permissions`
- `popup.js` → `API_BASE_URL`

Both must use the exact HTTPS Render origin.

### Extension returns CORS errors

Confirm Render is using the included `app.py`, and that `ALLOWED_ORIGINS` is set correctly. Start with `*` for a development test; restrict it to your production web origin later.

### Model gives strange predictions

Confirm that the deployed `url_features.py` is the exact same file used when the Joblib artifact was created.

## 16. Final architecture checklist

```text
Google Colab
    │
    ├── UCI PhiUSIIL training data
    ├── Uploaded PhishTank external check
    ├── URL feature extraction
    ├── Character hashing
    ├── Linear SVM
    ├── Threshold selection
    └── phishing_url_detector.joblib
              │
              ▼
         GitHub repository
              │
              ▼
            Render
              │
              ├── FastAPI
              ├── /health
              └── /predict
                    ▲
                    │ HTTPS JSON
                    │
           Chrome Manifest V3 extension
```

## 17. Sources

UCI PhiUSIIL dataset:
https://archive.ics.uci.edu/dataset/967/phiusil-phishing-url-dataset

Render FastAPI deployment:
https://render.com/docs/deploy-fastapi

Render Python version configuration:
https://render.com/docs/python-version

Chrome extension cross-origin requests:
https://developer.chrome.com/docs/extensions/develop/concepts/network-requests

Chrome manifest reference:
https://developer.chrome.com/docs/extensions/reference/manifest
