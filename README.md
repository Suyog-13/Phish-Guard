# PhishGuard — Phishing URL Detection System

A full-stack cybersecurity project that scores any URL for phishing risk in
real time, using lexical/structural feature extraction and a trained
machine learning model — wrapped in a clean, terminal-styled web UI.

**No page is ever fetched or loaded.** Every signal is computed from the
URL string itself (scheme, host, path, query), so it's safe to scan
real, live-looking links without visiting them.

## Live demo flow

1. Paste a URL into the scanner.
2. Watch the scan log "type out" each of the 14 heuristic checks being run.
3. Get a 0–100 risk score, a Safe / Suspicious / Likely Phishing verdict,
   and a full breakdown of which checks fired.

## How it works

```
URL  --->  feature_extraction.py  --->  20+ numeric features
                                              |
                                              v
                                  RandomForestClassifier (scikit-learn)
                                              |
                                              v
                          phishing probability (0–100 risk score)
```

**Features extracted** (see `feature_extraction.py`): URL/hostname/path
length, dot/hyphen/digit/special-character counts, digit ratio, subdomain
count, raw-IP-as-host detection, HTTPS usage, the "https-in-path" disguise
trick, link-shortener detection, count of sensitive keywords
(login, verify, secure, account...), non-standard ports, abused free TLDs,
and redirect-style tokens.

**Model**: a `RandomForestClassifier` (200 trees) trained with an 80/20
train/test split. On the held-out test set it currently scores:

| Metric | Score |
|---|---|
| Accuracy | ~96% |
| Precision | ~97% |
| Recall | ~95% |
| F1 Score | ~96% |

(Exact numbers are written to `model/metrics.json` every time you retrain,
and the homepage pulls them live — so the numbers you see in the browser
are always the real, current numbers, not hardcoded.)

## About the training data

This project runs fully offline, so instead of downloading a live feed it
ships with `generate_dataset.py`, which **programmatically builds a 5,000-URL
labeled dataset** using lexical patterns that are well documented in
phishing research (raw IPs, hyphenated brand-impersonation subdomains, the
`@` trick, link shorteners, abused free TLDs, noisy query strings) mixed
with realistic "hard" examples and ~3% label noise so the two classes
aren't trivially separable.

This is a **deliberate, transparent design choice for a portfolio project**
— be ready to explain it in an interview. If you want to train on real-world
data instead, swap in a CSV with `url,label` columns (1 = phishing) from a
source like:

- [PhishTank](https://phishtank.org/developer_info.php)
- [UCI Phishing Websites Dataset](https://archive.ics.uci.edu/dataset/327)

```bash
python train_model.py --csv path/to/your_dataset.csv
```

## Project structure

```
phishing-url-detector/
├── app.py                  # Flask app: serves the UI + /api/scan endpoint
├── feature_extraction.py   # URL -> feature vector + human-readable checks
├── generate_dataset.py     # builds the offline synthetic training dataset
├── train_model.py          # trains & evaluates the RandomForest, saves it
├── requirements.txt
├── LICENSE
├── dataset/
│   └── urls_dataset.csv    # generated training data
├── model/
│   ├── phishing_model.pkl  # trained model (generated)
│   └── metrics.json        # accuracy/precision/recall/F1 (generated)
├── templates/
│   └── index.html
└── static/
    ├── css/style.css
    └── js/script.js
```

## Running it locally

Requires Python 3.10+.

```bash
# 1. Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Re)build the dataset and train the model — already included,
#    but run this if you want to regenerate it or change parameters
python generate_dataset.py
python train_model.py

# 4. Start the app
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## API

`POST /api/scan`

```json
// request
{ "url": "http://secure-paypal-verify.xyz/account/login" }

// response
{
  "url": "http://secure-paypal-verify.xyz/account/login",
  "risk_score": 77,
  "verdict": "phishing",
  "model_probability_phishing": 0.7721,
  "checks": [ { "id": "https", "label": "Uses HTTPS", "value": "no", "flag": true, "severity": "low" }, ... ],
  "processing_time_ms": 25.9
}
```

`GET /api/metrics` — returns the model's evaluation metrics as JSON.
`GET /healthz` — basic health check.

## Putting this on your resume

Some bullet points you can adapt:

- *Built a full-stack phishing URL detection system (Python, Flask,
  scikit-learn) combining a Random Forest classifier with 20+ engineered
  lexical/structural URL features, achieving ~96% accuracy on a held-out
  test set.*
- *Designed and implemented a feature-extraction pipeline that flags
  known phishing techniques (IP-as-host, brand-impersonation subdomains,
  link shorteners, suspicious TLDs) without fetching or rendering the
  target page.*
- *Built a REST API and a responsive web UI exposing real-time URL risk
  scoring, with a transparent, per-check explanation of every verdict.*

## Ideas to extend it further

- Swap in a real-world labeled dataset (PhishTank/UCI) for production-grade
  accuracy and discuss the train/test distribution shift in your writeup.
- Add a browser extension front-end that calls the same `/api/scan` endpoint.
- Add WHOIS/domain-age and SSL-certificate-age features (requires network
  access at inference time — a good "what I'd do with more time" talking point).
- Containerize with Docker and deploy the Flask app behind Gunicorn + Nginx.
- Add a feedback loop: let users flag false positives/negatives and use
  them to retrain.

## Disclaimer

This is an educational/portfolio project. The risk scores are heuristic
and model-based estimates, not a guarantee — don't use this as your only
line of defense against real phishing attacks.

## License

MIT — see [LICENSE](LICENSE).
