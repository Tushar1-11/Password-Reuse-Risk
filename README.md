# Smart Password Reuse Risk Analyzer

A Flask application that combines privacy-preserving local password-reuse detection with an ANN-based risk analyzer.

## Architecture

1. The user enters a platform, password, and account sensitivity.
2. The password is converted to a per-installation HMAC-SHA-256 fingerprint.
3. Only the fingerprint is stored in SQLite; the plaintext password is not stored.
4. The fingerprint is compared with existing fingerprints to detect exact reuse.
5. Risk features are generated for the ANN.
6. The trained ANN predicts LOW, MEDIUM, HIGH, or CRITICAL risk.
7. The dashboard displays reuse groups and risk information.

## Project structure

```text
Smart Password Reuse Risk Analyzer/
├── app.py
├── analyzer.py
├── train_password_reuse_ann.py
├── password_reuse_risk_dataset_10000.csv
├── requirements.txt
├── Procfile
├── model/
│   ├── password_reuse_risk_ann.keras
│   ├── preprocessing.joblib
│   └── metadata.json
├── templates/
├── static/
├── tests/
└── instance/
    ├── password_risk.sqlite3
    └── fingerprint.key
```

## First-time Windows setup

```powershell
cd "D:\Smart Password Reuse Risk Analyzer"
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Train and save the ANN

Make sure the CSV is in the project root, then:

```powershell
python train_password_reuse_ann.py
```

This creates:

```text
model/password_reuse_risk_ann.keras
model/preprocessing.joblib
model/metadata.json
```

The preprocessing artifact is required because the production app must use the same feature order and StandardScaler learned during training.

## Run locally

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

Check ML status:

```text
http://127.0.0.1:5000/api/health
```

It should report `"ml_enabled": true` after the model has been trained.

## Deploy to Render

The included `render.yaml` defines a public Render web service. It uses Waitress and a persistent disk for the SQLite database and fingerprint key. The disk requires Render's Starter (paid) plan; an ephemeral filesystem would lose account data and rotate the fingerprint key on restart.

1. Push this project to a GitHub repository.
2. In Render, choose **New → Blueprint**, connect the repository, and apply the `render.yaml` configuration.
3. After deployment, open the service URL and check `/api/health`.

You can also create a Render Web Service manually with build command `pip install -r requirements.txt` and start command `waitress-serve --host=0.0.0.0 --port=$PORT app:app`. Configure `DATABASE=/var/data/password_risk.sqlite3` and `SECRET_FILE=/var/data/fingerprint.key`, and attach a persistent disk mounted at `/var/data`.

## Public deployment and privacy

This app has no user accounts or authentication. A public deployment is one shared instance: anyone who can reach it can add or delete entries, and `/api/dashboard` exposes the saved platform names and reuse groups to every visitor. Passwords are sent to the server over HTTPS and processed there; only HMAC fingerprints are stored. Do not use real passwords or personal account information on a public instance. Add authentication, per-user data isolation, and appropriate abuse protections before using it with real users.

For private local use, keep the server bound to `127.0.0.1` and protect the `instance/` directory.

## Tests

```powershell
python -m unittest discover -s tests -v
```
