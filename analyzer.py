from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

SENSITIVITY_WEIGHTS = {"standard": 0, "important": 10, "critical": 20}
SENSITIVITY_VALUES = {"standard": 0, "important": 2, "critical": 3}
VALID_SENSITIVITIES = set(SENSITIVITY_WEIGHTS)


class PasswordReuseAnalyzer:
    def __init__(self, database: str, secret_file: str, model_dir: str | None = None):
        self.database = database
        self.secret_file = Path(secret_file)
        self.secret = self._load_or_create_secret()
        self.model = None
        self.scaler = None
        self.classes = None
        self.features = None
        self.model_available = False
        if model_dir:
            self._load_model(Path(model_dir))

    def _load_or_create_secret(self) -> bytes:
        self.secret_file.parent.mkdir(parents=True, exist_ok=True)
        if self.secret_file.exists():
            return self.secret_file.read_bytes()
        secret = os.urandom(32)
        fd = os.open(str(self.secret_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as key_file:
            key_file.write(secret)
        return secret

    def _load_model(self, model_dir: Path) -> None:
        model_path = model_dir / "password_reuse_risk_ann.keras"
        preprocessing_path = model_dir / "preprocessing.joblib"
        if not model_path.exists() or not preprocessing_path.exists():
            return

        try:
            from tensorflow.keras.models import load_model
            import joblib

            self.model = load_model(model_path, compile=False)
            preprocessing = joblib.load(preprocessing_path)
            self.scaler = preprocessing["scaler"]
            self.classes = np.array(preprocessing["classes"])
            self.features = preprocessing["features"]
            self.model_available = True
        except Exception:
            self.model = None
            self.scaler = None
            self.classes = None
            self.features = None
            self.model_available = False

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._connection() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS account_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    platform TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    password_fingerprint TEXT NOT NULL,
                    sensitivity TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    def _fingerprint(self, password: str) -> str:
        return hmac.new(self.secret, password.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _password_strength(password: str) -> float:
        length = len(password)
        score = min(40, length * 3.0)
        if any(c.islower() for c in password):
            score += 10
        if any(c.isupper() for c in password):
            score += 10
        if any(c.isdigit() for c in password):
            score += 10
        if any(not c.isalnum() for c in password):
            score += 20
        if len(set(password)) >= max(4, length * 0.65):
            score += 10
        return float(max(5, min(100, score)))

    @staticmethod
    def _validate(platform: str, password: object, sensitivity: str) -> tuple[str, str, str]:
        platform = platform.strip()
        if not 2 <= len(platform) <= 80:
            raise ValueError("Platform name must be between 2 and 80 characters.")
        if not isinstance(password, str) or not password:
            raise ValueError("Enter a password to analyze.")
        if sensitivity not in VALID_SENSITIVITIES:
            raise ValueError("Choose a valid account sensitivity.")
        return platform, password, sensitivity

    def _ml_risk(self, password: str, count: int, sensitivities: list[str], created_dates: list[str]) -> tuple[int, str, dict]:
        if not self.model_available:
            score, level = self._risk(count, sensitivities)
            return score, level, {"source": "rule_based", "probabilities": {}}

        now = datetime.now(timezone.utc)
        ages = []
        for created in created_dates:
            try:
                dt = datetime.fromisoformat(created)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                ages.append(max(0, (now - dt).days))
            except ValueError:
                ages.append(0)

        accounts = max(1, count)
        reuse_count = max(0, count - 1)
        reuse_frequency = reuse_count / max(accounts - 1, 1)
        password_age_days = max(ages, default=0)
        account_sensitivity = max(SENSITIVITY_VALUES[s] for s in sensitivities)

        features = {
            "accounts": accounts,
            "reuse_count": reuse_count,
            "password_age_days": password_age_days,
            "account_sensitivity": account_sensitivity,
            "breach_count": 0,
            "variation_count": 1,
            "reuse_frequency": reuse_frequency,
            "strength_score": self._password_strength(password),
        }

        values = np.array([[features[name] for name in self.features]], dtype=float)
        scaled = self.scaler.transform(values)
        probabilities = self.model.predict(scaled, verbose=0)[0]
        index = int(np.argmax(probabilities))
        level = str(self.classes[index])
        score = int(round(float(np.max(probabilities)) * 100))
        return score, level.title(), {
            "source": "ann",
            "probabilities": {str(label).title(): round(float(prob), 4) for label, prob in zip(self.classes, probabilities)},
            "features": features,
        }

    def add_entry(self, platform: str, password: object, sensitivity: str) -> dict:
        platform, password, sensitivity = self._validate(platform, password, sensitivity)
        fingerprint = self._fingerprint(password)
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as db:
            try:
                cursor = db.execute(
                    "INSERT INTO account_entries (platform, password_fingerprint, sensitivity, created_at) VALUES (?, ?, ?, ?)",
                    (platform, fingerprint, sensitivity, now),
                )
            except sqlite3.IntegrityError:
                raise ValueError("That platform already has a record. Delete it before adding a replacement.")
            group = db.execute(
                "SELECT id, platform, sensitivity, created_at FROM account_entries WHERE password_fingerprint = ? ORDER BY platform COLLATE NOCASE",
                (fingerprint,),
            ).fetchall()

        reused_on = [row["platform"] for row in group if row["id"] != cursor.lastrowid]
        score, level, model_info = self._ml_risk(
            password,
            len(group),
            [row["sensitivity"] for row in group],
            [row["created_at"] for row in group],
        )
        return {
            "id": cursor.lastrowid,
            "reused": bool(reused_on),
            "reused_on": reused_on,
            "risk_score": score,
            "risk_level": level,
            "model": model_info,
            "message": "Password reuse detected. Change this password and the matching accounts." if reused_on else "No matching password fingerprint was found.",
        }

    @staticmethod
    def _risk(count: int, sensitivities: list[str]) -> tuple[int, str]:
        if count <= 1:
            return 0, "Low"
        score = min(100, 25 + (count - 2) * 15 + max(SENSITIVITY_WEIGHTS[s] for s in sensitivities))
        if score >= 70:
            return score, "Critical"
        if score >= 45:
            return score, "High"
        return score, "Medium"

    def dashboard(self) -> dict:
        with self._connection() as db:
            rows = db.execute("SELECT id, platform, password_fingerprint, sensitivity, created_at FROM account_entries ORDER BY platform COLLATE NOCASE").fetchall()
        groups: dict[str, list[sqlite3.Row]] = defaultdict(list)
        for row in rows:
            groups[row["password_fingerprint"]].append(row)
        risk_by_fingerprint = {}
        for fingerprint, items in groups.items():
            score, level, _ = self._ml_risk(
                "", len(items), [item["sensitivity"] for item in items], [item["created_at"] for item in items]
            )
            risk_by_fingerprint[fingerprint] = (score, level)

        entries = []
        for row in rows:
            score, level = risk_by_fingerprint[row["password_fingerprint"]]
            entries.append({
                "id": row["id"], "platform": row["platform"], "sensitivity": row["sensitivity"],
                "risk_score": score, "risk_level": level,
                "reused_with": [other["platform"] for other in groups[row["password_fingerprint"]] if other["id"] != row["id"]],
            })
        reuse_groups = []
        for items in groups.values():
            if len(items) > 1:
                score, level = risk_by_fingerprint[items[0]["password_fingerprint"]]
                reuse_groups.append({"platforms": [item["platform"] for item in items], "score": score, "level": level})
        reuse_groups.sort(key=lambda group: group["score"], reverse=True)
        highest = max((group["score"] for group in reuse_groups), default=0)
        return {
            "entries": entries,
            "reuse_groups": reuse_groups,
            "summary": {
                "accounts": len(rows),
                "reused_accounts": sum(len(group["platforms"]) for group in reuse_groups),
                "highest_risk": highest,
                "ml_enabled": self.model_available,
            },
        }

    def delete_entry(self, entry_id: int) -> bool:
        with self._connection() as db:
            return db.execute("DELETE FROM account_entries WHERE id = ?", (entry_id,)).rowcount == 1
