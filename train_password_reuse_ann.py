import json
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, Input
from tensorflow.keras.callbacks import EarlyStopping

BASE_DIR = Path(__file__).resolve().parent
DATASET = BASE_DIR / "password_reuse_risk_dataset_10000.csv"
MODEL_DIR = BASE_DIR / "model"
MODEL_DIR.mkdir(exist_ok=True)

FEATURES = [
    "accounts",
    "reuse_count",
    "password_age_days",
    "account_sensitivity",
    "reuse_frequency",
    "strength_score"
]

TARGET = "risk_level"


def main():
    df = pd.read_csv(DATASET)

    X = df[FEATURES].values
    y_text = df[TARGET].values

    encoder = LabelEncoder()
    y = encoder.fit_transform(y_text)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    model = Sequential([
        Input(shape=(len(FEATURES),)),
        Dense(32, activation="relu"),
        Dropout(0.20),
        Dense(16, activation="relu"),
        Dropout(0.10),
        Dense(8, activation="relu"),
        Dense(len(encoder.classes_), activation="softmax"),
    ])

    model.compile(
        optimizer="adam",
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )

    early_stop = EarlyStopping(
        monitor="val_loss",
        patience=10,
        restore_best_weights=True,
    )

    model.fit(
        X_train,
        y_train,
        validation_split=0.20,
        epochs=100,
        batch_size=32,
        callbacks=[early_stop],
        verbose=1,
    )

    loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
    predictions = np.argmax(model.predict(X_test, verbose=0), axis=1)

    print(f"\nTest Accuracy: {accuracy:.4f}")
    print("\nClasses:", list(encoder.classes_))
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=encoder.classes_))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    model.save(MODEL_DIR / "password_reuse_risk_ann.keras")

    joblib.dump(
        {
            "features": FEATURES,
            "classes": list(encoder.classes_),
            "scaler": scaler,
            "label_encoder": encoder,
        },
        MODEL_DIR / "preprocessing.joblib",
    )

    metadata = {
        "features": FEATURES,
        "classes": list(encoder.classes_),
        "test_accuracy": float(accuracy),
        "dataset": DATASET.name,
        "random_state": 42,
    }
    (MODEL_DIR / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("\nSaved:")
    print(MODEL_DIR / "password_reuse_risk_ann.keras")
    print(MODEL_DIR / "preprocessing.joblib")
    print(MODEL_DIR / "metadata.json")


if __name__ == "__main__":
    main()
