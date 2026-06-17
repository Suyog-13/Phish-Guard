"""
train_model.py
---------------
Trains a RandomForestClassifier on the lexical features in
feature_extraction.py and saves it to model/phishing_model.pkl.

Usage:
    python train_model.py                       # uses dataset/urls_dataset.csv
    python train_model.py --csv my_dataset.csv   # train on your own url,label CSV
    python train_model.py --n 4000               # regenerate synthetic data first
"""

import argparse
import csv
import json
import subprocess
import sys

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

from feature_extraction import feature_vector, FEATURE_ORDER


def load_csv(path):
    urls, labels = [], []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"])
            labels.append(int(row["label"]))
    return urls, labels


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="dataset/urls_dataset.csv",
                         help="Path to a CSV with columns url,label")
    parser.add_argument("--n", type=int, default=None,
                         help="If set, regenerate the synthetic dataset with this many rows per class first")
    args = parser.parse_args()

    if args.n:
        print(f"Regenerating synthetic dataset with {args.n} rows per class...")
        subprocess.run([sys.executable, "-c",
                         f"from generate_dataset import build_dataset; "
                         f"import csv; rows = build_dataset({args.n}); "
                         f"f = open('dataset/urls_dataset.csv','w',newline=''); "
                         f"w = csv.writer(f); w.writerow(['url','label']); w.writerows(rows)"],
                        check=True)

    print(f"Loading dataset from {args.csv} ...")
    urls, labels = load_csv(args.csv)
    print(f"  {len(urls)} URLs loaded.")

    print("Extracting lexical features...")
    X = [feature_vector(u)[0] for u in urls]
    y = labels

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1_score": round(f1_score(y_test, y_pred), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "n_train": len(X_train),
        "n_test": len(X_test),
        "feature_order": FEATURE_ORDER,
    }

    importances = sorted(
        zip(FEATURE_ORDER, clf.feature_importances_.tolist()),
        key=lambda t: t[1], reverse=True,
    )
    metrics["feature_importances"] = [{"feature": f, "importance": round(v, 4)} for f, v in importances]

    print("\n--- Evaluation on held-out test set ---")
    for k in ("accuracy", "precision", "recall", "f1_score"):
        print(f"  {k:10s}: {metrics[k]}")
    print("  confusion matrix [[TN, FP], [FN, TP]]:", metrics["confusion_matrix"])
    print("\nTop features by importance:")
    for f, v in importances[:6]:
        print(f"  {f:25s} {v:.4f}")

    joblib.dump(clf, "model/phishing_model.pkl")
    with open("model/metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print("\nSaved model to model/phishing_model.pkl")
    print("Saved metrics to model/metrics.json")


if __name__ == "__main__":
    main()
