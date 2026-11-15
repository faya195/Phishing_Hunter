import os
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.layers import Conv1D, Dense, Dropout, Embedding, GlobalMaxPooling1D
from tensorflow.keras.models import Sequential
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import Tokenizer
from xgboost import XGBClassifier

os.makedirs("models", exist_ok=True)

# 1. Load both processed datasets
df_urls = pd.read_csv("data/processed/clean_urls.csv")
df_features = pd.read_csv("data/processed/features_dataset.csv")

X_tab = df_features.drop(columns=["label"])
y = df_features["label"].values
urls_text = df_urls["url"].astype(str).values

# Split indices identically so both models use the exact same test set
indices = np.arange(len(y))
train_idx, test_idx = train_test_split(
    indices, test_size=0.2, random_state=42, stratify=y
)

# ==========================================
# TRACK 1: Machine Learning (XGBoost + Early Stopping)
# ==========================================
print("--- Training Track 1: XGBoost (with Early Stopping) ---")
X_train_tab, X_test_tab = X_tab.iloc[train_idx], X_tab.iloc[test_idx]
y_train, y_test = y[train_idx], y[test_idx]

xgb_model = XGBClassifier(
    n_estimators=200,
    max_depth=3,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    early_stopping_rounds=15,
    random_state=42,
    eval_metric="logloss",
)

xgb_model.fit(
    X_train_tab,
    y_train,
    eval_set=[(X_test_tab, y_test)],
    verbose=False,
)

xgb_probs = xgb_model.predict_proba(X_test_tab)[:, 1]
xgb_preds = (xgb_probs >= 0.5).astype(int)
print(f"XGBoost Best Iteration: {xgb_model.best_iteration}")
print(f"XGBoost Test Accuracy: {accuracy_score(y_test, xgb_preds) * 100:.2f}%")

joblib.dump(xgb_model, "models/xgb_model.pkl")

# ==========================================
# TRACK 2: Deep Learning (1D-CNN + EarlyStopping & Rollback)
# ==========================================
print("\n--- Training Track 2: 1D-CNN (with EarlyStopping & Weight Rollback) ---")
MAX_LEN = 150
tokenizer = Tokenizer(char_level=True, lower=True)
tokenizer.fit_on_texts(urls_text[train_idx])

sequences = tokenizer.texts_to_sequences(urls_text)
X_seq = pad_sequences(sequences, maxlen=MAX_LEN, padding="post", truncating="post")

X_train_seq, X_test_seq = X_seq[train_idx], X_seq[test_idx]
vocab_size = len(tokenizer.word_index) + 1

cnn_model = Sequential([
    Embedding(input_dim=vocab_size, output_dim=32, input_length=MAX_LEN),
    Conv1D(filters=64, kernel_size=5, activation="relu"),
    GlobalMaxPooling1D(),
    Dense(32, activation="relu"),
    Dropout(0.4),
    Dense(1, activation="sigmoid"),
])

cnn_model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])

# Stop training if val_loss stops improving for 3 epochs and restore best weights
early_stop = EarlyStopping(
    monitor="val_loss",
    patience=3,
    restore_best_weights=True,
    verbose=1,
)

cnn_model.fit(
    X_train_seq,
    y_train,
    epochs=20,
    batch_size=32,
    validation_split=0.15,
    callbacks=[early_stop],
    verbose=1,
)

cnn_probs = cnn_model.predict(X_test_seq, verbose=0).flatten()
cnn_preds = (cnn_probs >= 0.5).astype(int)
print(f"1D-CNN Test Accuracy: {accuracy_score(y_test, cnn_preds) * 100:.2f}%")

cnn_model.save("models/dl_cnn_model.keras")
joblib.dump(tokenizer, "models/char_tokenizer.pkl")

# ==========================================
# HYBRID ENSEMBLE EVALUATION (ML + DL)
# ==========================================
print("\n--- Hybrid Ensemble Evaluation (50% XGBoost + 50% 1D-CNN) ---")
hybrid_probs = 0.5 * xgb_probs + 0.5 * cnn_probs
hybrid_preds = (hybrid_probs >= 0.5).astype(int)

print(f"Hybrid Model Test Accuracy: {accuracy_score(y_test, hybrid_preds) * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, hybrid_preds, target_names=["Benign (0)", "Phishing (1)"]))
print("All models saved cleanly inside models/ folder!")