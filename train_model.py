import pandas as pd
import joblib
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import whois
import datetime
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# Load the dataset
df = pd.read_csv("dataset_phishing.csv")

# Select relevant features
selected_features = [
    "length_url", "length_hostname", "nb_dots", "nb_hyphens", "nb_at",
    "nb_qm", "nb_and", "nb_or", "nb_eq", "nb_underscore", "nb_tilde", "nb_percent",
    "nb_slash", "nb_star", "nb_colon", "nb_comma", "nb_semicolumn", "nb_dollar",
    "nb_space", "nb_www", "nb_com", "nb_dslash", "http_in_path", "https_token",
    "domain_in_title", "domain_with_copyright", "whois_registered_domain",
    "domain_registration_length", "domain_age", "web_traffic", "dns_record",
    "google_index", "page_rank"
]

# Prepare dataset
df_filtered = df[selected_features + ["status"]].copy()
df_filtered["label"] = df_filtered["status"].map({"legitimate": 0, "phishing": 1})
df_filtered.drop(columns=["status"], inplace=True)

# Split dataset into train and test sets
X = df_filtered.drop(columns=["label"])
y = df_filtered["label"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Hyperparameter tuning using Grid Search
param_grid = {
    "n_estimators": [50, 100, 150],
    "max_depth": [10, 20, None],
    "min_samples_split": [2, 5, 10],
    "min_samples_leaf": [1, 2, 4]
}

grid_search = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=5, n_jobs=-1, verbose=2)
grid_search.fit(X_train, y_train)

# Train the final model with the best hyperparameters
best_params = grid_search.best_params_
print(f"\n✅ Best Hyperparameters: {best_params}")

model = RandomForestClassifier(**best_params, random_state=42)
model.fit(X_train, y_train)

# Make predictions
y_pred = model.predict(X_test)

# Compute accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"\n✅ Model Accuracy: {accuracy * 100:.2f}%")

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
print("\nConfusion Matrix:")
print(cm)

# Plot Confusion Matrix
plt.figure(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Legitimate", "Phishing"], yticklabels=["Legitimate", "Phishing"])
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix")
plt.show()

# Classification Report
report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
print("\nClassification Report:")
print(report)

# Feature Importance Analysis
feature_importances = model.feature_importances_
feature_importance_df = pd.DataFrame({"Feature": X_train.columns, "Importance": feature_importances})
feature_importance_df = feature_importance_df.sort_values(by="Importance", ascending=False)

# Display top 10 most important features
print("\n✅ Top 10 Important Features:")
print(feature_importance_df.head(10))

# Plot feature importance
plt.figure(figsize=(10, 5))
sns.barplot(x=feature_importance_df["Importance"][:10], y=feature_importance_df["Feature"][:10], palette="coolwarm")
plt.xlabel("Importance Score")
plt.ylabel("Feature")
plt.title("Top 10 Most Important Features in Phishing Detection")
plt.show()

# Save the trained model
joblib.dump(model, "phishing_model.pkl")
print("\n✅ Model saved as phishing_model.pkl")
