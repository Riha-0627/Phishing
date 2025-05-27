from xgboost import XGBClassifier
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split

# Load dataset
iris = load_iris()
X, y = iris.data, iris.target

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Create model
model = XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')

# Train model
model.fit(X_train, y_train)

# Save model
model.save_model("xgb_model.json")

print("Model trained and saved to xgb_model.json")
