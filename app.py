import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from xgboost import XGBClassifier
import re

# Set page config for wide layout and title
st.set_page_config(page_title="Phishing URL Detection Dashboard", layout='wide')


# Cache loading the dataset for speed
@st.cache_data
def load_data():
    df = pd.read_csv('5.urldata.csv')
    return df


# Cache loading the model for speed
@st.cache_data
def load_model():
    model = XGBClassifier()
    model.load_model("xgb_model.json")
    return model


def extract_features(url):
    """
    Extract features from URL string for phishing detection.
    Match these features with your trained model features exactly.
    """
    features = []

    try:
        # Feature 1: Check if URL contains an IP address
        ip_pattern = re.compile(r'(([0-9]{1,3}\.){3}[0-9]{1,3})')
        have_ip = 1 if ip_pattern.search(url) else 0
        features.append(have_ip)

        # Feature 2: Length of URL
        url_len = len(url)
        features.append(url_len)

        # Feature 3: Number of dots
        count_dots = url.count('.')
        features.append(count_dots)

        # Feature 4: Number of hyphens
        count_hyphens = url.count('-')
        features.append(count_hyphens)

        # Add more features here if your model requires

    except Exception as e:
        st.error(f"Error extracting features: {e}")

    return features


# Load data and model
data = load_data()
model = load_model()

# Sidebar for navigation between pages
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Home", "Exploratory Data Analysis", "Model Performance", "Predict URL"])


def plot_feature_importance(model, features):
    importances = model.feature_importances_
    indices = np.argsort(importances)

    plt.figure(figsize=(10, 6))
    plt.title("Feature Importances (XGBoost)")
    plt.barh(range(len(indices)), importances[indices], color='skyblue', align='center')
    plt.yticks(range(len(indices)), [features[i] for i in indices])
    plt.xlabel("Relative Importance")
    st.pyplot(plt.gcf())


if page == "Home":
    st.title("Phishing URL Detection Dashboard")
    st.write("""
    Explore the phishing URL dataset, analyze model performance,
    and predict whether a URL is phishing or legitimate based on extracted features.
    """)

    st.subheader("Dataset Preview")
    st.dataframe(data.head())

    st.subheader("Dataset Summary")
    st.write(data.describe())

    st.subheader("Dataset Shape")
    st.write(f"Rows: {data.shape[0]}, Columns: {data.shape[1]}")

elif page == "Exploratory Data Analysis":
    st.title("Exploratory Data Analysis")

    st.subheader("Correlation Heatmap")
    fig, ax = plt.subplots(figsize=(15, 13))
    numeric_data = data.select_dtypes(include=[np.number])  # Select only numeric columns
    sns.heatmap(numeric_data.corr(), annot=True, fmt=".2f", cmap='coolwarm', ax=ax)

    st.pyplot(fig)

    st.subheader("Feature Distribution Histograms")
    fig2, ax2 = plt.subplots(figsize=(15, 15))
    data.hist(bins=50, ax=ax2)
    st.pyplot(fig2)

elif page == "Model Performance":
    st.title("Model Performance Comparison")

    # Sample model accuracies (replace with your actual results)
    results = pd.DataFrame({
        'Model': ['Decision Tree', 'Random Forest', 'Multilayer Perceptrons', 'XGBoost', 'AutoEncoder', 'SVM'],
        'Train Accuracy': [0.91, 0.95, 0.94, 0.97, 0.88, 0.92],
        'Test Accuracy': [0.89, 0.93, 0.92, 0.94, 0.85, 0.90]
    })

    st.table(results.style.background_gradient(cmap='Blues'))

    st.subheader("Feature Importance from XGBoost")
    feature_cols = data.columns.drop(['Domain', 'Label'])
    plot_feature_importance(model, feature_cols)

elif page == "Predict URL":
    st.title("Predict if URL is Phishing or Legitimate")

    url_input = st.text_input("Enter a URL to check")

    if st.button("Predict"):
        if url_input.strip() == "":
            st.warning("Please enter a valid URL.")
        else:
            try:
                # Extract features from input URL
                features = extract_features(url_input)
                if not features or len(features) != 4:
                    st.error("Feature extraction failed or incorrect number of features.")
                else:
                    input_df = pd.DataFrame([features],
                                            columns=['Have_IP', 'URL_Length', 'Count_Dots', 'Count_Hyphens'])

                    # Make prediction and get probabilities
                    prediction = model.predict(input_df)[0]
                    proba = model.predict_proba(input_df)[0]

                    label = "🚨 Phishing URL" if prediction == 1 else "✅ Legitimate URL"
                    st.markdown(f"### Prediction: {label}")

                    st.markdown(f"### Confidence Scores:")
                    st.write(f"- Legitimate URL Probability: {proba[0]:.3f}")
                    st.write(f"- Phishing URL Probability: {proba[1]:.3f}")

            except Exception as e:
                st.error(f"Error during prediction: {e}")

# Footer in sidebar
st.sidebar.markdown("---")
st.sidebar.write("Developed by Your Name | Phishing URL Detection")
