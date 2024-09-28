import warnings
import pickle

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
warnings.filterwarnings("ignore")

# Example data (assuming you have a DataFrame with the extracted features)
df = pd.DataFrame(pd.read_excel('Features_Training_Combined.xlsx'))

y_train = df['Algorithm']
df.drop(columns=['Original Text', 'Length', 'Encrypted Data (Binary)', 'Encrypted Data (Hex)', 'Algorithm', 'iv', 'length', 'block_size'], inplace=True)
X_train = df

df = pd.DataFrame(pd.read_excel('Features_Testing_Combined.xlsx'))

y_test = df['Algorithm']
df.drop(columns=['Original Text', 'Length', 'Encrypted Data (Binary)', 'Encrypted Data (Hex)', 'Algorithm', 'iv', 'length', 'block_size'], inplace=True)
X_test=df
import numpy as np

from sklearn.preprocessing import LabelEncoder

label_encoder = LabelEncoder()
X_train['mode'] = label_encoder.fit_transform(X_train[['mode']])

label_encoder = LabelEncoder()
X_test['mode'] = label_encoder.fit_transform(X_test[['mode']])

# Initialize Random Forest Classifier
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)

# Train the model
rf_model.fit(X_train, y_train)

pickle.dump(rf_model, open("model.pkl", "wb"))