# import numpy as np
# from flask import Flask, request, render_template
# import pickle

# flask_app = Flask(__name__)
# model = pickle.load(open("model.pkl", "rb"))

# @flask_app.route("/")
# def Home():
#     return render_template("index.html")

# @flask_app.route("/predict", methods=["POST"])
# def predict():
   
#     hex_feature = request.form['hexa'] 
#     features = [hex_feature] 


#     prediction = model.predict([features])  

#     return render_template("index.html", prediction_text="The algorithm is {}".format(prediction[0]))

# if __name__ == "__main__":
#     flask_app.run(debug=True)

from flask import Flask, request, jsonify,render_template
import numpy as np
import pandas as pd
import pickle  # Assuming you're using joblib to load your model
from collections import Counter
import math
import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import LabelEncoder

flask_app = Flask(__name__)

# Load your machine learning model (replace 'your_model.pkl' with the correct path)
model = pickle.load(open("model.pkl", "rb"))

def hex_to_bytes(hex_str):
    """Convert hexadecimal string to bytes."""
    return bytes.fromhex(hex_str)

def calculate_entropy(data):
    """Calculate the entropy of a given data."""
    if not data:
        return 0
    entropy = 0
    data_len = len(data)
    counter = Counter(data)
    for count in counter.values():
        probability = count / data_len
        entropy -= probability * math.log2(probability)
    return entropy

def top_n_frequencies(data, n=5):
    """Calculate the top-N frequencies of characters in the data."""
    freq_dist = Counter(data)
    most_common = freq_dist.most_common(n)
    dictionary = {f'top_{i+1}_freq': count for i, (char, count) in enumerate(most_common)}
    for i in range(1, 6):
        if f"top_{i}_freq" not in dictionary:
            dictionary[f"top_{i}_freq"] = 0
    return dictionary

def extract_features(ciphertext_hex):
    """Extract features from the given ciphertext in hexadecimal form."""
    features = {}

    # Convert hex to bytes
    ciphertext_bytes = hex_to_bytes(ciphertext_hex)

    # Ciphertext length
    features['length'] = len(ciphertext_bytes)

    # Entropy
    features['entropy'] = calculate_entropy(ciphertext_bytes)

    # Frequency distribution
    freq_dist = top_n_frequencies(ciphertext_bytes)
    features.update({f'freq_{byte}': count for byte, count in freq_dist.items()})

    # Block size (assuming common block sizes)
    block_sizes = [8, 16, 32]
    for block_size in block_sizes:
        if len(ciphertext_bytes) % block_size == 0:
            features['block_size'] = block_size
            break
    else:
        features['block_size'] = None

    # Feature: Byte Distribution
    byte_distribution = Counter(ciphertext_bytes)
    features['byte_distribution_mean'] = np.mean(list(byte_distribution.values()))
    features['byte_distribution_std'] = np.std(list(byte_distribution.values()))

    # Feature: Repetition Patterns
    repetition_count = sum([ciphertext_bytes[i] == ciphertext_bytes[i+1] for i in range(len(ciphertext_bytes) - 1)])
    features['repetition_count'] = repetition_count / len(ciphertext_bytes)

    # Feature: Hamming Distance Between Adjacent Blocks
    block_size = features['block_size']  # Assuming AES-like block size
    if block_size is None:
        hamming_distances = []
    else:
        hamming_distances = []
        for i in range(0, len(ciphertext_bytes) - block_size, block_size):
            block1 = ciphertext_bytes[i:i+block_size]
            block2 = ciphertext_bytes[i+block_size:i+2*block_size]
            hamming_distances.append(np.sum(np.bitwise_xor(list(block1), np.array(list(block2)))))
    features['avg_hamming_distance'] = np.mean(hamming_distances) if hamming_distances else 0

    # Feature: Bit-Level Features
    bits = ''.join(format(byte, '08b') for byte in ciphertext_bytes)
    features['bit_zeros_ratio'] = bits.count('0') / len(bits)
    features['bit_ones_ratio'] = bits.count('1') / len(bits)

    # Feature: Padding Detection
    padding_byte = ciphertext_bytes[-1]
    padding_length = padding_byte if all(byte == padding_byte for byte in ciphertext_bytes[-padding_byte:]) else 0
    features['padding_length'] = padding_length

    return features

def extract_iv_and_infer_mode(ciphertext_hex, features, block_size=16):
    """Extract IV and infer mode of operation from the given ciphertext in hexadecimal form."""
    # Convert hex to bytes
    ciphertext_bytes = hex_to_bytes(ciphertext_hex)

    # Extract IV (assuming it's the first block)
    iv = ciphertext_bytes[:block_size]
    features['iv'] = iv

    # Infer mode of operation (basic heuristics)
    if len(ciphertext_bytes) % block_size != 0:
        features['mode'] = 'Unknown or Stream Cipher'
    else:
        # Check for ECB patterns (repeated blocks)
        blocks = [ciphertext_bytes[i:i+block_size] for i in range(0, len(ciphertext_bytes), block_size)]
        if len(blocks) != len(set(blocks)):
            features['mode'] = 'ECB'
        else:
            features['mode'] = 'CBC or other block mode'

    return features

@flask_app.route("/")
def Home():
    return render_template("index.html")

@flask_app.route('/predict', methods=['POST'])
def predict():
    # Get the hexadecimal data from the form
    hex_data = request.form.get('hexa')  # form data instead of json
    
    if hex_data is None:
        return jsonify({'error': 'No hex_data provided'}), 400
    
    try:
        hex_data = ''.join(hex_data.split())
        # Step 1: Extract features from the hexadecimal data
        features = extract_features(hex_data)
        
        # Step 2: Extract IV and infer mode of operation
        features = extract_iv_and_infer_mode(hex_data, features)

        # Convert features to DataFrame for prediction
        features_df = pd.DataFrame([features])

        features_df.drop(columns=['iv', 'length', 'block_size'], inplace=True)
        X = features_df

        label_encoder = LabelEncoder()
        X['mode'] = label_encoder.fit_transform(X[['mode']])
        # Step 3: Make predictions using your ML model
        prediction = model.predict(X)
        
        return render_template("index.html", prediction_text=f"The algorithm is {prediction}")
    
    except ValueError:
        return jsonify({'error': 'Invalid hexadecimal data'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    
if __name__ == '__main__':
    flask_app.run(debug=True,port=5001)
