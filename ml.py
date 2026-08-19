import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import seaborn as sns # For a nicer-looking confusion matrix plot

# --- 1. Load the Data ---
try:
    df = pd.read_csv('network_traffic.csv')
    df.dropna(inplace=True) 
except FileNotFoundError:
    print("Error: network_traffic.csv not found. Make sure it's in the same directory.")
    exit()

print(f"Loaded {len(df)} total packets.")

# --- 2. Separate Normal and Attack Traffic ---
# For training, we only use traffic that our rule-based system marked as normal.
normal_traffic = df[df['rule_based_alert'] == 0]
attack_traffic = df[df['rule_based_alert'] == 1]

print(f"Separated data into {len(normal_traffic)} normal packets and {len(attack_traffic)} alert packets.")

# --- 3. Select Numerical Features for Clustering ---
# We select features that describe the packet's behavior.
# We exclude IPs for now as they are categorical.
features_to_use = ['source_port', 'destination_port', 'protocol', 'length']
normal_traffic_features = normal_traffic[features_to_use]

# --- 4. Scale the Data ---
# This is crucial for k-means. It scales the data so that all features have a 
# mean of 0 and a standard deviation of 1.
scaler = StandardScaler()
scaled_normal_traffic = scaler.fit_transform(normal_traffic_features)

print("\nData preparation complete. Here's a sample of the scaled 'normal' data for training:")
print(pd.DataFrame(scaled_normal_traffic, columns=features_to_use).head())

print("\n--- Step 2: Finding the optimal k using the Elbow Method ---")

# We will test k values from 1 to 5 (since we only have 18 data points)
inertia_values = []
k_range = range(1, 6)

for k in k_range:
    kmeans = KMeans(n_clusters=k, random_state=42, n_init=10) # n_init=10 is to avoid bad luck
    kmeans.fit(scaled_normal_traffic)
    inertia_values.append(kmeans.inertia_)

# --- Plot the Elbow Curve ---
plt.figure(figsize=(8, 5))
plt.plot(k_range, inertia_values, 'bo-')
plt.xlabel('Number of Clusters (k)')
plt.ylabel('Inertia (Sum of squared distances)')
plt.title('Elbow Method for Optimal k')
plt.xticks(k_range)
plt.grid(True)
plt.show()

print("Please look at the plot. The 'elbow' is the point where the drop-off slows down.")
print("This suggests the optimal number of clusters to use.")

OPTIMAL_K = 3 

print(f"\n--- Step 3: Training k-means model with k={OPTIMAL_K} ---")

# 1. Train the final model
kmeans = KMeans(n_clusters=OPTIMAL_K, random_state=42, n_init=10)
kmeans.fit(scaled_normal_traffic)

print("Model training complete.")

# 2. Calculate distances for the *normal* data
# .transform() gets the distances of each point to ALL cluster centers.
# .min(axis=1) gets just the distance to the *closest* cluster center.
distances_to_center = kmeans.transform(scaled_normal_traffic).min(axis=1)

# 3. Find the anomaly threshold (e.g., 95th percentile)
# This means 95% of all 'normal' traffic falls within this distance.
# Anything further out will be considered an anomaly.
threshold = np.quantile(distances_to_center, 0.95)

print(f"Anomaly threshold (95th percentile distance) set to: {threshold:.4f}")

# --- We are now ready for the final step: Testing the model ---
print("\n--- Step 4: Testing the Model on the Full Dataset ---")

# --- 1. Prepare the FULL dataset ---
# We use the *same* features_to_use list from Step 1
all_traffic_features = df[features_to_use]

# IMPORTANT: We use .transform() ONLY. We do *not* .fit() again.
# We are scaling the new data based on what the model learned from the normal data.
scaled_full_traffic = scaler.transform(all_traffic_features)

# --- 2. Calculate distances for ALL packets ---
all_distances = kmeans.transform(scaled_full_traffic).min(axis=1)

# --- 3. Make Predictions ---
# If distance > threshold, predict 1 (Anomaly), otherwise predict 0 (Normal)
predictions = np.where(all_distances > threshold, 1, 0)

# Get the actual labels from the original dataframe
actual_labels = df['rule_based_alert']

# --- 4. Evaluate the Results ---
print("\n--- MODEL EVALUATION RESULTS ---")

# Confusion Matrix
cm = confusion_matrix(actual_labels, predictions)
print(f"Confusion Matrix:\n{cm}")

print("\n(Rows=Actual, Columns=Predicted)")
print("[[True Neg (Normal, Predicted Normal), False Pos (Normal, Predicted Anomaly)],")
print(" [False Neg (Attack, Predicted Normal), True Pos (Attack, Predicted Anomaly)]]")

# Key Metrics
accuracy = accuracy_score(actual_labels, predictions)
precision = precision_score(actual_labels, predictions, zero_division=0)
recall = recall_score(actual_labels, predictions, zero_division=0)
f1 = f1_score(actual_labels, predictions, zero_division=0)

print(f"\nAccuracy: {accuracy*100:.2f}%")
print(f"Precision: {precision:.4f} (Of all 'Anomaly' predictions, how many were real attacks?)")
print(f"Recall: {recall:.4f} (Of all real attacks, how many did we catch?)")
print(f"F1-Score: {f1:.4f} (A balance of Precision and Recall)")

# Optional: Plot the confusion matrix
plt.figure(figsize=(6, 4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=['Predicted Normal', 'Predicted Anomaly'], 
            yticklabels=['Actual Normal', 'Actual Attack'])
plt.title('Anomaly Detection Confusion Matrix')
plt.ylabel('Actual Label')
plt.xlabel('Predicted Label')
plt.show()