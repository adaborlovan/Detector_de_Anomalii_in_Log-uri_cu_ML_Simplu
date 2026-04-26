import random
from datetime import datetime, timedelta
import pandas as pd

from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt


# 1. LOG GENERATION

print("="*50)
print(" LOG ANOMALY DETECTOR - CLOUD SECURITY PROJECT ")
print("="*50)

def generate_logs():
    normal_ips = [f"192.168.1.{i}" for i in range(1, 20)]
    attacker_ip = "10.0.0.99"

    actions = ["LOGIN_SUCCESS", "LOGIN_FAILED", "GET /home", "GET /profile"]

    logs = []
    current_time = datetime.now()

    # normal behavior
    for _ in range(300):
        ip = random.choice(normal_ips)
        action = random.choice(actions)

        logs.append({
            "timestamp": current_time,
            "ip": ip,
            "action": action
        })

        current_time += timedelta(seconds=random.randint(2, 10))

    # brute-force attacker
    for _ in range(60):
        logs.append({
            "timestamp": current_time,
            "ip": attacker_ip,
            "action": "LOGIN_FAILED"
        })
        current_time += timedelta(seconds=1)

    random.shuffle(logs)
    return pd.DataFrame(logs)


df = generate_logs()
print(f"[+] Logs generated: {len(df)}")



# 2. FEATURE ENGINEERING

print("\n[2] Feature extraction...")

data = df.groupby("ip").agg(
    requests=("action", "count"),
    failed_logins=("action", lambda x: (x == "LOGIN_FAILED").sum())
)

data["fail_rate"] = data["failed_logins"] / data["requests"]
data["fail_rate"] = data["fail_rate"].fillna(0)

print(f"[+] Unique IPs: {len(data)}")



# 3. MODEL TRAINING

print("\n[3] Training Isolation Forest...")

X = data[["requests", "failed_logins", "fail_rate"]]

model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X)

data["anomaly"] = model.predict(X)
data["score"] = model.decision_function(X)



# 4. RISK CLASSIFICATION

def risk_level(score):
    if score < -0.2:
        return "HIGH"
    elif score < -0.05:
        return "MEDIUM"
    return "LOW"

data["risk"] = data["score"].apply(risk_level)



# 5. RESULTS

print("\n[4] Detected anomalies:\n")

alerts = data[data["anomaly"] == -1]

if alerts.empty:
    print("No anomalies detected.")
else:
    for ip, row in alerts.iterrows():
        print(f"[ALERT] IP: {ip}")
        print(f"   Requests: {row['requests']}")
        print(f"   Failed logins: {row['failed_logins']}")
        print(f"   Fail rate: {row['fail_rate']:.2f}")
        print(f"   Risk: {row['risk']}")
        print(f"   Score: {row['score']:.4f}")
        print("-"*40)



# 6. VISUALIZATION

print("\n[5] Generating plot...")

colors = data["anomaly"].map({1: "blue", -1: "red"})

plt.figure(figsize=(8,6))
plt.scatter(data["requests"], data["failed_logins"], c=colors)

for ip, row in alerts.iterrows():
    plt.text(row["requests"], row["failed_logins"], ip)

plt.xlabel("Requests")
plt.ylabel("Failed Logins")
plt.title("Brute-force Anomaly Detection")

plt.savefig("anomaly_plot.png")
plt.show()

print("[+] Plot saved as anomaly_plot.png")



# 7. SAVE OUTPUT

data.to_csv("results.csv")

print("\n[+] Results saved to results.csv")
print("="*50)