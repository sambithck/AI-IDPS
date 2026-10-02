import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import os

FEATURE_COLUMNS = [
    "packet_rate",
    "byte_rate",
    "unique_ports",
    "syn_rate",
    "icmp_rate",
    "udp_rate",
    "fin_rate",
    "null_rate",
    "xmas_rate",
    "request_rate",
    "error_rate",
    "failed_login_rate",
    "admin_path_hits",
    "suspicious_pattern_score",
]
CLASS_NAMES = ["Normal","PortScan","DoS","BruteForce","WebAttack"]
MODEL_PATH = os.path.join(os.path.dirname(__file__), "idps_xgb_model.json")

def generate_dataset(n=3000, seed=42):
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n):
        rows.append([rng.normal(5,2),rng.normal(2000,800),rng.integers(1,4),rng.normal(0.2,0.2),0,rng.normal(0.5,0.3),0,0,0,rng.normal(1,0.5),rng.uniform(0,0.05),0,0,rng.uniform(0,0.1),0])
    for _ in range(n):
        rows.append([rng.normal(40,10),rng.normal(500,200),rng.integers(15,60),rng.normal(35,8),0,rng.normal(2,1),rng.normal(8,3),rng.normal(5,2),rng.normal(3,1),rng.normal(0.2,0.2),rng.uniform(0,0.1),0,0,rng.uniform(0,0.1),1])
    for _ in range(n):
        rows.append([rng.normal(500,100),rng.normal(500000,100000),rng.integers(1,3),rng.normal(50,15),rng.normal(40,10),rng.normal(60,15),0,0,0,rng.normal(50,15),rng.uniform(0,0.2),0,0,rng.uniform(0,0.1),2])
    for _ in range(n):
        rows.append([rng.normal(10,3),rng.normal(3000,1000),rng.integers(1,3),rng.normal(1,0.5),0,rng.normal(1,0.5),0,0,0,rng.normal(20,5),rng.uniform(0.6,0.95),rng.normal(8,2),rng.normal(3,1),rng.uniform(0,0.2),3])
    for _ in range(n):
        rows.append([rng.normal(8,3),rng.normal(4000,1500),rng.integers(1,3),rng.normal(0.5,0.3),0,rng.normal(0.5,0.3),0,0,0,rng.normal(5,2),rng.uniform(0.1,0.4),0,0,rng.uniform(0.4,1.0),4])
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS+["label"])
    for col in FEATURE_COLUMNS:
        df[col] = df[col].clip(lower=0)
    return df

def train():
    df = generate_dataset()
    X = df[FEATURE_COLUMNS]
    y = df["label"]
    X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.2,random_state=42,stratify=y)
    model = xgb.XGBClassifier(n_estimators=150,max_depth=6,learning_rate=0.1,objective="multi:softprob",num_class=len(CLASS_NAMES),eval_metric="mlogloss")
    model.fit(X_train,y_train)
    preds = model.predict(X_test)
    print(classification_report(y_test,preds,target_names=CLASS_NAMES))
    model.save_model(MODEL_PATH)
    print("Model saved to", MODEL_PATH)

if __name__ == "__main__":
    train()
