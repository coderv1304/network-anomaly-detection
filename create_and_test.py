import pandas as pd
import numpy as np

print("Loading data...")

# --- BENIGN (majority, as in real traffic ~75%) ---
df_benign = pd.read_csv('data/Monday-WorkingHours.pcap_ISCX.csv', encoding='cp1252', nrows=6000)
df_benign.columns = df_benign.columns.str.strip()
df_benign = df_benign[df_benign['Label'] == 'BENIGN'].head(5200)

# --- DDoS (large attack, Friday afternoon) ---
df_ddos = pd.read_csv('data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv', encoding='cp1252', nrows=3000)
df_ddos.columns = df_ddos.columns.str.strip()
df_ddos = df_ddos[df_ddos['Label'] == 'DDoS'].head(900)

# --- PortScan ---
df_portscan = pd.read_csv('data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv', encoding='cp1252', nrows=1500)
df_portscan.columns = df_portscan.columns.str.strip()
df_portscan = df_portscan[df_portscan['Label'] == 'PortScan'].head(450)

# --- Web Attacks (Thursday morning) ---
df_web = pd.read_csv('data/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv', encoding='cp1252', nrows=1000)
df_web.columns = df_web.columns.str.strip()
df_web_attacks = df_web[df_web['Label'] != 'BENIGN'].head(220)

# --- DoS Hulk (Wednesday) ---
df_wed = pd.read_csv('data/Wednesday-workingHours.pcap_ISCX.csv', encoding='cp1252', nrows=2000)
df_wed.columns = df_wed.columns.str.strip()
df_dos = df_wed[df_wed['Label'] == 'DoS Hulk'].head(180)

# --- FTP Patator (Tuesday) ---
df_tue = pd.read_csv('data/Tuesday-WorkingHours.pcap_ISCX.csv', encoding='cp1252', nrows=1000)
df_tue.columns = df_tue.columns.str.strip()
df_ftp = df_tue[df_tue['Label'] == 'FTP-Patator'].head(50)

# --- Combine and shuffle ---
df_test = pd.concat([
    df_benign,
    df_ddos,
    df_portscan,
    df_web_attacks,
    df_dos,
    df_ftp
], ignore_index=True)

df_test = df_test.sample(frac=1, random_state=42).reset_index(drop=True)
df_test.to_csv('test_dataset.csv', index=False)

# Print summary
total = len(df_test)
print(f"\n✅ Created 'test_dataset.csv' with {total} rows")
print(f"\nDistribution (realistic imbalance):")
counts = df_test['Label'].value_counts()
for label, count in counts.items():
    pct = count / total * 100
    print(f"  {label:<35} {count:>5} ({pct:.1f}%)")
print(f"\nUpload at http://127.0.0.1:5000")