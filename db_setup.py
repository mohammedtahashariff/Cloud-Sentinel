import os
import sqlite3
import datetime
import bcrypt
import numpy as np

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'anomaly_detection.db')

def init_db():
    print(f"Initializing database at: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # Drop existing tables to ensure clean rebuild
    cursor.execute("DROP TABLE IF EXISTS active_attack;")
    cursor.execute("DROP TABLE IF EXISTS blockchain_ledger;")
    cursor.execute("DROP TABLE IF EXISTS detections;")
    cursor.execute("DROP TABLE IF EXISTS node_metrics;")
    cursor.execute("DROP TABLE IF EXISTS events;")
    cursor.execute("DROP TABLE IF EXISTS nodes;")
    cursor.execute("DROP TABLE IF EXISTS users;")
    
    # 1. Create Nodes Table (12 AWS, 12 Azure, 12 GCP = 36 total nodes)
    cursor.execute("""
    CREATE TABLE nodes (
        node_id TEXT PRIMARY KEY,
        cloud_provider TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        ip TEXT NOT NULL,
        public_ip TEXT,
        region TEXT NOT NULL
    );
    """)
    
    # 2. Create Node Metrics Table (Telemetry Stream)
    cursor.execute("""
    CREATE TABLE node_metrics (
        metrics_id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id TEXT NOT NULL,
        timestamp DATETIME NOT NULL,
        cpu_utilization REAL NOT NULL,
        memory_utilization REAL NOT NULL,
        disk_utilization REAL NOT NULL,
        network_traffic REAL NOT NULL,
        failed_logins INTEGER NOT NULL,
        running_processes INTEGER NOT NULL,
        running_processes_text TEXT,
        status TEXT NOT NULL,
        is_anomalous INTEGER NOT NULL,
        risk_score REAL NOT NULL,
        threat_type TEXT NOT NULL,
        FOREIGN KEY (node_id) REFERENCES nodes (node_id) ON DELETE CASCADE
    );
    """)
    
    # 3. Create Security Detections log
    cursor.execute("""
    CREATE TABLE detections (
        detection_id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        category TEXT NOT NULL,
        anomaly_score REAL NOT NULL,
        is_anomalous INTEGER NOT NULL,
        model_used TEXT NOT NULL,
        timestamp DATETIME NOT NULL,
        raw_log TEXT NOT NULL
    );
    """)
    
    # 4. Create Blockchain Audit Ledger
    cursor.execute("""
    CREATE TABLE blockchain_ledger (
        block_id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        transactions_count INTEGER NOT NULL,
        block_hash TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        integrity_status TEXT NOT NULL
    );
    """)
    
    # 5. Create Active Attack Configuration (Coordinator)
    cursor.execute("""
    CREATE TABLE active_attack (
        attack_id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        intensity REAL NOT NULL,
        is_active INTEGER NOT NULL
    );
    """)
    
    # 6. Create Users Table
    cursor.execute("""
    CREATE TABLE users (
        user_id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL
    );
    """)
    
    conn.commit()
    print("Tables created successfully.")
    
    # Seed Admin User
    hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode('utf-8')
    cursor.execute(
        "INSERT INTO users (user_id, username, password_hash, role) VALUES (?, ?, ?, ?)",
        ("usr-admin", "admin", hashed, "Administrator")
    )
    print("Seeded user 'admin'")
    
    # Seed exactly 36 nodes (12 AWS, 12 Azure, 12 GCP)
    providers = ['AWS', 'Azure', 'GCP']
    r_types = ['VM', 'Container', 'Kubernetes Pod']
    regions = {
        'AWS': ['us-east-1', 'us-west-2', 'eu-west-1'],
        'Azure': ['eastus', 'westus2', 'westeurope'],
        'GCP': ['us-central1', 'us-east4', 'asia-east1']
    }
    
    nodes = []
    # Seed 12 AWS nodes
    for i in range(12):
        node_id = f"aws-node-{i+1:02d}"
        cloud = "AWS"
        rtype = r_types[i % 3]
        ip = f"10.0.1.{10+i}"
        pub_ip = f"54.210.14.{10+i}"
        reg = regions[cloud][i % 3]
        nodes.append((node_id, cloud, rtype, ip, pub_ip, reg))
        
    # Seed 12 Azure nodes
    for i in range(12):
        node_id = f"azure-node-{i+1:02d}"
        cloud = "Azure"
        rtype = r_types[i % 3]
        ip = f"10.1.1.{10+i}"
        pub_ip = f"52.160.8.{10+i}"
        reg = regions[cloud][i % 3]
        nodes.append((node_id, cloud, rtype, ip, pub_ip, reg))
        
    # Seed 12 GCP nodes
    for i in range(12):
        node_id = f"gcp-node-{i+1:02d}"
        cloud = "GCP"
        rtype = r_types[i % 3]
        ip = f"10.2.1.{10+i}"
        pub_ip = f"35.220.190.{10+i}"
        reg = regions[cloud][i % 3]
        nodes.append((node_id, cloud, rtype, ip, pub_ip, reg))
        
    cursor.executemany(
        "INSERT INTO nodes (node_id, cloud_provider, resource_type, ip, public_ip, region) VALUES (?, ?, ?, ?, ?, ?)",
        nodes
    )
    print(f"Seeded {len(nodes)} nodes (12 AWS, 12 Azure, 12 GCP).")
    
    # Seed historical telemetry baselines (e.g., 5 past metrics per node to populate charts)
    now = datetime.datetime.now()
    # Seed Genesis Block for Blockchain Ledger
    genesis_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    cursor.execute("""
        INSERT INTO blockchain_ledger (timestamp, transactions_count, block_hash, prev_hash, integrity_status)
        VALUES (?, ?, ?, ?, ?)
    """, (now.strftime('%Y-%m-%d %H:%M:%S'), 0, genesis_hash, "0", "Verified"))
    print("Blockchain initialized with Genesis Block.")
    
    conn.commit()
    conn.close()
    print("Database initialization successful.")

if __name__ == '__main__':
    init_db()
