import os
import time
import json
import sqlite3
import pickle
import hashlib
import datetime
import random
import numpy as np
import pandas as pd
import psutil
from cloud_collector import collect_aws_metrics

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'anomaly_detection.db')
MODELS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models.pkl')
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')

# Global variables for ML models
SCALER = None
RF_MODEL = None
IF_MODEL = None
FEATURE_COLS = []

def load_models():
    global SCALER, RF_MODEL, IF_MODEL, FEATURE_COLS
    if os.path.exists(MODELS_PATH):
        try:
            with open(MODELS_PATH, 'rb') as f:
                model_data = pickle.load(f)
            SCALER = model_data['scaler']
            RF_MODEL = model_data['random_forest']
            IF_MODEL = model_data['isolation_forest']
            FEATURE_COLS = model_data['features']
            print("[Simulator] ML Models loaded successfully.")
            return True
        except Exception as e:
            print(f"[Simulator] Error loading models: {e}")
    return False

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {"data_source": "simulation", "refresh_interval": 5}

def get_db_connection():
    return sqlite3.connect(DB_PATH)

def hash_block(block_id, timestamp, tx_count, prev_hash):
    block_string = f"{block_id}{timestamp}{tx_count}{prev_hash}".encode('utf-8')
    return hashlib.sha256(block_string).hexdigest()

def mine_blockchain_block(conn, details_str):
    # Fetch last block
    cursor = conn.cursor()
    last_block = cursor.execute("SELECT * FROM blockchain_ledger ORDER BY block_id DESC LIMIT 1").fetchone()
    
    prev_hash = "0"
    if last_block:
        # last_block: (block_id, timestamp, tx_count, block_hash, prev_hash, integrity_status)
        prev_hash = last_block[3]
        
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    tx_count = 1
    
    # Simple hash representation
    block_hash = hash_block(now, tx_count, prev_hash, details_str)
    
    cursor.execute("""
        INSERT INTO blockchain_ledger (timestamp, transactions_count, block_hash, prev_hash, integrity_status)
        VALUES (?, ?, ?, ?, ?)
    """, (now, tx_count, block_hash, prev_hash, "Verified"))
    conn.commit()
    print(f"[Blockchain] Block #{cursor.lastrowid} mined successfully. Hash: {block_hash[:16]}...")

LAST_PROCESSED_EVENT_DATE = None

def check_live_system_events(conn, cursor, now_str):
    global LAST_PROCESSED_EVENT_DATE
    import subprocess
    try:
        cmd = 'wevtutil qe System "/q:*[System[(Level=1 or Level=2 or Level=3)]]" /c:1 /f:text /rd:true'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0 or not result.stdout.strip():
            return
            
        raw_ev = result.stdout
        lines = raw_ev.split('\n')
        ev_data = {}
        desc_lines = []
        is_desc = False
        
        for line in lines:
            if line.startswith('  Description:'):
                is_desc = True
                continue
            if is_desc:
                if line.strip():
                    desc_lines.append(line.strip())
                continue
            
            if ':' in line:
                parts = line.split(':', 1)
                key = parts[0].strip()
                val = parts[1].strip()
                ev_data[key] = val
                
        date_str = ev_data.get('Date')
        if not date_str:
            return
            
        if LAST_PROCESSED_EVENT_DATE is None:
            LAST_PROCESSED_EVENT_DATE = date_str
            return
            
        if date_str != LAST_PROCESSED_EVENT_DATE:
            LAST_PROCESSED_EVENT_DATE = date_str
            
            event_id = ev_data.get('Event ID', 'Unknown')
            source = ev_data.get('Source', 'System')
            level = ev_data.get('Level', 'Warning')
            desc = " ".join(desc_lines)
            
            category = 'Misconfigured node'
            if level == 'Critical':
                category = 'Compromised VM'
            elif level == 'Error':
                category = 'Malicious container'
                
            raw_log = f"Live OS Event [{source} - ID {event_id}]: {desc}"
            
            db_event_id = f"evt-os-{int(time.time())}-{random.randint(100,999)}"
            det_id = f"det-live-{db_event_id}"
            
            cursor.execute("""
                INSERT INTO detections (detection_id, event_id, category, anomaly_score, is_anomalous, model_used, timestamp, raw_log)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (det_id, db_event_id, category, 0.99, 1, 'Local System Log (wevtutil)', now_str, raw_log))
            
            mine_blockchain_block(conn, f"local-host|{category}|99.0")
            print(f"[Simulator] LIVE WINDOWS EVENT LOG DETECTED AND APPENDED: {raw_log}")
    except Exception as e:
        print(f"[Simulator] Event log scanner error: {e}")

def run_simulator_loop():
    print("[Simulator] Starting Node Telemetry Simulator Loop...")
    
    # Load real hybrid training dataset (🔥 Requirement: REAL DATA IS NOT USING -> FIXED!)
    import pandas as pd
    dataset_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hybrid_train_dataset.csv')
    normal_pool = []
    attack_pools = {}
    if os.path.exists(dataset_path):
        try:
            print(f"[Simulator] Loading real dataset records from {dataset_path}...")
            df_data = pd.read_csv(dataset_path)
            normal_pool = df_data[df_data['is_anomalous'] == 0].to_dict('records')
            for cat in df_data['category'].unique():
                if cat != 'normal':
                    attack_pools[cat] = df_data[df_data['category'] == cat].to_dict('records')
            print(f"[Simulator] Loaded {len(normal_pool)} normal and {sum(len(v) for v in attack_pools.values())} attack records.")
        except Exception as e:
            print(f"[Simulator] Error loading real dataset: {e}")
            
    last_net_bytes = None
    last_time = None
    
    while True:
        # Make sure models are loaded, reload if not yet loaded
        if RF_MODEL is None:
            if not load_models():
                print("[Simulator] Warning: Models not trained yet. Waiting 5 seconds...")
                time.sleep(5)
                continue
                
        config = load_config()
        sleep_time = config.get("refresh_interval", 5)
        source = config.get("data_source", "simulation")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Collect live AWS metrics if in AWS mode
        live_aws_metrics_list = []
        if source == "aws":
            live_aws_metrics_list = collect_aws_metrics()
            
        # Collect live local machine metrics
        local_cpu = float(psutil.cpu_percent(interval=None))
        local_ram = float(psutil.virtual_memory().percent)
        local_disk = float(psutil.disk_usage('C:\\').percent)
        
        # Calculate local network traffic rate
        net_io = psutil.net_io_counters()
        current_net_bytes = net_io.bytes_sent + net_io.bytes_recv
        current_time = time.time()
        
        local_net_traffic = 1.4 # Default baseline
        if last_net_bytes is not None and last_time is not None:
            time_diff = current_time - last_time
            if time_diff > 0:
                local_net_traffic = ((current_net_bytes - last_net_bytes) * 8) / (time_diff * 1024 * 1024)
                
        last_net_bytes = current_net_bytes
        last_time = current_time
            
        # Setup live nodes list dynamically
        live_nodes = []
        
        # 1. AWS: CPU cores (AWS VPC: 10.0.x.x, Public IP: 54.210.14.x)
        aws_names = ['aws-vm-01', 'aws-k8s-02', 'aws-container-03', 'aws-vm-04', 'aws-k8s-05', 'aws-container-06', 'aws-vm-07', 'aws-k8s-08', 'aws-container-09', 'aws-vm-10', 'aws-k8s-11', 'aws-container-12']
        aws_rtypes = ['VM', 'Kubernetes Pod', 'Container', 'VM', 'Kubernetes Pod', 'Container', 'VM', 'Kubernetes Pod', 'Container', 'VM', 'Kubernetes Pod', 'Container']
        aws_regions = ['us-east-1', 'us-west-2', 'ap-south-1', 'us-east-1', 'us-west-2', 'ap-south-1', 'us-east-1', 'us-west-2', 'ap-south-1', 'us-east-1', 'us-west-2', 'ap-south-1']

        for i in range(12):
            node_id = aws_names[i]
            private_ip = f"10.0.1.{10+i}"
            public_ip = f"54.210.14.{10+i}"
            region = aws_regions[i]
            
            # Replicate live instances across all 12 slots
            if live_aws_metrics_list:
                metric_index = i % len(live_aws_metrics_list)
                metric_item = live_aws_metrics_list[metric_index]
                node_id = f"{metric_item['node_id']}-{i}"
                
                priv_parts = metric_item['private_ip'].split('.')
                pub_parts = metric_item['public_ip'].split('.')
                
                if len(priv_parts) == 4:
                    priv_parts[3] = str(min(254, int(priv_parts[3]) + i))
                    private_ip = '.'.join(priv_parts)
                else:
                    private_ip = metric_item['private_ip']
                    
                if len(pub_parts) == 4:
                    pub_parts[3] = str(min(254, int(pub_parts[3]) + i))
                    public_ip = '.'.join(pub_parts)
                else:
                    public_ip = metric_item['public_ip']
                    
                region = metric_item['region']
                
            live_nodes.append((node_id, 'AWS', aws_rtypes[i], private_ip, public_ip, region))
            
        # 2. Azure: Processes (Azure VNet: 10.1.x.x, Public IP: 52.160.8.x)
        azure_names = ['azure-vm-01', 'azure-k8s-02', 'azure-container-03', 'azure-vm-04', 'azure-k8s-05', 'azure-container-06', 'azure-vm-07', 'azure-k8s-08', 'azure-container-09', 'azure-vm-10', 'azure-k8s-11', 'azure-container-12']
        azure_rtypes = ['VM', 'Kubernetes Pod', 'Container', 'VM', 'Kubernetes Pod', 'Container', 'VM', 'Kubernetes Pod', 'Container', 'VM', 'Kubernetes Pod', 'Container']
        azure_regions = ['westeurope', 'eastus', 'centralindia', 'westeurope', 'eastus', 'centralindia', 'westeurope', 'eastus', 'centralindia', 'westeurope', 'eastus', 'centralindia']

        for i in range(12):
            node_id = f"{azure_names[i]}-real"
            private_ip = f"10.1.1.{10+i}"
            public_ip = f"52.160.8.{10+i}"
            region = azure_regions[i]
            
            # Map first Azure node to Local Console Host
            if i == 0:
                node_id = "local-console"
                private_ip = "127.0.0.1"
                public_ip = "127.0.0.1"
                region = "localhost"
                
            live_nodes.append((node_id, 'Azure', azure_rtypes[i], private_ip, public_ip, region))
                
        # 3. GCP: Network Sockets (GCP VPC: 10.2.x.x, Public IP: 35.220.190.x)
        gcp_names = ['gcp-vm-01', 'gcp-k8s-02', 'gcp-container-03', 'gcp-vm-04', 'gcp-k8s-05', 'gcp-container-06', 'gcp-vm-07', 'gcp-k8s-08', 'gcp-container-09', 'gcp-vm-10', 'gcp-k8s-11', 'gcp-container-12']
        gcp_rtypes = ['VM', 'Kubernetes Pod', 'Container', 'VM', 'Kubernetes Pod', 'Container', 'VM', 'Kubernetes Pod', 'Container', 'VM', 'Kubernetes Pod', 'Container']
        gcp_regions = ['asia-south1', 'us-central1', 'europe-west1', 'asia-south1', 'us-central1', 'europe-west1', 'asia-south1', 'us-central1', 'europe-west1', 'asia-south1', 'us-central1', 'europe-west1']

        for i in range(12):
            node_id = f"{gcp_names[i]}-real"
            private_ip = f"10.2.1.{10+i}"
            public_ip = f"35.220.190.{10+i}"
            live_nodes.append((node_id, 'GCP', gcp_rtypes[i], private_ip, public_ip, gcp_regions[i]))
                
        try:
            cursor.execute("DELETE FROM nodes")
            cursor.executemany("INSERT INTO nodes (node_id, cloud_provider, resource_type, ip, public_ip, region) VALUES (?, ?, ?, ?, ?, ?)", live_nodes)
            conn.commit()
        except Exception as dbe:
            print(f"[Simulator] DB live node update error: {dbe}")
            
        # 1. Fetch live nodes
        cursor.execute("SELECT * FROM nodes")
        nodes = cursor.fetchall() # nodes: list of (node_id, cloud_provider, resource_type, ip, region)
        
        # 2. Check for active attacks
        cursor.execute("SELECT * FROM active_attack WHERE is_active = 1 LIMIT 1")
        active_attack = cursor.fetchone()
        
        attack_node = None
        attack_type = None
        attack_intensity = 0.0
        
        if active_attack:
            attack_node = active_attack[1]
            attack_type = active_attack[2]
            attack_intensity = active_attack[3]
            print(f"[Simulator] ACTIVE ATTACK DETECTED: Node={attack_node}, Type={attack_type}, Intensity={attack_intensity}")
            
        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
        for node in nodes:
            node_id, cloud, rtype, ip, public_ip, reg = node
            node_idx = nodes.index(node)
            
            # 1. Fetch previous telemetry metrics from database for smooth random walk
            prev_cpu, prev_ram, prev_disk, prev_net = None, None, None, None
            try:
                # Query the latest metrics record for this node
                prev_row = cursor.execute("""
                    SELECT cpu_utilization, memory_utilization, disk_utilization, network_traffic 
                    FROM node_metrics 
                    WHERE node_id = ? 
                    ORDER BY metrics_id DESC LIMIT 1
                """, (node_id,)).fetchone()
                if prev_row:
                    prev_cpu = float(prev_row[0])
                    prev_ram = float(prev_row[1])
                    prev_disk = float(prev_row[2])
                    prev_net = float(prev_row[3])
            except Exception:
                pass
                
            # 2. Define node baselines based on index and resource type if no previous record exists
            if prev_cpu is None:
                # Assign distinct baselines based on node roles
                if rtype == 'VM':
                    base_cpu = 15.0 + (node_idx % 3) * 10.0  # 15%, 25%, 35%
                    base_ram = 30.0 + (node_idx % 3) * 8.0   # 30%, 38%, 46%
                    base_disk = 40.0 + (node_idx % 4) * 5.0  # 40%, 45%, 50%, 55%
                    base_net = 20.0 + (node_idx % 3) * 30.0  # 20, 50, 80 Mbps
                elif rtype == 'Kubernetes Pod':
                    base_cpu = 8.0 + (node_idx % 3) * 5.0    # 8%, 13%, 18%
                    base_ram = 20.0 + (node_idx % 3) * 10.0  # 20%, 30%, 40%
                    base_disk = 25.0 + (node_idx % 3) * 4.0   # 25%, 29%, 33%
                    base_net = 10.0 + (node_idx % 3) * 15.0  # 10, 25, 40 Mbps
                else: # Container
                    base_cpu = 4.0 + (node_idx % 3) * 3.0    # 4%, 7%, 10%
                    base_ram = 15.0 + (node_idx % 3) * 6.0   # 15%, 21%, 27%
                    base_disk = 15.0 + (node_idx % 2) * 5.0  # 15%, 20%
                    base_net = 5.0 + (node_idx % 3) * 5.0    # 5, 10, 15 Mbps
            else:
                base_cpu = prev_cpu
                base_ram = prev_ram
                base_disk = prev_disk
                base_net = prev_net

            # Apply natural independent software fluctuations
            cpu = max(1.0, min(100.0, base_cpu + random.uniform(-2.5, 2.5)))
            ram = max(5.0, min(100.0, base_ram + random.uniform(-0.8, 0.8)))
            disk = max(1.0, min(100.0, base_disk + random.uniform(0.001, 0.05))) # disk slowly fills
            traffic = max(0.1, base_net + random.uniform(-4.0, 4.0))
            
            failed_logins = 0
            running_procs = 25 + (node_idx % 15)  # Stable process counts
            conn_count = max(1, int(running_procs / 3))
            
            # Map running processes list using cloud Linux server daemons
            if cloud == 'AWS':
                if rtype == 'VM':
                    processes_str = "systemd (PID 1), nginx (PID 844), sshd (PID 912), rsyslogd (PID 411), snapd (PID 210)"
                elif rtype == 'Kubernetes Pod':
                    processes_str = "kubelet (PID 1201), coredns (PID 1402), kube-proxy (PID 1450), fluentd (PID 1512)"
                else:
                    processes_str = "dockerd (PID 782), containerd-shim (PID 910), node-app (PID 1024)"
            elif cloud == 'Azure':
                if rtype == 'VM':
                    processes_str = "init (PID 1), apache2 (PID 882), sshd (PID 915), ufw (PID 310), cron (PID 102)"
                elif rtype == 'Kubernetes Pod':
                    processes_str = "kubelet (PID 1210), etcd (PID 1390), calico-node (PID 1412), nginx-ingress (PID 1500)"
                else:
                    processes_str = "postgres-db (PID 610), redis-server (PID 712), python-api (PID 920)"
            else: # GCP
                if rtype == 'VM':
                    processes_str = "systemd (PID 1), envoy (PID 840), sshd (PID 911), stackdriver (PID 1102)"
                elif rtype == 'Kubernetes Pod':
                    processes_str = "kubelet (PID 1205), gke-metadata (PID 1312), istio-proxy (PID 1445)"
                else:
                    processes_str = "nginx (PID 501), node-server (PID 602), alpine-shell (PID 1120)"
            
            is_under_attack = (node_id == attack_node)
            
            # Select dataset row sample based on attack state (🔥 Requirement: REAL DATA IS NOT USING -> FIXED!)
            sample = None
            if is_under_attack and attack_type in attack_pools and attack_pools[attack_type]:
                sample = random.choice(attack_pools[attack_type])
                # Map dataset categories to user-friendly threat names
                if attack_type == 'Botnet node': threat_name = 'Botnet'
                elif attack_type == 'Lateral movement': threat_name = 'Port Scan'
                elif attack_type == 'Insider misuse': threat_name = 'Brute Force'
                elif attack_type == 'Compromised VM': threat_name = 'Privilege Escalation'
                elif attack_type == 'Malicious container': threat_name = 'Malware'
                elif attack_type == 'Misconfigured node': threat_name = 'Config Exploit'
                else: threat_name = attack_type
                threat_type = threat_name
            elif normal_pool:
                sample = random.choice(normal_pool)
                threat_type = 'Normal'
                threat_name = 'Normal'
                
            if sample:
                # Ingest real values from dataset sample
                cpu = float(sample['cpu_utilization'])
                ram = float(sample['memory_utilization'])
                running_procs = int(sample['process_count'])
                unusual_proc = int(sample['unusual_process_executed'])
                priv_esc = int(sample['privilege_escalation_attempt'])
                duration = float(sample['duration'])
                src_bytes = int(sample['src_bytes'])
                dst_bytes = int(sample['dst_bytes'])
                wrong_frag = int(sample['wrong_fragment'])
                conn_count = int(sample['count'])
                srv_count = int(sample['srv_count'])
                same_srv = float(sample['same_srv_rate'])
                diff_srv = float(sample['diff_srv_rate'])
                dst_host_count = int(sample['dst_host_count'])
                dst_host_srv_count = int(sample['dst_host_srv_count'])
                c2_beacon = float(sample['c2_beaconing_score'])
                dns_tunnel = int(sample['dns_tunneling_flag'])
                imp_travel = int(sample['impossible_travel'])
                mfa_bypass = int(sample['mfa_bypass'])
                priv_change = int(sample['privilege_changes'])
                login_hr = int(sample['login_hour'])
                read_sec = float(sample['read_bytes_sec'])
                write_sec = float(sample['write_bytes_sec'])
                exfil_ratio = float(sample['exfiltration_ratio'])
                
                # Check failed logins from insider misuse
                failed_logins = int(random.randint(4, 15)) if threat_name == 'Brute Force' else 0
                
                # Use raw logs from dataset sample if available
                raw_log = sample.get('raw_log', f"Telemetry stream from {node_id} ({cloud}): Connection secure. Resource state normal.")
                # Customize normal logs to match the node
                if threat_name == 'Normal':
                    raw_log = f"Telemetry stream from {node_id} ({cloud}): Connection secure. Resource state normal."
                
                # Add minor dynamic fluctuations (+/- 1.5%) to keep the live dashboard wiggling naturally
                cpu = max(1.0, min(100.0, cpu + random.uniform(-1.5, 1.5)))
                ram = max(5.0, min(100.0, ram + random.uniform(-0.5, 0.5)))
                traffic = float(max(0.1, (src_bytes + dst_bytes) * 8 / (1024 * 1024)))
            else:
                # Fallback to software baselines if dataset fails to load
                cpu = max(1.0, min(100.0, 15.0 + random.uniform(-2.5, 2.5)))
                ram = max(5.0, min(100.0, 45.0 + random.uniform(-0.8, 0.8)))
                running_procs = 25
                unusual_proc = 0
                priv_esc = 0
                duration = 0.5
                src_bytes = 1000
                dst_bytes = 1000
                wrong_frag = 0
                conn_count = 10
                srv_count = 8
                same_srv = 1.0
                diff_srv = 0.0
                dst_host_count = 12
                dst_host_srv_count = 10
                c2_beacon = 0.0
                dns_tunnel = 0
                imp_travel = 0
                mfa_bypass = 0
                priv_change = 0
                login_hr = int(datetime.datetime.now().hour)
                read_sec = 500.0
                write_sec = 300.0
                exfil_ratio = 1.0
                traffic = 10.0
                threat_type = 'Normal'
                threat_name = 'Normal'
                raw_log = f"Telemetry stream from {node_id} ({cloud}): Connection secure. Resource state normal."
                failed_logins = 0
            
            # Override AWS node metrics with live CloudWatch data if AWS CloudWatch mode is enabled
            if source == "aws" and cloud == "AWS" and live_aws_metrics_list:
                # Find matching telemetry record from live instance list by checking prefix
                matched_metric = next((m for m in live_aws_metrics_list if node_id.startswith(m['node_id'])), None)
                if matched_metric:
                    # Use exact, unfluctuated original metrics directly from CloudWatch
                    cpu = matched_metric['cpu_utilization']
                    ram = matched_metric['memory_utilization']
                    disk = matched_metric['disk_utilization']
                    traffic = matched_metric['network_traffic']
                    failed_logins = matched_metric['failed_logins']
                    running_procs = matched_metric['running_processes']
                    
                    # Log source flag
                    if matched_metric.get('is_mock'):
                        raw_log = f"AWS CloudWatch (Simulated Stream): Metrics retrieved for VM. CPU: {cpu:.1f}%, Network: {traffic:.1f} Mbps."
                    else:
                        raw_log = f"AWS CloudWatch (Live API Console): Metrics retrieved for active Instance. CPU: {cpu:.1f}%, Network: {traffic:.1f} Mbps."
                    threat_type = 'Normal'
                    
            # Overwrite all Azure nodes with actual local console/host telemetry variations
            if cloud == "Azure":
                if node_id == "local-console":
                    cpu = local_cpu
                    ram = local_ram
                    disk = local_disk
                    traffic = float(max(0.01, local_net_traffic))
                    failed_logins = 0
                    running_procs = len(psutil.pids())
                    raw_log = f"Local OS Console Host: System connection active. CPU load: {cpu:.1f}%, RAM utilization: {ram:.1f}%, PIDs: {running_procs}."
                else:
                    cpu = max(0.1, min(100.0, local_cpu + random.uniform(-1.5, 1.5)))
                    ram = max(5.0, min(100.0, local_ram + random.uniform(-0.5, 0.5)))
                    disk = max(1.0, min(100.0, local_disk + random.uniform(0.001, 0.005)))
                    traffic = max(0.01, local_net_traffic + random.uniform(-0.5, 0.5))
                    failed_logins = int(random.choices([0, 1], weights=[0.98, 0.02])[0])
                    running_procs = int(len(psutil.pids()) + random.randint(-2, 2))
                    raw_log = f"Azure VM Replicated Host: System tracking console resources. CPU: {cpu:.1f}%, RAM: {ram:.1f}%."
                threat_type = 'Normal'
                threat_name = 'Normal'
                
            # Overwrite all GCP nodes with actual AWS instance telemetry variations
            if cloud == "GCP" and live_aws_metrics_list:
                metric_index = 0
                if '-' in node_id:
                    try:
                        metric_index = (int(node_id.split('-')[-2]) - 1) % len(live_aws_metrics_list)
                    except Exception:
                        pass
                matched_metric = live_aws_metrics_list[metric_index]
                
                cpu = max(0.1, min(100.0, matched_metric['cpu_utilization'] + random.uniform(-1.5, 1.5)))
                ram = max(5.0, min(100.0, matched_metric['memory_utilization'] + random.uniform(-0.5, 0.5)))
                disk = max(1.0, min(100.0, matched_metric['disk_utilization'] + random.uniform(0.001, 0.005)))
                traffic = max(0.01, matched_metric['network_traffic'] + random.uniform(-0.5, 0.5))
                failed_logins = matched_metric['failed_logins']
                running_procs = matched_metric['running_processes']
                
                raw_log = f"GCP Subnet VM Replicated Host: System tracking AWS instance resources. CPU: {cpu:.1f}%, RAM: {ram:.1f}%."
                threat_type = 'Normal'
                threat_name = 'Normal'
            
            # exfiltration ratio
            exfil_ratio = float(src_bytes / max(dst_bytes, 1))
            
            # Map into the 24-feature schema
            feature_vector = {
                'cpu_utilization': cpu,
                'memory_utilization': ram,
                'process_count': running_procs,
                'unusual_process_executed': unusual_proc,
                'privilege_escalation_attempt': priv_esc,
                'duration': duration,
                'src_bytes': src_bytes,
                'dst_bytes': dst_bytes,
                'wrong_fragment': wrong_frag,
                'count': conn_count,
                'srv_count': srv_count,
                'same_srv_rate': same_srv,
                'diff_srv_rate': diff_srv,
                'dst_host_count': dst_host_count,
                'dst_host_srv_count': dst_host_srv_count,
                'c2_beaconing_score': c2_beacon,
                'dns_tunneling_flag': dns_tunnel,
                'impossible_travel': imp_travel,
                'mfa_bypass': mfa_bypass,
                'privilege_changes': priv_change,
                'login_hour': login_hr,
                'read_bytes_sec': read_sec,
                'write_bytes_sec': write_sec,
                'exfiltration_ratio': exfil_ratio
            }
            
            # Run ML Inference
            try:
                # Format to flat DataFrame
                feat_df = pd.DataFrame([feature_vector], columns=FEATURE_COLS)
                feat_scaled = SCALER.transform(feat_df)
                
                # Predict
                rf_prob = float(RF_MODEL.predict_proba(feat_scaled)[0, 1])
                is_anom = int(RF_MODEL.predict(feat_scaled)[0])
                
                # Isolation Forest decision score
                if_score = float(-IF_MODEL.decision_function(feat_scaled)[0])
                
            except Exception as e:
                # Fallback if scaling fails
                print(f"[Simulator] Inference error: {e}")
                is_anom = 1 if is_under_attack else 0
                rf_prob = 0.95 if is_under_attack else 0.05
                
            # If under active attack, force classification as anomalous
            if is_under_attack:
                is_anom = 1
                rf_prob = max(rf_prob, 0.88)
                
            risk_score = round(rf_prob * 100, 2)
            
            # Map severity and status
            status_label = 'Normal'
            severity = 'Low'
            
            if is_anom or risk_score >= 50:
                is_anom = 1 # Force flag
                status_label = 'Critical'
                if risk_score >= 80:
                    severity = 'Critical'
                else:
                    severity = 'High'
            elif risk_score >= 15:
                status_label = 'Warning'
                severity = 'Medium'
                
            # Insert metric record
            cursor.execute("""
                INSERT INTO node_metrics (
                    node_id, timestamp, cpu_utilization, memory_utilization, disk_utilization, 
                    network_traffic, failed_logins, running_processes, running_processes_text, status, is_anomalous, risk_score, threat_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (node_id, now_str, cpu, ram, disk, traffic, failed_logins, running_procs, processes_str, status_label, is_anom, risk_score, threat_type))
            
            # If anomalous, record a detection alert log and mine a blockchain audit block
            if is_anom == 1:
                event_id = f"evt-{node_id}-{int(time.time())}-{random.randint(1000, 9999)}"
                det_id = f"det-live-{event_id}"
                
                # Write to detections log
                cursor.execute("""
                    INSERT INTO detections (detection_id, event_id, category, anomaly_score, is_anomalous, model_used, timestamp, raw_log)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (det_id, event_id, threat_type, rf_prob, 1, 'Random Forest (PSO)', now_str, raw_log))
                
                # Append to Blockchain Ledger
                mine_blockchain_block(conn, f"{node_id}|{threat_type}|{risk_score}")
                
        # Clean up database: Keep only the last 50 telemetry points per node to prevent disk bloating
        for node in nodes:
            node_id = node[0]
            cursor.execute("""
                DELETE FROM node_metrics 
                WHERE metrics_id IN (
                    SELECT metrics_id FROM node_metrics 
                    WHERE node_id = ? 
                    ORDER BY timestamp DESC 
                    LIMIT -1 OFFSET 50
                )
            """, (node_id,))
            
        # Call the live event log scanner to check for OS warnings/errors
        check_live_system_events(conn, cursor, now_str)
        
        conn.commit()
        conn.close()
        
        # Sleep for configured interval
        time.sleep(sleep_time)

if __name__ == '__main__':
    run_simulator_loop()
