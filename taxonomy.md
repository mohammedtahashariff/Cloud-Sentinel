# Taxonomy: Anomaly Categories & Feature Definitions

This taxonomy document defines the feature groups used by the Multi-Cloud Node Anomaly Detection System to detect node-level threats.

---

## 1. Behavioral Features
Behavioral features capture host-level metrics, process activity, and OS-level operations.

*   **`cpu_utilization`** *(float, 0.0 - 100.0)*: The average CPU utilization percentage over the sample window. Spikes may indicate unauthorized tasks (e.g., cryptomining or heavy exploit compiles).
*   **`memory_utilization`** *(float, 0.0 - 100.0)*: The average memory usage percentage. Anomalous spikes might suggest buffer allocations, in-memory payloads, or database dumps.
*   **`process_count`** *(integer)*: Total number of active processes running on the node. A sudden increase can suggest process spawning cascades by exploits or automated scripts.
*   **`unusual_process_executed`** *(binary, 0 or 1)*: Flag set to `1` if a binary not in the standard baseline whitelist is executed (e.g., netcat, nmap, unknown compiled binaries).
*   **`privilege_escalation_attempt`** *(binary, 0 or 1)*: Flag set to `1` when suspicious privilege transitions are detected (e.g., multiple failed sudo attempts, direct access to shadow files, or credential dumps).

---

## 2. Network Features
Network features track network flow statistics (inspired by NSL-KDD and CICIDS2017/2018 datasets) representing VPC (AWS) or VNet (Azure) activities.

*   **`duration`** *(float)*: The duration of the connection session in seconds.
*   **`src_bytes`** *(integer)*: Bytes sent from the source node to the destination.
*   **`dst_bytes`** *(integer)*: Bytes received by the source node from the destination.
*   **`wrong_fragment`** *(integer)*: Number of malformed or wrong packet fragments. High values indicate OS fingerprinting or network-level attacks.
*   **`count`** *(integer)*: Number of connections to the same destination IP as the current connection in the past two seconds. High rates can suggest network scanning.
*   **`srv_count`** *(integer)*: Number of connections to the same port/service as the current connection in the past two seconds.
*   **`same_srv_rate`** *(float, 0.0 - 1.0)*: Percentage of connections to the same service.
*   **`diff_srv_rate`** *(float, 0.0 - 1.0)*: Percentage of connections to different services, indicating port sweeps.
*   **`dst_host_count`** *(integer)*: Total connections to the destination host.
*   **`dst_host_srv_count`** *(integer)*: Total connections to the destination host service.
*   **`c2_beaconing_score`** *(float, 0.0 - 1.0)*: A score indicating the predictability and regularity of connection intervals to an external IP, suggesting botnet Command & Control beaconing.
*   **`dns_tunneling_flag`** *(binary, 0 or 1)*: Flag set to `1` if outbound DNS requests have abnormally high entropy, indicating data leakage or C2 tunneling over DNS.

---

## 3. Identity/Access Features
Identity features monitor authentication patterns, role assignments, and cloud API access (AWS IAM / Azure AD).

*   **`impossible_travel`** *(binary, 0 or 1)*: Flag set to `1` if logins occur from different geographic locations within an impossible travel time window (e.g., London and Tokyo within 30 minutes).
*   **`mfa_bypass`** *(binary, 0 or 1)*: Flag set to `1` if logins bypass Multi-Factor Authentication or show patterns of MFA exhaustion/fatigue.
*   **`privilege_changes`** *(binary, 0 or 1)*: Flag set to `1` if there are modifications to the node's associated IAM policies, roles, or Azure service principal permissions.
*   **`login_hour`** *(integer, 0 - 23)*: The hour of the day when the identity action occurred. Off-hours logins (e.g., 2:00 AM local time) are scrutinized.

---

## 4. Data Features
Data features capture storage access volumes and data movement characteristics.

*   **`read_bytes_sec`** *(float)*: Data volume read from storage or cloud buckets per second.
*   **`write_bytes_sec`** *(float)*: Data volume written to storage per second.
*   **`exfiltration_ratio`** *(float)*: The ratio of outgoing network bytes to incoming network bytes (`src_bytes / dst_bytes`). High ratios combined with volume indicate bulk data exfiltration.
