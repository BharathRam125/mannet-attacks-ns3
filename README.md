# 🛰️ MANET Attacks and Defence in NS-3

**Comprehensive NS-3 Simulation Framework for MANET Security Research**
---

## 🚀 Overview

This project provides an in-depth demonstration and analysis of **routing-layer attacks** in Mobile Ad Hoc Networks (MANETs), focusing on **RREQ Flooding** and **Sybil Identity** attacks, along with the implementation of robust and lightweight **defence mechanisms** in the **NS-3 simulator**.

**Key features:**
- Performance analytics (PDR, packet drops, throughput)
- Wireshark-verified packet trace export
- NetAnim visualization for network topology and mobility
- Scalable, node-level simulation for research and teaching

---

## ⚙️ Attack Mechanisms

### 🔸 RREQ Flooding Attack
- **Concept:**  
  Attacker overwhelms the routing process by broadcasting fake Route Request (RREQ) packets in AODV.
- **Implementation:**  
  - Malicious node sends ≈480 RREQs/sec.
  - Transmits in bursts (3–5 packets) at millisecond intervals.
  - Uses spoofed destinations, poisoning legitimate routing tables.
- **Impact:**  
  - Drains node CPU and network bandwidth.  
  - Causes route table overflow and overall congestion.  
  - Packet Delivery Ratio (PDR) plummets to ~0.7%.

### 🔸 Sybil Identity Attack
- **Concept:**  
  A single adversary node masquerades as multiple IPs (10.0.0.200–205) to impersonate several distinct network participants.
- **Implementation:**  
  - Sends cyclic bursts using faked source identities.
  - Mimics the behavior of multiple simultaneous attackers.
- **Impact:**  
  - Induces routing confusion and excess control traffic.  
  - Results in congestion and starkly reduced packet delivery (~29% PDR).

---

## 🛡️ Defence Mechanisms

### 🔹 RREQ Flooding Defence
- **Rate Limiting:** Each node restricted to no more than 3 RREQs/sec.  
- **Reputation Management:** Detects repeated violations, isolating offenders.  
- **Packet Filtering:** Real-time RREQ validation via IPv4 reception hooks.  
- **Outcome:** Over 90% of malicious RREQs are blocked; PDR improves from 0.71% to 76.43%.

### 🔹 Sybil Defence
- **Burst Detection:** Flags nodes sending ≥4 packets within a 5-second window.  
- **Anomaly Detection:** Spots abnormal, rapid, or spoofed traffic patterns.  
- **Violation Counting:** Blacklists nodes with frequent violations.  
- **Outcome:** Drops 1,479 spoofed packets—100% of legitimate packets are delivered (PDR).

---

## 📊 Summary of Results

| Scenario              | PDR (%) | Packets Sent | Packets Blocked | Network Status |
|-----------------------|---------|--------------|-----------------|----------------|
| **Flooding Attack**   | 0.71    | 14,397       | --              | Unstable       |
| **Flooding Defence**  | 76.43   | 14,397       | 1,909           | Stable         |
| **Sybil Attack**      | 29.73   | 147          | --              | Congested      |
| **Sybil Defence**     | 100.00  | 27,000       | 1,479           | Stable         |

**Observations:**
- Flooding Defence restores network connectivity, reducing routing load and congestion.
- Sybil Defence maintains a 100% PDR by actively filtering spoofed packets.
- Both defence strategies isolate and neutralize attacks, incurring minimal computational overhead.

---

## 🧪 Simulation Results

### Flooding Attack
![Flooding Attack](results/images/flooding-attack-result.png)

### Flooding Defence
![Flooding Defence](results/images/flooding-attack-defence.png)

### Sybil Attack
![Sybil Attack](results/images/sybil-attack-result.png)

### Sybil Defence
![Sybil Defence](results/images/sybil-defence-result.png)

---
