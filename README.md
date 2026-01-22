# virus-Total

# Malware Types & Behavior Analysis (Basic)

## Objective
The objective of this task is to understand different types of malware, analyze their behavior using VirusTotal sandbox reports, and document detection results, behavior indicators, and prevention techniques.

---

## Tool Used
- **VirusTotal** (Web-based malware analysis platform)

---

## Malware Sample Analyzed

### Sample Name
**eicar.com-24082**

### Hash
- **SHA-256:** 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

### File Size
- 68 Bytes

### Distributor
- File distributed by **Offensive Security**

---

## Detection Summary
- **Detection Ratio:** 65 / 67 security vendors
- **Classification:** Malware / Trojan
- **Community Score:** High (widely recognized malicious test sample)

This confirms that the file is detected as malicious by the majority of antivirus engines.

---

## Behavioral Analysis (Sandbox Results)

### Sandbox Detections
Multiple sandboxes flagged the file as malicious:
- Zenbox: Malware Trojan
- Lastline: Malware Trojan
- OS X Sandbox: Malware Trojan Evader

### Observed Behavior Tags
- Detects debug/sandbox environment
- Direct CPU clock access
- Long sleep execution
- Sets process name
- Idle behavior to evade analysis

These behaviors indicate **sandbox evasion techniques**, commonly used by trojans to avoid detection during dynamic analysis.

---

## MITRE ATT&CK Observations
- Low-severity indicators mapped to reconnaissance and evasion-related techniques
- Demonstrates how malware attempts to identify virtualized or sandboxed environments

---

## Malware Lifecycle (Conceptual)
1. **Delivery:** Email attachment or downloaded file
2. **Execution:** Triggered in sandbox environment
3. **Evasion:** Uses timing checks and environment detection
4. **Payload:** Test malware (no real destructive payload)
5. **Impact:** Used for validating malware detection systems

---

## Malware Type Explanation
This sample is based on the **EICAR test malware**, which is intentionally designed to safely test antivirus detection capabilities without causing real harm. Although non-destructive, it is treated as malware by security engines due to its known malicious signature.

---

## Prevention Techniques
- Use updated antivirus and endpoint protection
- Monitor sandbox evasion behavior
- Block suspicious email attachments
- Implement network and host-based intrusion detection systems
- Educate users about phishing and malicious downloads

---

## Conclusion
This task provided hands-on experience in analyzing malware behavior using VirusTotal. The analysis demonstrates how malware is detected through signature-based methods and sandbox behavior analysis, along with how evasion techniques are identified even in test malware samples.

---

## Outcome
- Improved understanding of malware types
- Learned to analyze VirusTotal detection and behavior reports
- Gained awareness of malware evasion and prevention techniques
