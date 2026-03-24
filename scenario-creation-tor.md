# Scenario: Shadow IT – Unauthorized TOR Usage

## Overview
This scenario simulates a case of Shadow IT where a user installs and uses the TOR browser on a corporate-managed device without authorization.

While Shadow IT is typically considered a policy violation, the use of anonymization tools like TOR introduces additional security concerns such as evasion of monitoring, untracked network activity, and potential misuse.

The purpose of this scenario is to generate realistic telemetry that can later be used for threat hunting and detection.

---

## Objective
- Simulate unauthorized software installation (TOR browser)
- Generate endpoint and network logs related to TOR usage
- Create artifacts that resemble suspicious user behavior
- Provide a foundation for a structured threat hunting investigation

---

## Lab Setup and Actions Performed

The following steps were performed in a controlled lab environment to generate logs and indicators:

1. Downloaded the TOR browser installer from:
   https://www.torproject.org/download/

2. Executed the installer silently:
   ```
   tor-browser-windows-x86_64-portable-15.0.7.exe /S
   ```

3. Launched the TOR browser from the local directory

4. Established TOR connections and browsed various sites  
   (Note: Onion links change frequently. General browsing is sufficient to generate logs.)

5. Created a file on the desktop:
   ```
   tor-shopping-list.txt
   ```
   Added sample content to simulate user intent

6. Deleted the file to generate additional file activity logs

---

## Expected Telemetry

The following types of logs are expected to be generated from this activity:

### File Activity
- TOR installer download
- Presence of TOR-related binaries (`tor.exe`, `firefox.exe`)
- Creation and deletion of user files

### Process Activity
- Execution of the TOR installer
- Silent installation behavior
- Launch of TOR browser processes

### Network Activity
- Outbound connections initiated by TOR processes
- Traffic over commonly used TOR ports (e.g., 9001, 9030, 9050)

---

## Data Sources

The scenario is designed to be analyzed using the following Microsoft Defender for Endpoint tables:

- `DeviceFileEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`

---

## Notes
- This scenario was created in a controlled lab environment
- The activity is intended for defensive security learning purposes only
- No real malicious actions were performed

---

## Author

- **Name**: Nikhil Pawar  
- **Contact**: https://www.linkedin.com/in/nikhil-pawar-535710178/  

---

## Revision History

| Version | Changes       | Date | Modified By   |
|--------|--------------|------|---------------|
| 1.0    | Initial draft | 2026 | Nikhil Pawar  |
