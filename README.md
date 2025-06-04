# CyberPath

Automated attack path visualization and assessment for penetration testing.

## Features

- YAML-based definition of attack trees with a **single point of origin** (root node)
- Recursive subpaths (branches) for complex attack scenarios
- Automatic visualization as PlantUML diagram (PNG)
- Scoring of paths and all nested subpaths by severity, feasibility, and required expertise
- Automatic generation of a Markdown report
- Comparison of all full attack chains with cumulative scores

## Requirements

- Python 3.x
- Java (for PlantUML)
- `plantuml.jar` in the project directory
- Python packages: `pyyaml`, `markdown`
- **On Arch Linux:**  
  You also need to install `graphviz` and `jre-openjdk-headless`:
  ```bash
  sudo pacman -S graphviz jre-openjdk-headless
  ```

Install required Python packages:
```bash
pip install pyyaml markdown
```

## Example: Attack Tree with a Single Point of Origin

Create a YAML file, e.g., `example_coffee_attack.yaml`:
```yaml
attack_paths:
  - name: "Compromise Organization"
    technique: "ROOT"
    severity: 4
    feasibility: 4
    expertise: 3
    # This is the single point of origin (root node)
    subpaths:
      - name: "Compromise Coffee Machine via WiFi"
        technique: "T1476"
        severity: 4
        feasibility: 4
        expertise: 3
        steps:
          - from: "Attacker"
            to: "Coffee Machine"
            action: "Exploit WiFi vulnerability"
          - from: "Coffee Machine"
            to: "Backend Server"
            action: "Send malicious request"
          - from: "Backend Server"
            to: "Coffee Bean Supplier"
            action: "Manipulate order data"
        subpaths:
          - name: "Lateral Movement to Office Network"
            technique: "T1021"
            severity: 5
            feasibility: 3
            expertise: 4
            steps:
              - from: "Coffee Machine"
                to: "Office Printer"
                action: "Pivot via open port"
              - from: "Office Printer"
                to: "Internal File Server"
                action: "Access sensitive files"
            subpaths:
              - name: "Escalate to Domain Controller"
                technique: "T1068"
                severity: 5
                feasibility: 2
                expertise: 5
                steps:
                  - from: "Internal File Server"
                    to: "Domain Controller"
                    action: "Exploit SMB vulnerability"
              - name: "Access HR Database"
                technique: "T1005"
                severity: 4
                feasibility: 3
                expertise: 3
                steps:
                  - from: "Internal File Server"
                    to: "HR Database"
                    action: "Steal employee data"
      - name: "Denial of Service on Coffee Machine"
        severity: 3
        feasibility: 5
        expertise: 2
        steps:
          - from: "Attacker"
            to: "Coffee Machine"
            action: "Flood with requests"
        subpaths:
          - name: "Disrupt Supply Chain"
            severity: 4
            feasibility: 3
            expertise: 3
            steps:
              - from: "Coffee Machine"
                to: "Backend Server"
                action: "Send malformed data"
              - from: "Backend Server"
                to: "Coffee Bean Supplier"
                action: "Interrupt orders"
            subpaths:
              - name: "Trigger Supplier System Crash"
                severity: 5
                feasibility: 2
                expertise: 4
                steps:
                  - from: "Coffee Bean Supplier"
                    to: "Supplier Database"
                    action: "Exploit buffer overflow"
```

**Note:**  
- The root node (`Compromise Organization`) is the single point of origin for all attack branches.
- All attack paths and subpaths branch from this root node, following the classic attack tree methodology.

## Usage

Run the script with your YAML file:
```bash
python cyberPath.py example_coffee_attack.yaml
```

### Running with the Example File

To generate a report for the attack tree scenario, use:
```bash
python cyberPath.py example_coffee_attack.yaml
```
This will create the following files in the `output` directory:
- `attack_paths.png` – Visualization of the attack tree
- `pentest_report.md` – Markdown report including the diagram, scoring table, Schneier-style tree, and full attack chain comparison

## Example Output

![Attack Paths](attack_paths.png)

### Scoring Table

| Path / Subpath                         | Technique | Severity | Feasibility | Expertise | Score |
|----------------------------------------|-----------|----------|-------------|-----------|-------|
| Compromise Organization                | ROOT      | 4        | 4           | 3         | 3.70  |
| └─ Compromise Coffee Machine via WiFi  | T1476     | 4        | 4           | 3         | 3.70  |
| └─ └─ Lateral Movement to Office Network | T1021   | 5        | 3           | 4         | 4.10  |
| └─ └─ └─ Escalate to Domain Controller | T1068     | 5        | 2           | 5         | 4.10  |
| └─ └─ └─ Access HR Database            | T1005     | 4        | 3           | 3         | 3.50  |
| └─ Denial of Service on Coffee Machine |           | 3        | 5           | 2         | 3.50  |
| └─ └─ Disrupt Supply Chain             |           | 4        | 3           | 3         | 3.50  |
| └─ └─ └─ Trigger Supplier System Crash |           | 5        | 2           | 4         | 4.10  |

### Full Attack Chain Comparison

| Full Attack Chain                                                                 | Cumulative Score |
|----------------------------------------------------------------------------------|------------------|
| Compromise Organization → Compromise Coffee Machine via WiFi → Lateral Movement to Office Network → Escalate to Domain Controller | 3.98             |
| Compromise Organization → Compromise Coffee Machine via WiFi → Lateral Movement to Office Network → Access HR Database            | 3.77             |
| Compromise Organization → Denial of Service on Coffee Machine → Disrupt Supply Chain → Trigger Supplier System Crash              | 3.70             |
| Compromise Organization → Compromise Coffee Machine via WiFi                                                                 | 3.70             |
| Compromise Organization → Denial of Service on Coffee Machine → Disrupt Supply Chain                                           | 3.50             |
| Compromise Organization → Denial of Service on Coffee Machine                                                                 | 3.50             |

### Schneier-style Attack Tree

```
- Compromise Organization [ROOT] (Score: 3.70)
    - Compromise Coffee Machine via WiFi [T1476] (Score: 3.70)
        - Lateral Movement to Office Network [T1021] (Score: 4.10)
            - Escalate to Domain Controller [T1068] (Score: 4.10)
            - Access HR Database [T1005] (Score: 3.50)
    - Denial of Service on Coffee Machine (Score: 3.50)
        - Disrupt Supply Chain (Score: 3.50)
            - Trigger Supplier System Crash (Score: 4.10)
```
