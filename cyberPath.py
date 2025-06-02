# MIT License
#
# Copyright (c) 2024 Chris
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import subprocess
import markdown
from typing import List, Dict, Any, Tuple
import yaml
import sys

# --- Config ---
PLANTUML_JAR_PATH = "plantuml.jar"  # Path to your PlantUML jar
OUTPUT_DIR = "output"
REPORT_MD = os.path.join(OUTPUT_DIR, "pentest_report.md")

# --- Helper Functions ---

def load_attack_paths(yaml_file: str) -> List[Dict[str, Any]]:
    """Load attack paths from a YAML file."""
    with open(yaml_file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data["attack_paths"]

def evaluate_paths(attack_paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Score each attack path and all nested subpaths recursively."""
    def eval_path(path):
        severity = path.get("severity", 1)
        feasibility = path.get("feasibility", 1)
        expertise = path.get("expertise", 1)
        path["score"] = 0.5 * severity + 0.3 * feasibility + 0.2 * expertise
        for sub in path.get("subpaths", []):
            eval_path(sub)
    for path in attack_paths:
        eval_path(path)
    return attack_paths

def score_to_color(score: float) -> str:
    """
    Returns a PlantUML color code based on the score.
    Green: <=2.0, Yellow: >2.0 and <4.0, Red: >=4.0
    """
    if score < 2.0:
        return "#27ae60"  # green
    elif score < 4.0:
        return "#f1c40f"  # yellow
    else:
        return "#e74c3c"  # red

def generate_plantuml(attack_paths: List[Dict[str, Any]]) -> str:
    """
    Generate PlantUML code for the attack paths and all nested subpaths,
    visualized as an attack tree (tree structure, not nested packages),
    with node color based on score.
    """
    uml = [
        "@startuml",
        "skinparam monochrome true",
        "skinparam linetype ortho",
        "left to right direction"
    ]

    node_defs = []
    node_ids = set()

    def safe_node_id(name):
        # Ensure unique and PlantUML-safe node IDs
        return "node_" + str(abs(hash(name)))[:10]

    def add_tree_edges(path, parent=None):
        node_id = safe_node_id(path["name"])
        # Avoid duplicate node definitions
        if node_id not in node_ids:
            label = f'{path["name"]}\\nScore: {path.get("score", 0):.2f}'
            color = score_to_color(path.get("score", 0))
            node_defs.append(f'{node_id} [{label}] #{color}')
            node_ids.add(node_id)
        if parent:
            uml.append(f'{parent} --> {node_id}')
        for sub in path.get("subpaths", []):
            add_tree_edges(sub, node_id)

    for path in attack_paths:
        add_tree_edges(path)

    uml = uml[:4] + node_defs + uml[4:]  # Insert node definitions after direction
    uml.append("@enduml")
    return "\n".join(uml)

def save_plantuml(uml_code: str, filename: str):
    """Save PlantUML code to a file."""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(uml_code)

def render_plantuml(uml_file: str, output_dir: str):
    """Render PlantUML file to PNG using plantuml.jar."""
    jar_path = os.path.abspath(PLANTUML_JAR_PATH)
    if not os.path.isfile(jar_path):
        raise FileNotFoundError(f"PlantUML jar not found at: {jar_path}")
    subprocess.run([
        "java", "-jar", jar_path, "-tpng", os.path.basename(uml_file), "-o", ".",
    ], cwd=output_dir, check=True)

def generate_table(attack_paths: List[Dict[str, Any]]) -> str:
    """Generate a Markdown table with the attack path and all nested subpath scores."""
    header = "| Path / Subpath | Severity | Feasibility | Expertise | Score |\n|---|---|---|---|---|"
    rows = []
    def add_rows(path, prefix=""):
        rows.append(
            f'| {prefix}{path["name"]} | {path.get("severity", "")} | {path.get("feasibility", "")} | {path.get("expertise", "")} | {path.get("score", ""):.2f} |'
        )
        for sub in path.get("subpaths", []):
            add_rows(sub, prefix + "└─ ")
    for path in attack_paths:
        add_rows(path)
    return header + "\n" + "\n".join(rows)

def collect_full_paths(attack_paths: List[Dict[str, Any]]) -> List[Tuple[List[str], List[float]]]:
    """
    Recursively collect all full attack chains (from root to leaf subpath).
    Returns a list of tuples: (list of path names, list of scores)
    """
    result = []
    def walk(path, names, scores):
        names = names + [path["name"]]
        scores = scores + [path["score"]]
        if "subpaths" in path and path["subpaths"]:
            for sub in path["subpaths"]:
                walk(sub, names, scores)
        else:
            result.append((names, scores))
    for path in attack_paths:
        walk(path, [], [])
    return result

def generate_fullpath_table(attack_paths: List[Dict[str, Any]]) -> str:
    """Generate a sorted Markdown table comparing all full attack chains."""
    full_paths = collect_full_paths(attack_paths)
    # Calculate cumulative score for each full path (average of all scores in the chain)
    path_scores = []
    for names, scores in full_paths:
        cumulative = sum(scores) / len(scores)
        path_scores.append( (names, scores, cumulative) )
    # Sort by cumulative score descending
    path_scores.sort(key=lambda x: x[2], reverse=True)
    header = "| Full Attack Chain | Cumulative Score |\n|---|---|"
    rows = []
    for names, scores, cumulative in path_scores:
        chain = " → ".join(names)
        rows.append(f"| {chain} | {cumulative:.2f} |")
    return header + "\n" + "\n".join(rows)

def generate_markdown_report(image_path: str, table_md: str, fullpath_table_md: str) -> str:
    """Generate the final Markdown report."""
    return f"""# Pentest Attack Paths Report

## Attack Path Diagram

![Attack Paths]({image_path})

## Scoring Table

{table_md}

## Full Attack Chain Comparison

{fullpath_table_md}
"""

# --- Main Functionality ---

def main(description_file: str):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    attack_paths = load_attack_paths(description_file)
    attack_paths = evaluate_paths(attack_paths)
    uml_code = generate_plantuml(attack_paths)
    uml_file = os.path.join(OUTPUT_DIR, "attack_paths.puml")
    save_plantuml(uml_code, uml_file)
    render_plantuml(uml_file, OUTPUT_DIR)
    image_file = "attack_paths.png"
    table_md = generate_table(attack_paths)
    fullpath_table_md = generate_fullpath_table(attack_paths)
    report_md = generate_markdown_report(image_file, table_md, fullpath_table_md)
    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write(report_md)
    print(f"Report generated: {REPORT_MD}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python cyberPath.py <description.yaml>")
    else:
        main(sys.argv[1])
