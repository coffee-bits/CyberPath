# MIT License
#
# Copyright (c) 2025 Christian Jess
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

def safe_node_id(name):
    """
    Ensure unique and PlantUML-safe node IDs (letters, digits, underscores only, must not start with a digit).
    """
    import re
    node_id = "node_" + re.sub(r'\W+', '_', name)
    node_id = node_id.rstrip('_')
    if len(node_id) <= 5:
        node_id += "x"
    if node_id[5].isdigit():
        node_id = "node_n" + node_id[5:]
    return node_id

def get_fullpath_scores(attack_paths: List[Dict[str, Any]]) -> Tuple[float, float, List[Tuple[list, float]]]:
    """
    Returns (min_score, max_score, list of (node_id_path, cumulative_score)) for all full attack chains.
    """
    full_paths = []
    def walk(path, ids, scores):
        node_id = safe_node_id(path["name"])
        ids = ids + [node_id]
        scores = scores + [path["score"]]
        if "subpaths" in path and path["subpaths"]:
            for sub in path["subpaths"]:
                walk(sub, ids, scores)
        else:
            cumulative = sum(scores) / len(scores)
            full_paths.append((ids, cumulative))
    for path in attack_paths:
        walk(path, [], [])
    if not full_paths:
        return 0, 0, []
    min_score = min(c for _, c in full_paths)
    max_score = max(c for _, c in full_paths)
    return min_score, max_score, full_paths

def score_to_edge_color(score: float, min_score: float, max_score: float) -> str:
    """
    Map a score to a color gradient from green (low) to yellow (mid) to red (high).
    """
    # Normalize score between 0 (min) and 1 (max)
    if max_score == min_score:
        t = 0.0
    else:
        t = (score - min_score) / (max_score - min_score)
    # Green to yellow to red gradient
    if t <= 0.5:
        # Green (#27ae60) to Yellow (#f1c40f)
        ratio = t / 0.5
        r = int(0x27 + ratio * (0xf1 - 0x27))
        g = int(0xae + ratio * (0xc4 - 0xae))
        b = int(0x60 + ratio * (0x0f - 0x60))
    else:
        # Yellow (#f1c40f) to Red (#e74c3c)
        ratio = (t - 0.5) / 0.5
        r = int(0xf1 + ratio * (0xe7 - 0xf1))
        g = int(0xc4 - ratio * (0xc4 - 0x4c))
        b = int(0x0f + ratio * (0x3c - 0x0f))
    return f"#{r:02x}{g:02x}{b:02x}"

def generate_plantuml(attack_paths: List[Dict[str, Any]]) -> str:
    """
    Generate PlantUML code for the attack paths and all nested subpaths,
    visualized as an attack tree (tree structure, not nested packages),
    with node color based on score and edge color based on fullpath cumulative score.
    """
    uml = [
        "@startuml",
        "skinparam linetype ortho",
        "top to bottom direction"  # Change direction: top-down instead of left-right
    ]

    node_defs = []
    node_ids = set()
    edge_defs = []

    # Get all full paths and their cumulative scores for edge coloring
    min_score, max_score, full_paths = get_fullpath_scores(attack_paths)
    # Build a lookup for each edge (parent, child) to the cumulative score of the full path it belongs to
    edge_score_map = {}
    for ids, cumulative in full_paths:
        for i in range(1, len(ids)):
            edge = (ids[i-1], ids[i])
            # If edge is part of multiple paths, keep the highest score (most critical)
            if edge not in edge_score_map or cumulative > edge_score_map[edge]:
                edge_score_map[edge] = cumulative

    def add_tree_edges(path, parent=None):
        node_id = safe_node_id(path["name"])
        if node_id not in node_ids:
            technique = path.get("technique", "")
            label = f'{path["name"]}'
            if technique:
                label += f'\\n[{technique}]'
            label += f'\\nScore: {path.get("score", 0):.2f}'
            color = score_to_color(path.get("score", 0))
            node_defs.append(f'rectangle {node_id} as "{label}" {color}')
            node_ids.add(node_id)
        if parent:
            edge_color = ""
            edge = (parent, node_id)
            if edge in edge_score_map:
                # Fix: Only ONE # for color and NO space after -[
                edge_color = f"#{score_to_edge_color(edge_score_map[edge], min_score, max_score)[1:]}"
            edge_defs.append(f'{parent} -[{edge_color}]-> {node_id}')
        for sub in path.get("subpaths", []):
            add_tree_edges(sub, node_id)

    for path in attack_paths:
        add_tree_edges(path)

    uml += node_defs
    uml += edge_defs
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
    """Generate a Markdown table with the attack path, technique, and all nested subpath scores."""
    header = "| Path / Subpath | Technique | Severity | Feasibility | Expertise | Score |\n|---|---|---|---|---|---|"
    rows = []
    def add_rows(path, prefix=""):
        technique = path.get("technique", "")
        rows.append(
            f'| {prefix}{path["name"]} | {technique} | {path.get("severity", "")} | {path.get("feasibility", "")} | {path.get("expertise", "")} | {path.get("score", ""):.2f} |'
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

def generate_attack_tree_text(attack_paths: List[Dict[str, Any]]) -> str:
    """
    Generate a textual attack tree in the style of Bruce Schneier's format.
    Each node is indented, subpaths are shown as children, and AND/OR logic can be added if present.
    """
    def node_text(path, indent=0):
        prefix = "    " * indent + "- "
        logic = path.get("logic", "OR")  # default to OR if not specified
        technique = f" [{path['technique']}]" if 'technique' in path else ""
        score = f" (Score: {path.get('score', 0):.2f})"
        line = f"{prefix}{path['name']}{technique}{score}"
        lines = [line]
        if "subpaths" in path and path["subpaths"]:
            if len(path["subpaths"]) > 1:
                lines.append("    " * (indent + 1) + f"({logic})")
            for sub in path["subpaths"]:
                lines.extend(node_text(sub, indent + 1))
        return lines

    tree_lines = []
    for path in attack_paths:
        tree_lines.extend(node_text(path))
    return "\n".join(tree_lines)

def generate_markdown_report(image_path: str, table_md: str, fullpath_table_md: str, attack_tree_text: str) -> str:
    """Generate the final Markdown report."""
    return f"""# Pentest Attack Paths Report

## Attack Path Diagram

![Attack Paths]({image_path})

## Schneier-style Attack Tree

```
{attack_tree_text}
```

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
    attack_tree_text = generate_attack_tree_text(attack_paths)
    report_md = generate_markdown_report(image_file, table_md, fullpath_table_md, attack_tree_text)
    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write(report_md)
    print(f"Report generated: {REPORT_MD}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python cyberPath.py <description.yaml>")
    else:
        main(sys.argv[1])
