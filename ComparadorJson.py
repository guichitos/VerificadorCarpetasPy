import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Any, Dict, List, Tuple


JsonNode = Dict[str, Any]


def _collect_nodes(node: JsonNode, base_path: str = "") -> List[Tuple[str, str, str | None]]:
    """Return a flat list of (path, type, graph_path) tuples for each node."""

    current_path = os.path.join(base_path, node.get("name", "")) if base_path else node.get("name", "")
    node_type = node.get("type", "")
    graph_path = node.get("graph_path")

    nodes = [(current_path, node_type, graph_path)]
    if node_type == "folder":
        for child in node.get("children", []):
            nodes.extend(_collect_nodes(child, current_path))
    return nodes


def _load_json(path: str) -> JsonNode:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data.get("structure", data)


def _compare_structures(old_structure: JsonNode, new_structure: JsonNode) -> dict:
    old_nodes = _collect_nodes(old_structure)
    new_nodes = _collect_nodes(new_structure)

    old_by_graph = {graph: (path, ntype) for path, ntype, graph in old_nodes if graph}
    new_by_graph = {graph: (path, ntype) for path, ntype, graph in new_nodes if graph}

    renames = []
    for graph_path, (old_path, ntype) in old_by_graph.items():
        new_entry = new_by_graph.get(graph_path)
        if new_entry and new_entry[0] != old_path:
            renames.append((old_path, new_entry[0], ntype))

    old_paths = {(path, ntype) for path, ntype, _ in old_nodes}
    new_paths = {(path, ntype) for path, ntype, _ in new_nodes}

    removed = sorted(old_paths - new_paths)
    added = sorted(new_paths - old_paths)

    return {
        "added": added,
        "removed": removed,
        "renamed": renames,
    }


def _format_results(results: dict) -> str:
    messages: list[str] = []

    if results["renamed"]:
        messages.append("Archivos/carpetas renombrados:")
        for old, new, ntype in results["renamed"]:
            messages.append(f"  [{ntype}] {old} -> {new}")

    if results["added"]:
        messages.append("Nuevos archivos/carpetas:")
        for path, ntype in results["added"]:
            messages.append(f"  [{ntype}] {path}")

    if results["removed"]:
        messages.append("Eliminados o no encontrados:")
        for path, ntype in results["removed"]:
            messages.append(f"  [{ntype}] {path}")

    if not messages:
        return "No se encontraron diferencias."

    return "\n".join(messages)


def _select_file(prompt: str) -> str | None:
    return filedialog.askopenfilename(title=prompt, filetypes=[("JSON files", "*.json")])


def compare_json_files() -> None:
    old_file = _select_file("Selecciona el JSON original")
    if not old_file:
        return

    new_file = _select_file("Selecciona el JSON actualizado")
    if not new_file:
        return

    try:
        old_structure = _load_json(old_file)
        new_structure = _load_json(new_file)
    except (OSError, json.JSONDecodeError) as error:
        messagebox.showerror("Error", f"No se pudieron leer los archivos: {error}")
        return

    results = _compare_structures(old_structure, new_structure)
    message = _format_results(results)
    messagebox.showinfo("Resultado de la comparación", message)


def main() -> None:
    root = tk.Tk()
    root.title("Comparador de estructuras JSON")
    root.geometry("420x200")
    root.resizable(False, False)

    label = tk.Label(
        root,
        text=(
            "Selecciona dos archivos JSON (anterior y actualizado) "
            "para detectar renombres y nuevos elementos."
        ),
        wraplength=380,
        justify="center",
        padx=20,
        pady=20,
    )
    label.pack()

    compare_button = tk.Button(
        root, text="Comparar JSON", command=compare_json_files, width=25
    )
    compare_button.pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    main()
