import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Tuple

from GeneradorArbol import BuildJson


JsonNode = Dict[str, Any]


def _compose_path(base_path: str, name: str) -> str:
    parts = [segment for segment in (base_path, name) if segment]
    return "/".join(parts).replace("\\", "/")


def _collect_nodes(node: JsonNode, base_path: str = "") -> List[Tuple[str, str, str | None]]:
    """Return a flat list of (path, type, graph_path) tuples for each node."""

    current_path = _compose_path(base_path, node.get("name", ""))
    node_type = node.get("type", "")
    graph_path = node.get("graph_path")

    nodes = [(current_path, node_type, graph_path)]
    if node_type == "folder":
        for child in node.get("children", []):
            nodes.extend(_collect_nodes(child, current_path))
    return nodes


def _load_json(path: str) -> tuple[JsonNode, str | None, str | None]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    structure = data.get("structure", data)
    computer = data.get("computer") if isinstance(data, dict) else None
    selected_path = data.get("selected_path") if isinstance(data, dict) else None
    return structure, computer, selected_path


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

    rename_old_paths = {old for old, _, _ in renames}
    rename_new_paths = {new for _, new, _ in renames}

    removed = [entry for entry in removed if entry[0] not in rename_old_paths]
    added = [entry for entry in added if entry[0] not in rename_new_paths]

    return {
        "added": added,
        "removed": removed,
        "renamed": renames,
        "old_nodes": old_nodes,
        "new_nodes": new_nodes,
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


def _status_to_tag(status: str) -> str:
    if status.startswith("Nuevo"):
        return "nuevo"
    if status.startswith("Eliminado"):
        return "eliminado"
    if status.startswith("Renombrado"):
        return "renombrado"
    return "normal"


def _build_status_maps(results: dict) -> tuple[dict[str, str], dict[str, str]]:
    old_index = {path: (ntype, graph) for path, ntype, graph in results["old_nodes"]}
    new_index = {path: (ntype, graph) for path, ntype, graph in results["new_nodes"]}

    removed_paths = {path for path, _ in results["removed"]}
    added_paths = {path for path, _ in results["added"]}

    rename_old_to_new = {old: new for old, new, _ in results["renamed"]}
    rename_new_to_old = {new: old for old, new, _ in results["renamed"]}

    old_status: dict[str, str] = {}
    new_status: dict[str, str] = {}

    for path in old_index:
        if path in rename_old_to_new:
            old_status[path] = f"Renombrado a {rename_old_to_new[path]}"
        elif path in removed_paths:
            old_status[path] = "Eliminado"
        else:
            old_status[path] = "Sin cambios"

    for path in new_index:
        if path in rename_new_to_old:
            new_status[path] = f"Renombrado desde {rename_new_to_old[path]}"
        elif path in added_paths:
            new_status[path] = "Nuevo"
        else:
            new_status[path] = "Sin cambios"

    return old_status, new_status


def _filter_structure_for_changes(
    node: JsonNode, status_map: dict[str, str], base_path: str = ""
) -> JsonNode | None:
    """Return a pared-down copy of the tree keeping only nodes with changes.

    Ancestors of changed nodes are kept to preserve the folder context.
    """

    current_path = _compose_path(base_path, node.get("name", ""))
    status = status_map.get(current_path, "Sin cambios")

    children: list[JsonNode] = []
    if node.get("type") == "folder":
        for child in node.get("children", []):
            filtered_child = _filter_structure_for_changes(child, status_map, current_path)
            if filtered_child:
                children.append(filtered_child)

    has_change = status != "Sin cambios"
    if not has_change and not children:
        return None

    filtered_node: JsonNode = {"name": node.get("name", ""), "type": node.get("type", "")}
    if children:
        filtered_node["children"] = children

    return filtered_node


def _filter_structure_by_paths(
    node: JsonNode | None,
    allowed_top_folders: set[str],
    base_path: str = "",
    root_path: str | None = None,
) -> JsonNode | None:
    """Return a copy of the tree filtering only top-level folders.

    Only folders whose *top-level* path exists in ``allowed_top_folders`` are
    kept. Once a top-level folder is allowed, its entire subtree is preserved.
    Files are never filtered by this function.
    """

    if not node:
        return None

    current_path = _compose_path(base_path, node.get("name", ""))
    if root_path is None:
        root_path = current_path

    node_type = node.get("type", "")

    if (
        node_type == "folder"
        and base_path == root_path
        and current_path not in allowed_top_folders
    ):
        return None

    filtered_node: JsonNode = {"name": node.get("name", ""), "type": node_type}

    if node_type == "folder":
        children: list[JsonNode] = []
        for child in node.get("children", []):
            child_type = child.get("type", "")
            if child_type == "folder":
                filtered_child = _filter_structure_by_paths(
                    child, allowed_top_folders, current_path, root_path
                )
                if filtered_child:
                    children.append(filtered_child)
            else:
                children.append(child)

        if children:
            filtered_node["children"] = children

    return filtered_node


def _get_top_level_folders(structure: JsonNode) -> set[str]:
    """Return the set of folder paths present at the top level of ``structure``."""

    root_path = _compose_path("", structure.get("name", ""))
    allowed: set[str] = set()

    for child in structure.get("children", []):
        if child.get("type") == "folder":
            allowed.add(_compose_path(root_path, child.get("name", "")))

    return allowed


def _populate_tree(
    tree: ttk.Treeview,
    node: JsonNode,
    status_map: dict[str, str],
    parent: str = "",
    base_path: str = "",
    expand: bool = True,
) -> None:
    if not node:
        return

    current_path = _compose_path(base_path, node.get("name", ""))
    status = status_map.get(current_path, "Sin cambios")
    node_type = node.get("type", "")
    display_type = "Carpeta" if node_type == "folder" else "Archivo" if node_type == "file" else node_type
    tag = _status_to_tag(status)

    item_id = tree.insert(
        parent,
        "end",
        text=node.get("name", ""),
        values=(status, display_type),
        tags=(tag,),
    )

    if expand:
        tree.item(item_id, open=True)

    if node.get("type") == "folder":
        for child in node.get("children", []):
            _populate_tree(tree, child, status_map, item_id, current_path, expand)


def _show_results(
    old_structure: JsonNode,
    new_structure: JsonNode,
    results: dict,
    old_status: dict[str, str],
    new_status: dict[str, str],
    old_computer: str | None,
    new_computer: str | None,
    old_path: str | None,
    new_path: str | None,
) -> None:
    window = tk.Toplevel()
    window.title("Resultado de la comparación")
    window.geometry("1000x600")

    window.columnconfigure(0, weight=1, uniform="col")
    window.columnconfigure(1, weight=1, uniform="col")
    window.rowconfigure(0, weight=1)

    previous_label = old_computer or "Desconocida"
    current_label = new_computer or "Desconocida"
    previous_path = old_path or "Ruta no disponible"
    current_path = new_path or "Ruta no disponible"

    left_section = ttk.Frame(window)
    right_section = ttk.Frame(window)
    left_section.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
    right_section.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

    for section in (left_section, right_section):
        section.rowconfigure(1, weight=1)
        section.columnconfigure(0, weight=1)

    remote_title = tk.Label(left_section, text="Remoto", font=("TkDefaultFont", 12, "bold"))
    local_title = tk.Label(right_section, text="Local", font=("TkDefaultFont", 12, "bold"))
    remote_title.grid(row=0, column=0, pady=(0, 6))
    local_title.grid(row=0, column=0, pady=(0, 6))

    old_frame = ttk.LabelFrame(left_section, text=f"{previous_label} - {previous_path}")
    old_frame.grid(row=1, column=0, sticky="nsew")
    new_frame = ttk.LabelFrame(right_section, text=f"{current_label} - {current_path}")
    new_frame.grid(row=1, column=0, sticky="nsew")

    for frame in (old_frame, new_frame):
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

    old_tree = ttk.Treeview(old_frame, columns=("Estado", "Tipo"), show="tree headings")
    new_tree = ttk.Treeview(new_frame, columns=("Estado", "Tipo"), show="tree headings")

    for tree in (old_tree, new_tree):
        tree.heading("#0", text="Elemento")
        tree.heading("Estado", text="Estado")
        tree.heading("Tipo", text="Tipo")
        tree.column("#0", width=320, stretch=True)
        tree.column("Estado", width=200, anchor="center")
        tree.column("Tipo", width=120, anchor="center")

        tree.tag_configure("nuevo", foreground="#22863a")
        tree.tag_configure("eliminado", foreground="#cb2431")
        tree.tag_configure("renombrado", foreground="#b08800")
        tree.tag_configure("normal", foreground="#24292e")

    old_tree.grid(row=0, column=0, sticky="nsew")
    new_tree.grid(row=0, column=0, sticky="nsew")

    old_vscroll = ttk.Scrollbar(old_frame, orient="vertical", command=old_tree.yview)
    new_vscroll = ttk.Scrollbar(new_frame, orient="vertical", command=new_tree.yview)
    old_hscroll = ttk.Scrollbar(old_frame, orient="horizontal", command=old_tree.xview)
    new_hscroll = ttk.Scrollbar(new_frame, orient="horizontal", command=new_tree.xview)

    old_tree.configure(yscrollcommand=old_vscroll.set, xscrollcommand=old_hscroll.set)
    new_tree.configure(yscrollcommand=new_vscroll.set, xscrollcommand=new_hscroll.set)

    old_vscroll.grid(row=0, column=1, sticky="ns")
    new_vscroll.grid(row=0, column=1, sticky="ns")
    old_hscroll.grid(row=1, column=0, columnspan=2, sticky="ew")
    new_hscroll.grid(row=1, column=0, columnspan=2, sticky="ew")

    filtered_old = _filter_structure_for_changes(old_structure, old_status)
    filtered_new = _filter_structure_for_changes(new_structure, new_status)
    allowed_top_folders = _get_top_level_folders(old_structure)

    filter_var = tk.BooleanVar(value=True)
    restrict_var = tk.BooleanVar(value=False)

    def refresh_views() -> None:
        for tree in (old_tree, new_tree):
            for item in tree.get_children():
                tree.delete(item)

        show_only_changes = filter_var.get()
        restrict_to_json = restrict_var.get()
        display_old = filtered_old if show_only_changes else old_structure
        display_new = filtered_new if show_only_changes else new_structure

        if restrict_to_json:
            display_new = _filter_structure_by_paths(display_new, allowed_top_folders)

        if display_old:
            _populate_tree(old_tree, display_old, old_status)
        if display_new:
            _populate_tree(new_tree, display_new, new_status)

    refresh_views()

    controls = tk.Frame(window)
    controls.grid(row=1, column=0, columnspan=2, pady=(0, 12))
    toggle = tk.Checkbutton(
        controls,
        text="Mostrar solo diferencias",
        variable=filter_var,
        command=refresh_views,
    )
    toggle.pack(side="left", padx=(0, 10))
    restrict_toggle = tk.Checkbutton(
        controls,
        text="Mostrar solo carpetas presentes en remoto",
        variable=restrict_var,
        command=refresh_views,
    )
    restrict_toggle.pack(side="left", padx=(0, 10))
    close_button = tk.Button(controls, text="Cerrar", width=14, command=window.destroy)
    close_button.pack(side="left")

    window.grab_set()


def _select_file(prompt: str) -> str | None:
    return filedialog.askopenfilename(title=prompt, filetypes=[("JSON files", "*.json")])


def compare_json_files() -> None:
    old_file = _select_file("Selecciona el JSON remoto")
    if not old_file:
        return

    try:
        old_structure, old_computer, old_path = _load_json(old_file)
    except (OSError, json.JSONDecodeError) as error:
        messagebox.showerror("Error", f"No se pudo leer el archivo remoto: {error}")
        return

    if not old_path:
        messagebox.showerror(
            "Error",
            "El JSON remoto no contiene la ruta (selected_path) necesaria para generar la estructura local.",
        )
        return

    if not os.path.isdir(old_path):
        messagebox.showerror(
            "Error",
            "La ruta indicada en el JSON remoto no existe en esta computadora."
            " Verifica que la carpeta esté disponible antes de comparar.",
        )
        return

    try:
        local_data = BuildJson(old_path)
    except OSError as error:
        messagebox.showerror(
            "Error",
            f"No se pudo generar la estructura local para la ruta seleccionada: {error}",
        )
        return

    new_structure = local_data.get("structure", {})
    new_computer = local_data.get("computer")
    new_path = local_data.get("selected_path")

    results = _compare_structures(old_structure, new_structure)
    old_status, new_status = _build_status_maps(results)
    _show_results(
        old_structure,
        new_structure,
        results,
        old_status,
        new_status,
        old_computer,
        new_computer,
        old_path,
        new_path,
    )
