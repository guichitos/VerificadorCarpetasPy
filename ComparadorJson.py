import json
import os
import subprocess
import sys
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, List, Tuple

from GeneradorArbol import BuildJson


JsonNode = Dict[str, Any]


def _compose_path(base_path: str, name: str) -> str:
    parts = [segment for segment in (base_path, name) if segment]
    return "/".join(parts).replace("\\", "/")


def _collect_nodes(
    node: JsonNode, base_path: str = "", include_files: bool = True
) -> List[Tuple[str, str, str | None]]:
    """Return a flat list of (path, type, graph_path) tuples for each node."""

    current_path = _compose_path(base_path, node.get("name", ""))
    node_type = node.get("type", "")
    graph_path = node.get("graph_path")

    nodes = [(current_path, node_type, graph_path)] if include_files or node_type == "folder" else []
    if node_type == "folder":
        for child in node.get("children", []):
            nodes.extend(_collect_nodes(child, current_path, include_files))
    return nodes


def _load_json(path: str) -> tuple[JsonNode, str | None, str | None]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    structure = data.get("structure", data)
    computer = data.get("computer") if isinstance(data, dict) else None
    selected_path = data.get("selected_path") if isinstance(data, dict) else None
    return structure, computer, selected_path


def _compare_structures(
    old_structure: JsonNode, new_structure: JsonNode, include_files: bool = True
) -> dict:
    old_nodes = _collect_nodes(old_structure, include_files=include_files)
    new_nodes = _collect_nodes(new_structure, include_files=include_files)

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


def _filter_structure_by_type(node: JsonNode | None, include_files: bool) -> JsonNode | None:
    """Return a copy of the structure honoring the ``include_files`` flag."""

    if not node:
        return None

    node_type = node.get("type", "")
    if node_type == "file" and not include_files:
        return None

    filtered: JsonNode = {"name": node.get("name", ""), "type": node_type}

    if node_type == "folder":
        children: list[JsonNode] = []
        for child in node.get("children", []):
            filtered_child = _filter_structure_by_type(child, include_files)
            if filtered_child:
                children.append(filtered_child)
        if children:
            filtered["children"] = children

    return filtered


def _filter_structure_by_paths(
    node: JsonNode | None,
    allowed_folders: set[str],
    base_path: str = "",
    root_path: str | None = None,
) -> JsonNode | None:
    """Return a copy of the tree filtering only top-level folders.

    Only folders whose *top-level* path exists in ``allowed_folders`` are
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
        and current_path not in allowed_folders
    ):
        return None

    filtered_node: JsonNode = {"name": node.get("name", ""), "type": node_type}

    if node_type == "folder":
        children: list[JsonNode] = []
        for child in node.get("children", []):
            child_type = child.get("type", "")
            if child_type == "folder":
                filtered_child = _filter_structure_by_paths(
                    child, allowed_folders, current_path, root_path
                )
                if filtered_child:
                    children.append(filtered_child)
            else:
                children.append(child)

        if children:
            filtered_node["children"] = children
    elif base_path not in allowed_folders:
        return None

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
        iid=current_path,
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
    local_title = tk.Label(
        right_section, text="Local", font=("TkDefaultFont", 12, "bold")
    )
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

    filter_var = tk.BooleanVar(value=True)
    restrict_var = tk.BooleanVar(value=True)
    include_files_var = tk.BooleanVar(value=False)
    sync_selection_var = tk.BooleanVar(value=False)

    comparison_state: dict[str, Any] = {}
    allowed_folders = _get_top_level_folders(old_structure)

    def recompute() -> None:
        include_files = include_files_var.get()

        display_old = _filter_structure_by_type(old_structure, include_files) or {}
        display_new = _filter_structure_by_type(new_structure, include_files) or {}

        results = _compare_structures(
            display_old, display_new, include_files=include_files
        )
        old_status, new_status = _build_status_maps(results)

        filtered_old = _filter_structure_for_changes(display_old, old_status)
        filtered_new = _filter_structure_for_changes(display_new, new_status)

        comparison_state.clear()
        comparison_state.update(
            {
                "old": display_old,
                "new": display_new,
                "filtered_old": filtered_old,
                "filtered_new": filtered_new,
                "old_status": old_status,
                "new_status": new_status,
                "results": results,
            }
        )

    def refresh_views() -> None:
        for tree in (old_tree, new_tree):
            for item in tree.get_children():
                tree.delete(item)

        show_only_changes = filter_var.get()
        restrict_to_json = restrict_var.get()

        base_old = comparison_state.get("filtered_old") if show_only_changes else comparison_state.get("old")
        base_new = comparison_state.get("filtered_new") if show_only_changes else comparison_state.get("new")

        if restrict_to_json:
            base_new = _filter_structure_by_paths(base_new, allowed_folders)

        old_status = comparison_state.get("old_status", {})
        new_status = comparison_state.get("new_status", {})

        if base_old:
            _populate_tree(old_tree, base_old, old_status)
        if base_new:
            _populate_tree(new_tree, base_new, new_status)

    def _expand_and_select(tree: ttk.Treeview, item_id: str) -> None:
        current = item_id
        while current:
            tree.item(current, open=True)
            current = tree.parent(current)

        tree.selection_set(item_id)
        tree.focus(item_id)
        tree.see(item_id)

    def _sync_selection(event: tk.Event | None = None) -> None:
        if not sync_selection_var.get():
            return

        selection = old_tree.selection()
        if not selection:
            return

        target = selection[0]
        candidate = target

        while candidate:
            if new_tree.exists(candidate):
                _expand_and_select(new_tree, candidate)
                return

            if "/" in candidate:
                candidate = candidate.rsplit("/", 1)[0]
            else:
                break

        if new_tree.get_children():
            fallback = new_tree.get_children()[0]
            _expand_and_select(new_tree, fallback)

    def refresh_all() -> None:
        recompute()
        refresh_views()

    def generate_report() -> None:
        results = comparison_state.get("results")
        if not results:
            messagebox.showwarning(
                "Sin datos",
                "Aún no hay resultados para generar el informe. Ejecuta una comparación primero.",
            )
            return

        timestamp = datetime.now().strftime("%Y.%m.%d.%H%M")
        filename = f"Files_diferences_{timestamp}.txt"
        destination = os.path.join(old_path or os.getcwd(), filename)

        content = _format_results(results)

        try:
            with open(destination, "w", encoding="utf-8") as handle:
                handle.write(content)
        except OSError as error:
            messagebox.showerror(
                "Error al guardar",
                f"No se pudo crear el informe en {destination}: {error}",
            )
            return

        messagebox.showinfo(
            "Informe generado",
            f"Se creó el archivo de diferencias:\n{destination}",
        )

    def open_main_folder() -> None:
        if not old_path or not os.path.isdir(old_path):
            messagebox.showerror(
                "Ruta no disponible",
                "No se puede abrir la carpeta principal porque la ruta es inválida",
            )
            return

        try:
            if os.name == "nt":
                os.startfile(old_path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", old_path])
            else:
                subprocess.Popen(["xdg-open", old_path])
        except OSError as error:
            messagebox.showerror(
                "Error al abrir",
                f"No se pudo abrir la carpeta seleccionada: {error}",
            )

    refresh_all()

    controls = tk.Frame(window)
    controls.grid(row=1, column=0, columnspan=2, pady=(0, 12), sticky="ew")
    controls.columnconfigure(0, weight=1)
    controls.columnconfigure(1, weight=1)

    filters_frame = ttk.LabelFrame(controls, text="Filtros")
    filters_frame.grid(row=0, column=0, sticky="ew", padx=(0, 8))
    operations_frame = ttk.LabelFrame(controls, text="Operaciones")
    operations_frame.grid(row=0, column=1, sticky="nsew")

    toggle = tk.Checkbutton(
        filters_frame,
        text="Mostrar solo diferencias",
        variable=filter_var,
        command=refresh_views,
        anchor="w",
    )
    toggle.pack(fill="x", padx=10, pady=(8, 2))
    restrict_toggle = tk.Checkbutton(
        filters_frame,
        text="Mostrar solo carpetas presentes en remoto",
        variable=restrict_var,
        command=refresh_views,
        anchor="w",
    )
    restrict_toggle.pack(fill="x", padx=10, pady=2)
    sync_selection_toggle = tk.Checkbutton(
        filters_frame,
        text="Selección sincronizada",
        variable=sync_selection_var,
        anchor="w",
    )
    sync_selection_toggle.pack(fill="x", padx=10, pady=2)
    include_files_toggle = tk.Checkbutton(
        filters_frame,
        text="Incluir archivos en la comparación",
        variable=include_files_var,
        command=refresh_all,
        anchor="w",
    )
    include_files_toggle.pack(fill="x", padx=10, pady=(2, 8))

    refresh_button = tk.Button(
        operations_frame,
        text="Actualizar",
        width=28,
        command=refresh_all,
    )
    refresh_button.pack(fill="x", padx=10, pady=(8, 4))

    generate_button = tk.Button(
        operations_frame,
        text="Generar informe de diferencias",
        width=28,
        command=generate_report,
    )
    generate_button.pack(fill="x", padx=10, pady=4)

    open_folder_button = tk.Button(
        operations_frame,
        text="Abrir carpeta principal",
        width=28,
        command=open_main_folder,
    )
    open_folder_button.pack(fill="x", padx=10, pady=4)

    close_button = tk.Button(
        operations_frame, text="Cerrar", width=28, command=window.destroy
    )
    close_button.pack(fill="x", padx=10, pady=(4, 8))

    old_tree.bind("<<TreeviewSelect>>", _sync_selection)

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

    _show_results(
        old_structure,
        new_structure,
        old_computer,
        new_computer,
        old_path,
        new_path,
    )
