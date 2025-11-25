import json
import os
import platform
import getpass
import tkinter as tk
from tkinter import filedialog, messagebox


OUTPUT_FILENAME = "estructura_carpetas.json"


def obtener_arbol(ruta: str) -> dict:
    """Genera un diccionario con la estructura de carpetas y archivos."""
    nombre = os.path.basename(ruta) or ruta
    if os.path.isdir(ruta):
        hijos = [
            obtener_arbol(os.path.join(ruta, elemento))
            for elemento in sorted(os.listdir(ruta))
        ]
        return {"nombre": nombre, "tipo": "carpeta", "hijos": hijos}
    return {"nombre": nombre, "tipo": "archivo"}


def obtener_id_onedrive(ruta_base: str) -> str | None:
    """Intenta recuperar el ID interno de OneDrive.

    La implementación busca primero variables de entorno habituales y después
    algunos archivos de configuración utilizados por clientes de OneDrive en
    Linux. Si no encuentra nada devuelve ``None`` para avisar al usuario.
    """

    posibles_env = [
        "ONEDRIVE_DRIVE_ID",
        "ONEDRIVE_ID",
        "ONEDRIVE_RESOURCE_ID",
    ]
    for variable in posibles_env:
        valor = os.environ.get(variable)
        if valor:
            return valor.strip()

    posibles_rutas = [
        os.path.join(os.path.expanduser("~"), ".config", "onedrive", "drive_id"),
        os.path.join(os.path.expanduser("~"), ".config", "OneDrive", "drive_id"),
        os.path.join(ruta_base, ".onedrive", "drive_id"),
    ]

    for ruta_config in posibles_rutas:
        if not os.path.isfile(ruta_config):
            continue
        try:
            with open(ruta_config, "r", encoding="utf-8") as archivo:
                contenido = archivo.read().strip()
                if contenido:
                    return contenido
        except OSError:
            continue

    return None


def generar_json(ruta_seleccionada: str) -> dict:
    """Arma la estructura JSON con los metadatos solicitados."""
    usuario = getpass.getuser()
    carpeta_local = os.path.expanduser("~")
    onedrive_id = obtener_id_onedrive(ruta_seleccionada)

    return {
        "usuario": {
            "nombre": usuario,
            "carpeta_local": carpeta_local,
        },
        "computadora": platform.node(),
        "ruta_seleccionada": ruta_seleccionada,
        "onedrive_id": onedrive_id,
        "estructura": obtener_arbol(ruta_seleccionada),
    }


def guardar_archivo(ruta_carpeta: str, contenido: dict) -> str:
    """Guarda el JSON en un archivo de texto dentro de la carpeta seleccionada."""
    destino = os.path.join(ruta_carpeta, OUTPUT_FILENAME)
    with open(destino, "w", encoding="utf-8") as archivo:
        json.dump(contenido, archivo, ensure_ascii=False, indent=2)
    return destino


def seleccionar_carpeta() -> None:
    carpeta = filedialog.askdirectory(title="Selecciona una carpeta para generar el árbol")
    if not carpeta:
        return

    datos = generar_json(carpeta)
    ruta_archivo = guardar_archivo(carpeta, datos)

    if datos.get("onedrive_id"):
        mensaje_adicional = ""
    else:
        mensaje_adicional = (
            "\nNo se encontró un ID interno de OneDrive. "
            "Si usas OneDrive, inicia sesión en el cliente y vuelve a intentar."
        )

    messagebox.showinfo(
        "Archivo creado",
        f"Se generó el archivo '{OUTPUT_FILENAME}' en:\n{ruta_archivo}{mensaje_adicional}",
    )


def main() -> None:
    raiz = tk.Tk()
    raiz.title("Generador de árbol de carpetas")
    raiz.geometry("400x200")
    raiz.resizable(False, False)

    etiqueta = tk.Label(
        raiz,
        text="Selecciona una carpeta y se generará un archivo con la estructura en JSON.",
        wraplength=360,
        justify="center",
        padx=20,
        pady=20,
    )
    etiqueta.pack()

    boton = tk.Button(raiz, text="Seleccionar carpeta", command=seleccionar_carpeta, width=25)
    boton.pack(pady=10)

    raiz.mainloop()


if __name__ == "__main__":
    main()
