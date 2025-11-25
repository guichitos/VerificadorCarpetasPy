import hashlib
import json
import os
import platform
import getpass
import tkinter as tk
from tkinter import filedialog, messagebox


OUTPUT_FILENAME = "estructura_carpetas.txt"


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


def calcular_huella_carpeta(ruta: str) -> str:
    """Calcula una huella SHA-256 basada en el contenido y estructura de la carpeta."""

    hash_global = hashlib.sha256()

    for raiz, directorios, archivos in os.walk(ruta):
        directorios.sort()
        archivos.sort()

        for carpeta in directorios:
            ruta_relativa = os.path.relpath(os.path.join(raiz, carpeta), ruta)
            hash_global.update(f"DIR:{ruta_relativa}".encode("utf-8"))

        for archivo in archivos:
            ruta_archivo = os.path.join(raiz, archivo)
            ruta_relativa = os.path.relpath(ruta_archivo, ruta)
            hash_global.update(f"FILE:{ruta_relativa}".encode("utf-8"))

            with open(ruta_archivo, "rb") as f:
                for bloque in iter(lambda: f.read(8192), b""):
                    hash_global.update(bloque)

    return hash_global.hexdigest()


def generar_json(ruta_seleccionada: str) -> dict:
    """Arma la estructura JSON con los metadatos solicitados."""
    usuario = getpass.getuser()
    carpeta_local = os.path.expanduser("~")
    huella = calcular_huella_carpeta(ruta_seleccionada)

    return {
        "usuario": {
            "nombre": usuario,
            "carpeta_local": carpeta_local,
        },
        "computadora": platform.node(),
        "ruta_seleccionada": ruta_seleccionada,
        "huella_carpeta": huella,
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
    messagebox.showinfo(
        "Archivo creado",
        f"Se generó el archivo '{OUTPUT_FILENAME}' en:\n{ruta_archivo}",
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
