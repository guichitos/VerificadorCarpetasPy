import tkinter as tk

from ComparadorJson import compare_json_files
from GeneradorArbol import SelectFolder


def main() -> None:
    root = tk.Tk()
    root.title("Herramientas de estructura de carpetas")
    root.geometry("520x330")
    root.resizable(False, False)

    content = tk.Frame(root, padx=20, pady=15)
    content.pack(fill="both", expand=True)

    step_one = tk.Label(
        content,
        text=(
            "1. Generar un archivo de estado desde una carpeta en la computadora 1 "
            "para guardar su estructura."
        ),
        wraplength=460,
        justify="left",
        anchor="w",
    )
    step_one.pack(fill="x")

    generate_button = tk.Button(
        content, text="Generar JSON base", command=SelectFolder, width=24
    )
    generate_button.pack(pady=(6, 16))

    step_two = tk.Label(
        content,
        text=(
            "2. Realizar la comparación de carpetas en la computadora 2 usando el "
            "archivo de estado generado."
        ),
        wraplength=460,
        justify="left",
        anchor="w",
    )
    step_two.pack(fill="x")

    compare_button = tk.Button(
        content,
        text="Comparar con JSON remoto",
        command=compare_json_files,
        width=24,
    )
    compare_button.pack(pady=(6, 20))

    close_button = tk.Button(content, text="Cerrar", command=root.destroy, width=16)
    close_button.pack(pady=(0, 0))

    root.mainloop()


if __name__ == "__main__":
    main()
