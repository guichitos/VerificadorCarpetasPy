import tkinter as tk

from ComparadorJson import compare_json_files
from GeneradorArbol import SelectFolder


def main() -> None:
    root = tk.Tk()
    root.title("Herramientas de estructura de carpetas")
    root.geometry("460x240")
    root.resizable(False, False)

    description = tk.Label(
        root,
        text=(
            "Selecciona la acción que necesitas:\n"
            "• Generar el JSON base para la carpeta actual.\n"
            "• Comparar con un JSON remoto para detectar cambios."
        ),
        wraplength=420,
        justify="left",
        padx=20,
        pady=20,
    )
    description.pack()

    buttons_frame = tk.Frame(root)
    buttons_frame.pack(pady=5)

    generate_button = tk.Button(
        buttons_frame, text="Generar JSON base", command=SelectFolder, width=22
    )
    generate_button.grid(row=0, column=0, padx=5, pady=5)

    compare_button = tk.Button(
        buttons_frame, text="Comparar con JSON remoto", command=compare_json_files, width=22
    )
    compare_button.grid(row=0, column=1, padx=5, pady=5)

    root.mainloop()


if __name__ == "__main__":
    main()
