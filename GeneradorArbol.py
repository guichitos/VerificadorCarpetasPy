import getpass
import json
import os
import platform
import tkinter as tk
from tkinter import filedialog, messagebox


OUTPUT_FILENAME = "estructura_carpetas.json"


def GetTree(TargetPath: str, RootPath: str, DriveId: str | None) -> dict:
    """Build a dictionary representing the directory tree."""

    NodeName = os.path.basename(TargetPath) or TargetPath
    RelativePath = os.path.relpath(TargetPath, RootPath)
    if RelativePath == ".":
        RelativePath = ""

    GraphPath = None
    if DriveId is not None:
        NormalizedRelative = RelativePath.replace(os.sep, "/")
        GraphPath = f"drives/{DriveId}/root:/{NormalizedRelative}" if NormalizedRelative else f"drives/{DriveId}/root"

    if os.path.isdir(TargetPath):
        Children = [
            GetTree(os.path.join(TargetPath, EntryName), RootPath, DriveId)
            for EntryName in sorted(os.listdir(TargetPath))
        ]
        return {
            "name": NodeName,
            "type": "folder",
            "graph_path": GraphPath,
            "children": Children,
        }
    return {"name": NodeName, "type": "file", "graph_path": GraphPath}


def _ParseIniForDriveId(FileContent: str) -> str | None:
    """Extract the drive ID from OneDrive policy content."""

    CleanContent = FileContent.replace("\x00", "")
    IniKeys = ("graphdriveid", "cid", "usercid")
    for Line in CleanContent.splitlines():
        if "=" not in Line:
            continue
        KeyPart, _, ValuePart = Line.partition("=")
        NormalizedKey = KeyPart.strip().lower()
        if NormalizedKey in IniKeys:
            Candidate = ValuePart.strip()
            if Candidate:
                return Candidate
    return None


def GetOneDriveId(BasePath: str) -> str | None:
    """Try to read the internal OneDrive ID from common locations."""

    EnvironmentCandidates = [
        "ONEDRIVE_DRIVE_ID",
        "ONEDRIVE_ID",
        "ONEDRIVE_RESOURCE_ID",
    ]
    for VariableName in EnvironmentCandidates:
        VariableValue = os.environ.get(VariableName)
        if VariableValue:
            return VariableValue.strip()

    CandidatePaths = [
        os.path.join(os.path.expanduser("~"), ".config", "onedrive", "drive_id"),
        os.path.join(os.path.expanduser("~"), ".config", "OneDrive", "drive_id"),
        os.path.join(BasePath, ".onedrive", "drive_id"),
    ]

    LocalAppData = os.environ.get("LOCALAPPDATA")
    if LocalAppData:
        OneDriveSettings = os.path.join(
            LocalAppData, "Microsoft", "OneDrive", "settings"
        )
        CandidatePaths.extend(
            [
                os.path.join(OneDriveSettings, "Business1", "ClientPolicy.ini"),
                os.path.join(OneDriveSettings, "Personal", "ClientPolicy.ini"),
            ]
        )

    for ConfigPath in CandidatePaths:
        if not os.path.isfile(ConfigPath):
            continue
        try:
            with open(ConfigPath, "r", encoding="utf-8") as FileHandle:
                FileContent = FileHandle.read().strip()
        except OSError:
            continue

        if not FileContent:
            continue

        ParsedDriveId = _ParseIniForDriveId(FileContent)
        if ParsedDriveId:
            return ParsedDriveId

    return None


def BuildJson(SelectedPath: str) -> dict:
    """Assemble the JSON payload with metadata and structure."""

    UserName = getpass.getuser()
    LocalFolder = os.path.expanduser("~")
    OneDriveId = GetOneDriveId(SelectedPath)

    return {
        "user": {
            "name": UserName,
            "local_folder": LocalFolder,
        },
        "computer": platform.node(),
        "selected_path": SelectedPath,
        "onedrive_id": OneDriveId,
        "structure": GetTree(SelectedPath, SelectedPath, OneDriveId),
    }


def SaveFile(TargetFolder: str, Content: dict) -> str:
    """Persist the JSON data inside the chosen folder."""

    DestinationPath = os.path.join(TargetFolder, OUTPUT_FILENAME)
    with open(DestinationPath, "w", encoding="utf-8") as FileHandle:
        json.dump(Content, FileHandle, ensure_ascii=False, indent=2)
    return DestinationPath


def SelectFolder() -> None:
    SelectedFolder = filedialog.askdirectory(title="Select a folder to analyze")
    if not SelectedFolder:
        return

    JsonData = BuildJson(SelectedFolder)
    OutputPath = SaveFile(SelectedFolder, JsonData)

    if JsonData.get("onedrive_id"):
        AdditionalMessage = ""
    else:
        AdditionalMessage = (
            "\nNo OneDrive internal ID was found. "
            "If you use OneDrive, sign in and try again."
        )

    messagebox.showinfo(
        "File created",
        f"The '{OUTPUT_FILENAME}' file was generated at:\n{OutputPath}{AdditionalMessage}",
    )


def Main() -> None:
    RootWindow = tk.Tk()
    RootWindow.title("Folder tree generator")
    RootWindow.geometry("400x200")
    RootWindow.resizable(False, False)

    DescriptionLabel = tk.Label(
        RootWindow,
        text="Select a folder to generate a JSON file with its structure.",
        wraplength=360,
        justify="center",
        padx=20,
        pady=20,
    )
    DescriptionLabel.pack()

    SelectButton = tk.Button(
        RootWindow, text="Select folder", command=SelectFolder, width=25
    )
    SelectButton.pack(pady=10)

    RootWindow.mainloop()


if __name__ == "__main__":
    Main()
