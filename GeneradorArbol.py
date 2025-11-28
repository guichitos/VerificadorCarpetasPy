import getpass
import json
import os
import platform
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox


EXCLUDED_NAMES = [".git"]


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
        Children = []
        for EntryName in sorted(os.listdir(TargetPath)):
            if EntryName in EXCLUDED_NAMES:
                continue
            Children.append(
                GetTree(os.path.join(TargetPath, EntryName), RootPath, DriveId)
            )
        return {
            "name": NodeName,
            "type": "folder",
            "graph_path": GraphPath,
            "children": Children,
        }
    return {"name": NodeName, "type": "file", "graph_path": GraphPath}


def _ParseIniForDriveId(FileContent: str, SourcePath: str) -> tuple[str | None, str | None]:
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
                return Candidate, f"{SourcePath} ({NormalizedKey})"
    return None, None


def GetOneDriveId(BasePath: str) -> tuple[str | None, str | None]:
    """Try to read the internal OneDrive ID from common locations."""

    EnvironmentCandidates = [
        "ONEDRIVE_DRIVE_ID",
        "ONEDRIVE_ID",
        "ONEDRIVE_RESOURCE_ID",
    ]
    for VariableName in EnvironmentCandidates:
        VariableValue = os.environ.get(VariableName)
        if VariableValue:
            return VariableValue.strip(), f"environment ({VariableName})"

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

        ParsedDriveId, Source = _ParseIniForDriveId(FileContent, ConfigPath)
        if ParsedDriveId:
            return ParsedDriveId, Source

    return None, None


def BuildJson(SelectedPath: str) -> dict:
    """Assemble the JSON payload with metadata and structure."""

    UserName = getpass.getuser()
    LocalFolder = os.path.expanduser("~")
    OneDriveId, OneDriveSource = GetOneDriveId(SelectedPath)

    return {
        "user": {
            "name": UserName,
            "local_folder": LocalFolder,
        },
        "computer": platform.node(),
        "selected_path": SelectedPath,
        "onedrive": {
            "id": OneDriveId,
            "source": OneDriveSource,
            "description": (
                "Internal drive identifier used by OneDrive Graph API. "
                "Allows locating folders even if they are renamed."
            ),
        },
        "structure": GetTree(SelectedPath, SelectedPath, OneDriveId),
    }


def SaveFile(TargetFolder: str, Content: dict) -> str:
    """Persist the JSON data inside the chosen folder."""

    def _sanitize_name(Name: str) -> str:
        return "".join(Character if Character.isalnum() or Character in {"-", "_"} else "_" for Character in Name)

    ComputerName = Content.get("computer") or platform.node() or "UnknownComputer"
    SafeComputer = _sanitize_name(str(ComputerName)) or "UnknownComputer"
    DateSuffix = datetime.now().strftime("%Y%m%d")
    FileName = f"File_structure_{SafeComputer}_{DateSuffix}.json"

    DestinationPath = os.path.join(TargetFolder, FileName)
    with open(DestinationPath, "w", encoding="utf-8") as FileHandle:
        json.dump(Content, FileHandle, ensure_ascii=False, indent=2)
    return DestinationPath


def SelectFolder() -> None:
    SelectedFolder = filedialog.askdirectory(title="Select a folder to analyze")
    if not SelectedFolder:
        return

    JsonData = BuildJson(SelectedFolder)
    OutputPath = SaveFile(SelectedFolder, JsonData)

    OneDriveData = JsonData.get("onedrive", {})
    if OneDriveData.get("id"):
        AdditionalMessage = (
            "\nSe detectó el identificador interno de OneDrive, "
            "útil para ubicar carpetas aunque cambien de nombre."
        )
    else:
        AdditionalMessage = (
            "\nNo OneDrive internal ID was found. "
            "If you use OneDrive, sign in and try again."
        )

    messagebox.showinfo(
        "File created",
        f"The file was generated at:\n{OutputPath}{AdditionalMessage}",
    )
