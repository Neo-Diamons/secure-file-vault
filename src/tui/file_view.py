import os

from textual.app import ComposeResult
from textual.containers import Grid, VerticalGroup, VerticalScroll
from textual.widgets import DirectoryTree, Label, Static


class FileView(Static):
    def __init__(self) -> None:
        super().__init__(id="file_view_container")
        self.directory_tree = DirectoryTree(path="./")  # Renamed to avoid conflict
        self.selected_file: str | None = None

    async def _get_file_widgets(self) -> tuple[Static, Static]:
        label_widget = self.query_one("#file_label", Static)
        content_widget = self.query_one("#file_content", Static)
        return label_widget, content_widget

    def get_selected_file(self) -> str | None:
        """Get the currently selected file path."""
        return self.selected_file

    async def reset_selected_file(self) -> None:
        """Reset the currently selected file path."""
        self.selected_file = None
        label_widget, content_widget = await self._get_file_widgets()
        label_widget.update("No file selected")
        content_widget.update("")
        self.directory_tree.reload()

    async def on_directory_tree_file_selected(
        self, message: DirectoryTree.FileSelected
    ) -> None:
        label_widget, content_widget = await self._get_file_widgets()

        filepath = message.path

        # Read the file contents
        if os.path.isfile(filepath):
            self.selected_file = str(filepath)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                content = "File is binary or not readable as text."
            except Exception:
                content = "Could not read file"
        else:
            content = f"Not text file : {filepath}"

        # Get relative path for display
        try:
            relpath = os.path.relpath(filepath, start=os.getcwd())
        except Exception:
            relpath = filepath

        # Update the inline file label/editor (if present)
        try:
            label_widget.update(f"File: {relpath}")
            content_widget.update(content)
        except Exception:
            pass

    def compose(self) -> ComposeResult:
        yield Grid(
            self.directory_tree,  # Updated reference
            VerticalGroup(
                Label("No file selected", id="file_label"),
                VerticalScroll(Static(id="file_content")),
                id="file_view",
            ),
            id="file_view_grid",
        )
