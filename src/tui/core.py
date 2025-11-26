from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import DirectoryTree, Footer, Header

from .encryption_modal import EncryptionModal, EncryptionMode
from .file_view import FileView


class Tui(App):
    CSS_PATH = [
        "encryption_modal.tcss",
        "file_view.tcss",
    ]
    BINDINGS = [
        Binding(key="q", action="quit", description="Quit the app"),
        Binding(
            key="r",
            action="refresh",
            description="Refresh file tree",
            key_display="r",
        ),
        Binding(
            key="e",
            action="encrypt_file",
            description="Encrypt selected file",
            key_display="e",
        ),
        Binding(
            key="d",
            action="decrypt_file",
            description="Decrypt selected file",
            key_display="d",
        ),
    ]

    def on_mount(self) -> None:
        self.title = "Secure File Vault"
        self.sub_title = "Encryption & Decryption Tool"
        self.theme = "tokyo-night"

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()
        yield FileView()

    def action_refresh(self) -> None:
        """Refresh the directory tree view."""
        file_view = self.query_one("#file_view_container", FileView)
        directory_view = file_view.query_one(DirectoryTree)
        self.call_later(directory_view.reload)

    def _open_encryption_modal(self, mode: EncryptionMode) -> None:
        """Open the encryption/decryption modal for the selected file."""
        file_view = self.query_one("#file_view_container", FileView)
        self.push_screen(
            EncryptionModal(
                mode=mode,
                relpath=file_view.get_selected_file(),
                clear_fn=file_view.reset_selected_file,
            )
        )

    def action_encrypt_file(self) -> None:
        """Open the encryption modal for the selected file."""
        self._open_encryption_modal(EncryptionMode("encryption"))

    def action_decrypt_file(self) -> None:
        """Open the decryption modal for the selected file."""
        self._open_encryption_modal(EncryptionMode("decryption"))
