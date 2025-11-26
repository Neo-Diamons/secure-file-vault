import os
from enum import Enum

from cryptography.fernet import InvalidToken
from textual.app import ComposeResult
from textual.containers import Grid, VerticalGroup
from textual.screen import ModalScreen
from textual.validation import ValidationResult, Validator
from textual.widgets import Button, Input, Label

from utils.encryption import Encryption


class EncryptionMode(Enum):
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"

    def __str__(self) -> str:
        return self.value


class EncryptionModal(ModalScreen):
    """Modal screen to show file encryption/decryption options."""

    class _PasswordValidator(Validator):
        def validate(self, value: str) -> ValidationResult:
            if 5 <= len(value) <= 100:
                return self.success()
            else:
                return self.failure("Password must be between 5 and 100 characters.")

    def __init__(self, mode: EncryptionMode, relpath: str | None, clear_fn) -> None:
        super().__init__()
        self.relpath = relpath
        self.clear_fn = clear_fn
        self.mode = mode
        self.encryption = Encryption()

    def _error_modal(self, message: str) -> ComposeResult:
        yield VerticalGroup(
            Label(
                message,
                classes="modal_label",
            ),
            Button("Cancel", variant="error", classes="cancel"),
            classes="modal",
        )

    def _get_option_button(self) -> Button:
        assert self.relpath, "relpath cannot be NULL"

        if self.mode == EncryptionMode.ENCRYPTION:
            return Button("Encrypt", variant="primary", id="encrypt")
        else:
            return Button("Decrypt", variant="primary", id="decrypt")

    async def on_button_pressed(self, event) -> None:
        """Handle button presses in the modal."""

        if event.button.id == "encrypt" or event.button.id == "decrypt":
            assert self.relpath, "relpath cannot be NULL"

            password_input = self.query_one("#modal_encryption_input", Input)
            password_hint = self.query_one("#modal_encryption_hint", Label)

            validation_result = password_input.validate(password_input.value)
            if not validation_result:
                return
            elif not validation_result.is_valid:
                password_hint.update(
                    validation_result.failure_descriptions[0] or "Invalid password."
                )
                return

            if self.mode == EncryptionMode.ENCRYPTION:
                relpath = self.relpath + ".encrypted"
                try:
                    self.encryption.encrypt_file(
                        self.relpath, relpath, password_input.value
                    )
                except Exception:
                    password_hint.update("Encryption failed: An error occurred.")
                    return
            elif self.mode == EncryptionMode.DECRYPTION:
                relpath = self.relpath.removesuffix(".encrypted")
                try:
                    self.encryption.decrypt_file(
                        self.relpath, relpath, password_input.value
                    )
                except InvalidToken:
                    password_hint.update("Decryption failed: Invalid password.")
                    return
                except Exception:
                    password_hint.update("Decryption failed: An error occurred.")
                    return

            try:
                if os.path.exists(self.relpath):
                    os.remove(self.relpath)
            except Exception:
                pass

            await self.clear_fn()

        self.app.pop_screen()

    def compose(self) -> ComposeResult:
        if not self.relpath:
            yield from self._error_modal(f"No file selected for {self.mode.value}.")
        elif self.mode == EncryptionMode.ENCRYPTION and self.encryption.is_encrypted(
            self.relpath
        ):
            yield from self._error_modal(
                f'File "{os.path.basename(self.relpath)}" already encrypted.'
            )
        elif (
            self.mode == EncryptionMode.DECRYPTION
            and not self.encryption.is_encrypted(self.relpath)
        ):
            yield from self._error_modal(
                f'File "{os.path.basename(self.relpath)}" is not encrypted.'
            )
        else:
            yield VerticalGroup(
                Label(
                    f"File: {os.path.basename(self.relpath)}",
                    classes="modal_label",
                    id="modal_encryption_label",
                ),
                Input(
                    placeholder="Enter password",
                    password=True,
                    validators=[
                        self._PasswordValidator(),
                    ],
                    validate_on=["blur"],
                    id="modal_encryption_input",
                ),
                Label(
                    "Password must be between 5 and 100 characters.",
                    id="modal_encryption_hint",
                ),
                Grid(
                    self._get_option_button(),
                    Button("Cancel", variant="error", classes="cancel"),
                    id="modal_encryption_buttons",
                ),
                id="modal_encryption",
                classes="modal",
            )
