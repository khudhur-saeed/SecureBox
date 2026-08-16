import base64
import json
import os
import sys
import uuid
from typing import Optional

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
import typer

from Client.api_client import ApiClient
from Client.crypto import decrypt_vault_item, derive_master_keys, encrypt_vault_item

app = typer.Typer(
    help="SecureBox: Zero-Knowledge CLI Password Manager",
    add_completion=False,
)
console = Console()


# ------------------------------------------------------------------------------
# Authentication Commands
# ------------------------------------------------------------------------------


@app.command()
def register(
    server_url: str = typer.Option(
        "http://127.0.0.1:8000", "--url", "-u", help="Backend API base URL"
    ),
):
    """Registers a new SecureBox account with client-side key derivation."""
    console.print(
        Panel.fit(
            "[bold cyan]SecureBox Account Registration[/bold cyan]",
            border_style="cyan",
        )
    )

    email = typer.prompt("Enter your email").strip().lower()
    password = typer.prompt(
        "Enter your master password",
        hide_input=True,
        confirmation_prompt=True,
    )

    if not email or not password:
        console.print("[bold red]Error: Email and password cannot be empty.[/bold red]")
        raise typer.Exit(code=1)

    api = ApiClient(base_url=server_url)

    try:
        with console.status(
            "[bold green]Deriving cryptographic keys locally (Argon2id)...[/bold green]"
        ):
            # 16-byte cryptographically secure salt
            auth_salt = os.urandom(16)
            auth_salt_b64 = base64.b64encode(auth_salt).decode("utf-8")

            # Standard Argon2id baseline parameters
            kdf_iterations = 3
            kdf_memory = 65536
            kdf_parallelism = 4

            # Derive MEK (for local vault encryption) and MAK (to send as server_password_hash)
            _, mak = derive_master_keys(
                master_password=password,
                salt=auth_salt,
                time_cost=kdf_iterations,
                memory_cost=kdf_memory,
                parallelism=kdf_parallelism,
            )
            mak_b64 = base64.b64encode(mak).decode("utf-8")

        with console.status("[bold green]Contacting server...[/bold green]"):
            api.register(
                email=email,
                kdf_salt_b64=auth_salt_b64,
                server_password_hash_b64=mak_b64,
                kdf_memory=kdf_memory,
                kdf_iterations=kdf_iterations,
                kdf_parallelism=kdf_parallelism,
            )

        console.print(
            f"\n[bold green]✓ Account registered successfully for {email}![/bold green]"
        )
        console.print(
            "[dim]You can now run [bold cyan]python -m Client.main login[/bold cyan] to access your vault.[/dim]"
        )

    except httpx.HTTPStatusError as e:
        try:
            detail = e.response.json().get("detail", e.response.text)
        except Exception:
            detail = e.response.text
        console.print(
            f"[bold red]Registration failed ({e.response.status_code}): {detail}[/bold red]"
        )
        raise typer.Exit(code=1)
    except httpx.RequestError as e:
        console.print(
            f"[bold red]Could not connect to server at {server_url}: {e}[/bold red]"
        )
        raise typer.Exit(code=1)
    finally:
        api.close()

@app.command()
def login(
    server_url: str = typer.Option(
        "http://127.0.0.1:8000", "--url", "-u", help="Backend API base URL"
    ),
):
    """Authenticates the user and opens an interactive, zero-knowledge vault session."""
    console.print(
        Panel.fit(
            "[bold cyan]SecureBox Vault Login[/bold cyan]",
            border_style="cyan",
        )
    )

    email = typer.prompt("Enter your email").strip().lower()
    password = typer.prompt("Enter your master password", hide_input=True)

    api = ApiClient(base_url=server_url)

    try:
        # Step 1: Pre-login challenge to fetch salt and Argon2 parameters
        with console.status("[bold yellow]Fetching account parameters...[/bold yellow]"):
            prelogin_data = api.prelogin(email=email)
            auth_salt = base64.b64decode(prelogin_data["kdf_salt"])
            time_cost = prelogin_data.get("kdf_iterations", 3)
            memory_cost = prelogin_data.get("kdf_memory", 65536)
            parallelism = prelogin_data.get("kdf_parallelism", 4)

        # Step 2: Client-side Key Derivation
        with console.status("[bold yellow]Deriving keys locally...[/bold yellow]"):
            mek, mak = derive_master_keys(
                master_password=password,
                salt=auth_salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
            )
            mak_b64 = base64.b64encode(mak).decode("utf-8")

        # Step 3: Server authentication
        with console.status("[bold yellow]Authenticating session...[/bold yellow]"):
            api.login(email=email, auth_key_b64=mak_b64)

        console.print(
            f"\n[bold green]✓ Successfully authenticated as [white]{email}[/white]![/bold green]\n"
        )

        # Start interactive vault session loop
        _interactive_vault_session(api=api, mek=mek, user_email=email)

    except httpx.HTTPStatusError as e:
        try:
            detail = e.response.json().get("detail", e.response.text)
        except Exception:
            detail = e.response.text or f"HTTP {e.response.status_code}"
        console.print(
            f"[bold red]Authentication failed ({e.response.status_code}): {detail}[/bold red]"
        )
        raise typer.Exit(code=1)
    finally:
        api.close()


# ------------------------------------------------------------------------------
# Interactive Vault Shell Loop
# ------------------------------------------------------------------------------


def _interactive_vault_session(api: ApiClient, mek: bytes, user_email: str) -> None:
    """Maintains an interactive CLI session holding the derived MEK in memory."""
    console.print(
        f"[dim]Type [bold cyan]help[/bold cyan] for commands or [bold cyan]exit[/bold cyan] to lock vault and quit.[/dim]\n"
    )

    while True:
        try:
            command = (
                Prompt.ask(f"[bold cyan]securebox[/bold cyan] ([green]{user_email}[/green])")
                .strip()
                .lower()
            )

            if not command:
                continue

            if command in ("exit", "quit", "q"):
                console.print(
                    "[bold yellow]Locking vault and purging encryption keys from memory. Goodbye![/bold yellow]"
                )
                break

            elif command == "help":
                _print_help_table()

            elif command == "list":
                _handle_list_vault(api=api, mek=mek)

            elif command == "add":
                _handle_add_vault_item(api=api, mek=mek)

            elif command.startswith("delete"):
                parts = command.split()
                if len(parts) < 2:
                    console.print(
                        "[bold red]Usage: delete <item_uuid>[/bold red]"
                    )
                else:
                    _handle_delete_vault_item(api=api, item_id=parts[1])

            else:
                console.print(
                    f"[bold red]Unknown command:[/bold red] '{command}'. Type [bold cyan]help[/bold cyan] for available commands."
                )

        except (KeyboardInterrupt, EOFError):
            console.print(
                "\n[bold yellow]Session interrupted. Locking vault and exiting.[/bold yellow]"
            )
            break


# ------------------------------------------------------------------------------
# Vault Action Handlers
# ------------------------------------------------------------------------------


def _handle_list_vault(api: ApiClient, mek: bytes) -> None:
    """Fetches encrypted items from server, decrypts locally, and prints a formatted table."""
    try:
        with console.status("[bold green]Fetching & decrypting vault items...[/bold green]"):
            raw_items = api.list_vault_items()

        if not raw_items:
            console.print("[dim]Your vault is empty.[/dim]\n")
            return

        table = Table(
            title="🔒 Your Decrypted Vault",
            show_lines=True,
            header_style="bold magenta",
        )
        table.add_column("Item ID", style="dim", no_wrap=True)
        table.add_column("Title / Service", style="bold cyan")
        table.add_column("Username / Email", style="green")
        table.add_column("Password", style="yellow")
        table.add_column("Notes", style="dim")

        for item in raw_items:
            item_id = item["id"]
            nonce_b64 = item["nonce"]
            ciphertext_b64 = item["ciphertext"]
            auth_tag_b64 = item["auth_tag"]

            try:
                # Decrypt locally using the in-memory MEK and item_id as Associated Data
                plaintext_str = decrypt_vault_item(
                    mek=mek,
                    item_id=item_id,
                    nonce_b64=nonce_b64,
                    ciphertext_b64=ciphertext_b64,
                    auth_tag_b64=auth_tag_b64,
                )
                secret_data = json.loads(plaintext_str)

                title = secret_data.get("title", "<No Title>")
                username = secret_data.get("username", "<N/A>")
                secret_pwd = secret_data.get("password", "********")
                notes = secret_data.get("notes", "")

                table.add_row(item_id, title, username, secret_pwd, notes)

            except Exception:
                # If Galois tag validation fails or JSON is corrupted
                table.add_row(
                    item_id,
                    "[bold red]DECRYPTION FAILED[/bold red]",
                    "-",
                    "-",
                    "[red]Integrity check failed[/red]",
                )

        console.print(table)
        console.print()

    except httpx.HTTPStatusError as e:
        console.print(
            f"[bold red]Failed to fetch vault items ({e.response.status_code}): {e.response.text}[/bold red]"
        )


def _handle_add_vault_item(api: ApiClient, mek: bytes) -> None:
    """Prompts for credentials, encrypts them locally with AES-256-GCM, and uploads to the server."""
    title = Prompt.ask("Enter service / website title (e.g. GitHub)").strip()
    username = Prompt.ask("Enter username / login email").strip()
    password = Prompt.ask("Enter secret password", password=True)
    notes = Prompt.ask("Enter notes (optional)", default="").strip()

    if not title or not password:
        console.print("[bold red]Error: Title and password are required.[/bold red]")
        return

    # 1. Package plaintext into structured JSON
    payload_dict = {
        "title": title,
        "username": username,
        "password": password,
        "notes": notes,
    }
    plaintext_bytes = json.dumps(payload_dict)


    # 2. Generate a unique item UUID (also serves as Associated Data)
    item_id = str(uuid.uuid4())

    # 3. Encrypt locally
    encrypted_data = encrypt_vault_item(
        mek=mek,
        item_id=item_id,
        plaintext=plaintext_bytes,
    )

    # 4. Upload pre-encrypted payload to backend
    try:
        with console.status("[bold green]Uploading encrypted entry...[/bold green]"):
            api.create_vault_item(
                item_id=item_id,
                nonce_b64=encrypted_data["nonce"],
                ciphertext_b64=encrypted_data["ciphertext"],
                auth_tag_b64=encrypted_data["auth_tag"],
            )
        console.print(
            f"[bold green]✓ Item '{title}' successfully encrypted and stored! (ID: {item_id})[/bold green]\n"
        )
    except httpx.HTTPStatusError as e:
        console.print(
            f"[bold red]Failed to save item ({e.response.status_code}): {e.response.text}[/bold red]"
        )


def _handle_delete_vault_item(api: ApiClient, item_id: str) -> None:
    """Requests backend deletion of a vault record by UUID."""
    confirm = typer.confirm(f"Are you sure you want to permanently delete item {item_id}?")
    if not confirm:
        console.print("[dim]Deletion cancelled.[/dim]")
        return

    try:
        with console.status("[bold red]Deleting item...[/bold red]"):
            api.delete_vault_item(item_id=item_id)
        console.print(f"[bold green]✓ Item {item_id} deleted successfully.[/bold green]\n")
    except httpx.HTTPStatusError as e:
        console.print(
            f"[bold red]Failed to delete item ({e.response.status_code}): {e.response.text}[/bold red]"
        )


def _print_help_table() -> None:
    """Displays available interactive commands."""
    table = Table(title="Available Interactive Commands", show_header=True)
    table.add_column("Command", style="bold cyan")
    table.add_column("Description", style="white")
    table.add_row("list", "Fetch and decrypt all vault items")
    table.add_row("add", "Prompt for credentials, encrypt locally, and store")
    table.add_row("delete <id>", "Delete an item permanently by its UUID")
    table.add_row("help", "Show this list of commands")
    table.add_row("exit / quit", "Purge keys from RAM and exit the application")
    console.print(table)
    console.print()


if __name__ == "__main__":
    app()