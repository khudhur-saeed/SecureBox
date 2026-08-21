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
            )

            if not command:
                continue

            cmd_lower = command.lower()

            if cmd_lower in ("exit", "quit", "q"):
                console.print(
                    "[bold yellow]Locking vault and purging encryption keys from memory. Goodbye![/bold yellow]"
                )
                break

            elif cmd_lower == "help":
                _print_help_table()

            elif cmd_lower == "list":
                _handle_list_vault(api=api, mek=mek)

            elif cmd_lower == "add":
                _handle_add_vault_item(api=api, mek=mek)

            elif cmd_lower.startswith("update"):
                parts = command.split()
                item_id = parts[1] if len(parts) > 1 else None
                _handle_update_vault_item(api=api, mek=mek, item_id=item_id)

            elif cmd_lower.startswith("delete"):
                parts = command.split()
                if len(parts) < 2:
                    console.print(
                        "[bold red]Usage: delete <item_uuid>[/bold red]"
                    )
                else:
                    _handle_delete_vault_item(api=api, item_id=parts[1])

            elif cmd_lower.startswith("search"):
                parts = command.split(maxsplit=1)
                search_query = parts[1].strip() if len(parts) > 1 else None
                _handle_search_vault(api=api, mek=mek, query=search_query)

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

    payload_dict = {
        "title": title,
        "username": username,
        "password": password,
        "notes": notes,
    }
    plaintext_str = json.dumps(payload_dict)
    item_id = str(uuid.uuid4())

    encrypted_data = encrypt_vault_item(
        mek=mek,
        item_id=item_id,
        plaintext=plaintext_str,
    )

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


def _handle_update_vault_item(api: ApiClient, mek: bytes, item_id: Optional[str] = None) -> None:
    """Fetches an existing item, decrypts it to show current values, prompts for edits, and uploads re-encrypted data."""
    try:
        with console.status("[bold green]Fetching vault items...[/bold green]"):
            raw_items = api.list_vault_items()

        if not raw_items:
            console.print("[yellow]Vault is empty. Nothing to update.[/yellow]\n")
            return

        if not item_id:
            item_id = Prompt.ask("Enter the Item ID to update").strip()

        target_item = next((it for it in raw_items if it["id"] == item_id), None)
        if not target_item:
            console.print(f"[bold red]Error: Item with ID '{item_id}' not found in your vault.[/bold red]\n")
            return

        try:
            plaintext_str = decrypt_vault_item(
                mek=mek,
                item_id=item_id,
                nonce_b64=target_item["nonce"],
                ciphertext_b64=target_item["ciphertext"],
                auth_tag_b64=target_item["auth_tag"],
            )
            current_data = json.loads(plaintext_str)
        except Exception as e:
            console.print(f"[bold red]Decryption failed: {e}[/bold red]\n")
            return

        console.print(f"\n[bold yellow]Editing secret for: {current_data.get('title', 'Untitled')}[/bold yellow]")
        console.print("[dim](Press Enter on any field to keep the current value)[/dim]\n")

        new_title = Prompt.ask("Title", default=current_data.get("title", ""))
        new_username = Prompt.ask("Username / Email", default=current_data.get("username", ""))
        new_password = Prompt.ask("Password", default=current_data.get("password", ""), password=True)
        new_notes = Prompt.ask("Notes", default=current_data.get("notes", ""))

        if not new_title or not new_password:
            console.print("[bold red]Error: Title and password cannot be empty.[/bold red]\n")
            return

        updated_dict = {
            "title": new_title,
            "username": new_username,
            "password": new_password,
            "notes": new_notes,
        }
        updated_plaintext_str = json.dumps(updated_dict)

        # Fresh Nonce generation is handled inside encrypt_vault_item
        encrypted_data = encrypt_vault_item(
            mek=mek,
            item_id=item_id,
            plaintext=updated_plaintext_str,
        )

        with console.status("[bold green]Saving changes to server...[/bold green]"):
            api.update_vault_item(
                item_id=item_id,
                nonce_b64=encrypted_data["nonce"],
                ciphertext_b64=encrypted_data["ciphertext"],
                auth_tag_b64=encrypted_data["auth_tag"],
            )

        console.print(f"[bold green]✓ Successfully updated item '{new_title}' ({item_id})![/bold green]\n")

    except httpx.HTTPStatusError as e:
        console.print(f"[bold red]Failed to update item ({e.response.status_code}): {e.response.text}[/bold red]\n")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]\n")


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
def _handle_search_vault(api: ApiClient, mek: bytes, query: Optional[str] = None) -> None:
    """Fetches encrypted items, decrypts them in RAM, and filters matches locally."""
    try:
    
        if not query:
            query = Prompt.ask("[bold cyan]Enter search term (title, username, or notes)[/bold cyan]").strip()

        if not query:
            console.print("[yellow]Search cancelled (empty query).[/yellow]\n")
            return

        query_lower = query.lower()

       
        with console.status("[bold green]Fetching & decrypting vault items in RAM...[/bold green]"):
            raw_items = api.list_vault_items()

        if not raw_items:
            console.print("[dim]Your vault is empty.[/dim]\n")
            return

        matching_rows = []

     
        for item in raw_items:
            item_id = str(item["id"])
            nonce_b64 = item["nonce"]
            ciphertext_b64 = item["ciphertext"]
            auth_tag_b64 = item["auth_tag"]

            try:
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

                searchable_text = f"{title} {username} {notes}".lower()
                if query_lower in searchable_text:
                    matching_rows.append((item_id, title, username, secret_pwd, notes))

            except Exception:
               
                if query_lower in "decryption failed integrity check failed":
                    matching_rows.append(
                        (item_id, "[bold red]DECRYPTION FAILED[/bold red]", "-", "-", "[red]Integrity check failed[/red]")
                    )

        if not matching_rows:
            console.print(f"[yellow]No matching items found for query:[/yellow] '{query}'\n")
            return

        table = Table(
            title=f"🔍 Search Results for '{query}' ({len(matching_rows)} found)",
            show_lines=True,
            header_style="bold magenta",
        )
        table.add_column("Item ID", style="dim", no_wrap=True)
        table.add_column("Title / Service", style="bold cyan")
        table.add_column("Username / Email", style="green")
        table.add_column("Password", style="yellow")
        table.add_column("Notes", style="dim")

        for row in matching_rows:
            table.add_row(*row)

        console.print(table)
        console.print()

    except httpx.HTTPStatusError as e:
        console.print(
            f"[bold red]Failed to fetch vault items ({e.response.status_code}): {e.response.text}[/bold red]\n"
        )
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]\n")






def _print_help_table() -> None:
    """Displays available interactive commands."""
    table = Table(title="Available Interactive Commands", show_header=True)
    table.add_column("Command", style="bold cyan")
    table.add_column("Description", style="white")
    table.add_row("list", "Fetch and decrypt all vault items")
    table.add_row("add", "Prompt for credentials, encrypt locally, and store")
    table.add_row("update [id]", "Update an existing item with fresh encryption")
    table.add_row("search [query]", "Search vault items in memory by keyword")
    table.add_row("delete <id>", "Delete an item permanently by its UUID")
    table.add_row("help", "Show this list of commands")
    table.add_row("exit / quit", "Purge keys from RAM and exit the application")
    console.print(table)
    console.print()


if __name__ == "__main__":
    app()