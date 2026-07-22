from __future__ import annotations

from rich.console import Console


console = Console()


def warn(message: str) -> None:
    console.print(f"[yellow]WARNING[/yellow] {message}")


def ok(message: str) -> None:
    console.print(f"[green]OK[/green] {message}")


def info(message: str) -> None:
    console.print(f"[cyan]INFO[/cyan] {message}")


def fail(message: str) -> None:
    console.print(f"[red]FAIL[/red] {message}")
