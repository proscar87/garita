#!/usr/bin/env python3
"""Envoltorio de la Action: prepara el entorno y llama a la CLI."""
import os
import subprocess
import sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(AQUI / "src"))

from garita.cli import main   # noqa: E402


def archivos_del_pr() -> list[str]:
    """Los archivos que toca el pull request.

    Advertencia que la documentación repite: revisar sólo lo que cambió es
    rápido pero ciego a lo que ya estaba. Sirve para dar respuesta veloz en
    cada pull request, no para sustituir una revisión completa.
    """
    base = os.environ.get("GITHUB_BASE_REF")
    if not base:
        return []
    subprocess.run(["git", "fetch", "--depth=1", "origin", base],
                   check=False, capture_output=True)
    r = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", f"origin/{base}...HEAD"],
        capture_output=True, text=True,
    )
    return [f for f in r.stdout.splitlines() if f.strip()]


if __name__ == "__main__":
    argv = []
    if os.environ.get("GARITA_SOLO_CAMBIOS", "").lower() == "true":
        cambios = archivos_del_pr()
        if cambios:
            argv = cambios
        else:
            print("Garita: no pude determinar los archivos del pull request; "
                  "reviso el repositorio completo.")
    sys.exit(main(argv))
