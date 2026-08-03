#!/usr/bin/env python3
"""Envoltorio de la Action: prepara el entorno y llama a la CLI."""
import os
import subprocess
import sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(AQUI / "src"))

from garita.cli import main   # noqa: E402


def archivos_del_pr(entorno=os.environ) -> list[str]:
    """Los archivos que toca el pull request.

    Advertencia que la documentación repite: revisar sólo lo que cambió es
    rápido pero ciego a lo que ya estaba. Sirve para dar respuesta veloz en
    cada pull request, no para sustituir una revisión completa.

    `--diff-filter=ACMR`: la R es la que hace que un archivo renombrado se
    reporte por su ruta NUEVA, que es donde hay que revisarlo. Los borrados
    (D) no aparecen: no se puede revisar lo que ya no está.
    """
    base = entorno.get("GITHUB_BASE_REF")
    if not base:
        return []
    subprocess.run(["git", "fetch", "--depth=1", "origin", base],
                   check=False, capture_output=True)
    r = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", f"origin/{base}...HEAD"],
        capture_output=True, text=True,
    )
    return [f for f in r.stdout.splitlines() if f.strip()]


def argumentos(entorno=os.environ) -> list[str]:
    argv = []
    # El input `config` de la Action se exportaba y nunca se leía: la opción
    # documentada era inoperante.
    cfg = entorno.get("GARITA_CONFIG", "").strip()
    if cfg and cfg != ".garita.yml":
        argv += ["--config", cfg]
    if entorno.get("GARITA_SOLO_CAMBIOS", "").lower() == "true":
        cambios = archivos_del_pr(entorno)
        if cambios:
            # += y no =: asignar pisaba el --config ya acumulado, y la
            # opción volvía a ser inoperante — ahora sólo en modo
            # solo-cambios, que es más difícil de notar.
            argv += cambios
        else:
            print("Garita: no pude determinar los archivos del pull request; "
                  "reviso el repositorio completo.")
    return argv


if __name__ == "__main__":
    sys.exit(main(argumentos()))
