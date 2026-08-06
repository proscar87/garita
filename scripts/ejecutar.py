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

    `--diff-filter=ACMRT`: la R es la que hace que un archivo renombrado se
    reporte por su ruta NUEVA, que es donde hay que revisarlo. La T cubre el
    cambio de tipo —un symlink que pasa a ser archivo regular—, que trae
    contenido nuevo como cualquier otro; sin ella ese archivo no se revisaba
    y el PR salía en verde. Los borrados (D) no aparecen: no se puede
    revisar lo que ya no está.

    `-z`: los nombres se leen separados por NUL. Sin esto git cita los que
    llevan acentos o ñ —«"se\\303\\261ales.csv"»— y esa cadena literal
    llegaba a la CLI, que respondía «no existe el archivo» con código 2:
    en una herramienta escrita para equipos hispanohablantes, un PR
    legítimo fallaba entero sin revisar ni un archivo.
    """
    base = entorno.get("GITHUB_BASE_REF")
    if not base:
        return []
    # SIN `--depth=1`: eso escribía `.git/shallow` sobre un clon que se pidió
    # completo, destruía el merge-base —con lo que este diff se quedaba
    # vacío y `solo-cambios` caía SIEMPRE al escaneo completo— y dejaba el
    # workspace somero, así que un `--historial` posterior en el mismo job
    # salía con 2. La refspec explícita actualiza la ref remota sin tocar la
    # profundidad.
    subprocess.run(
        ["git", "fetch", "origin", f"+{base}:refs/remotes/origin/{base}"],
        check=False, capture_output=True)
    r = subprocess.run(
        ["git", "diff", "-z", "--name-only", "--diff-filter=ACMRT",
         f"origin/{base}...HEAD"],
        capture_output=True, text=True,
    )
    return [f for f in r.stdout.split("\0") if f.strip()]


def argumentos(entorno=os.environ) -> list[str]:
    argv = []
    # El input `config` de la Action se exportaba y nunca se leía: la opción
    # documentada era inoperante.
    #
    # Y la cadena VACÍA no es «no lo pidió»: es `config: ${{ vars.X }}` con
    # la variable sin definir, el descuido ordinario en CI. Tragárselo hacía
    # correr con la configuración por omisión —sin la lista de nombres, sin
    # exenciones, sin `paises`— y aprobar con 0 un repo con el padrón a la
    # vista. La CLI ya rechaza `--config ""` con código 2; aquí no se puede
    # ser más laxo, porque ésta es la superficie que más se usa.
    # `action.yml` SIEMPRE exporta la variable, así que ausente significa
    # «me están corriendo fuera de la Action» y vacía significa «el input
    # llegó vacío».
    crudo = entorno.get("GARITA_CONFIG")
    cfg = (crudo or "").strip()
    if crudo is not None and not cfg:
        print("Garita: el input «config» está vacío (¿una variable sin "
              "definir en el workflow?). No se continúa con otra "
              "configuración de la que se pidió.", file=sys.stderr)
        raise SystemExit(2)
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
