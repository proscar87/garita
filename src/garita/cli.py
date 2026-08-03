#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
El punto de entrada. Sirve para las tres formas de usar Garita:

    garita                       revisa todo el repositorio
    garita archivo1 archivo2     revisa archivos concretos (hook de pre-commit)
    garita --explicar            dice qué revisa y con qué configuración

POR QUÉ ADMITE ARCHIVOS SUELTOS

El framework `pre-commit` invoca el hook con la lista de archivos en
preparación. Poder revisar sólo esos es lo que hace viable bloquear ANTES
de que el dato entre al historial — que es el único momento en que el
arreglo es barato. Si sólo se revisa en el push, cuando falla el dato ya
está en un commit y hay que reescribir historia.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .config import Config, ConfigInvalida, cargar as cargar_config
from .detectores import construir
from .fuentes import FuenteInvalida
from .nucleo import revisar
from .reporte import anotaciones_github, imprimir, resumen_markdown


def raiz_repo(desde: Path) -> Path:
    import subprocess
    try:
        salida = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=desde, capture_output=True, check=True,
        ).stdout.decode().strip()
        return Path(salida)
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise SystemExit(
            "Garita revisa lo que git rastrea, así que necesita correr dentro "
            "de un repositorio. No encontré uno aquí."
        )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="garita",
        description="Impide que datos personales y credenciales entren al "
                    "repositorio.",
    )
    p.add_argument("archivos", nargs="*",
                   help="archivos a revisar; sin argumentos, todo el repositorio")
    p.add_argument("--config", metavar="RUTA",
                   help="ruta del .garita.yml (por omisión, la raíz del repo)")
    p.add_argument("--explicar", action="store_true",
                   help="muestra qué se va a revisar y con qué configuración, "
                        "sin revisar")
    p.add_argument("--sin-color", action="store_true")
    p.add_argument("--version", action="version", version=f"garita {__version__}")
    args = p.parse_args(argv)

    raiz = raiz_repo(Path.cwd())

    try:
        cfg = cargar_config(Path(args.config).parent if args.config else raiz)
    except ConfigInvalida as e:
        print(f"Garita: configuración inválida.\n  {e}", file=sys.stderr)
        return 2

    try:
        detectores = construir(cfg, raiz)
    except FuenteInvalida as e:
        # Falla ruidosa y con código propio: un guardián que no pudo cargar su
        # lista NO debe aprobar. Aprobar por no poder revisar es la peor
        # respuesta posible, porque produce confianza sin respaldo.
        print(f"Garita: no pude cargar la lista de nombres a proteger.\n"
              f"  {e}\n"
              f"  No se continúa: revisar a medias y decir «OK» es peor que "
              f"no revisar.", file=sys.stderr)
        return 2

    if args.explicar:
        return _explicar(cfg, detectores, raiz)

    res = revisar(
        raiz, detectores, cfg.exenciones,
        archivos=args.archivos or None,
    )

    imprimir(res)
    anotaciones_github(res)

    resumen = os.environ.get("GITHUB_STEP_SUMMARY")
    if resumen:
        with open(resumen, "a", encoding="utf-8") as f:
            f.write(resumen_markdown(res))

    if res.errores:
        return 1
    if res.avisos and cfg.fallar_en_aviso:
        return 1
    return 0


def _explicar(cfg: Config, detectores, raiz: Path) -> int:
    """Qué se va a revisar. Existe porque «¿esto qué revisa?» es la primera
    pregunta de quien lo adopta, y leer el código para responderla es una
    barrera de entrada innecesaria."""
    print(f"Garita {__version__} — {raiz}\n")
    print("Detectores activos:")
    for d in detectores:
        print(f"  · {d.nombre:<22} {d.descripcion}")
    apagados = [k for k, v in cfg.detectores.items() if not v]
    if apagados:
        print(f"\nApagados en la configuración: {', '.join(apagados)}")
    if cfg.fuentes_nombres:
        print("\nLista de nombres, leída de:")
        for f in cfg.fuentes_nombres:
            print(f"  · {f}")
    else:
        print("\nSin lista de nombres configurada — ese detector queda apagado.")
        print("  Para activarlo, en .garita.yml:")
        print("    nombres:")
        print("      - scripts/generar_datos_sinteticos.py:PROHIBIDOS")
    if cfg.exenciones:
        print("\nExenciones declaradas:")
        for e in cfg.exenciones:
            ambito = ", ".join(e.detectores) if e.detectores else "todos"
            print(f"  · {e.patron}  [{ambito}]")
            print(f"      {e.motivo}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
