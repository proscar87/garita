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
from datetime import date
from pathlib import Path

from . import __version__
from .config import Config, ConfigInvalida, cargar as cargar_config
from .detectores import construir
from .fuentes import FuenteInvalida
from .linea_base import (
    LineaBaseInvalida, NOMBRE_POR_OMISION,
    cargar as cargar_linea_base,
    construir as construir_linea_base,
    guardar as guardar_linea_base,
)
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
        # Código 2, no 1: no encontrar un repositorio es un problema de
        # entorno, y confundirlo con un hallazgo manda a alguien a buscar un
        # dato personal que no existe.
        print("Garita revisa lo que git rastrea, así que necesita correr "
              "dentro de un repositorio. No encontré uno aquí.",
              file=sys.stderr)
        raise SystemExit(2)


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
    lb = p.add_mutually_exclusive_group()
    lb.add_argument("--linea-base", action="store_true",
                    help="congela los hallazgos actuales como deuda aceptada; "
                         "las corridas siguientes fallan sólo con lo nuevo")
    lb.add_argument("--sin-linea-base", action="store_true",
                    help="ignora la línea base aunque exista, para auditar "
                         "de verdad")
    p.add_argument("--linea-base-ruta", metavar="RUTA",
                   help=f"dónde vive la línea base (por omisión, "
                        f"{NOMBRE_POR_OMISION} en la raíz del repositorio)")
    p.add_argument("--sin-color", action="store_true")
    p.add_argument("--version", action="version", version=f"garita {__version__}")
    args = p.parse_args(argv)

    raiz = raiz_repo(Path.cwd())

    try:
        if args.config:
            ruta_cfg = Path(args.config)
            if not ruta_cfg.is_file():
                print(f"Garita: no existe el archivo de configuración "
                      f"«{args.config}». No se continúa con los valores por "
                      f"omisión: correr con otra configuración de la que se "
                      f"pidió es peor que no correr.", file=sys.stderr)
                return 2
            cfg = cargar_config(ruta_cfg.parent, nombre=ruta_cfg.name)
        else:
            cfg = cargar_config(raiz)
    except ConfigInvalida as e:
        print(f"Garita: configuración inválida.\n  {e}", file=sys.stderr)
        return 2

    try:
        detectores = construir(cfg, raiz)
    except ValueError as e:
        # Un país inexistente es un error de configuración, no un hallazgo.
        # Salir con 1 haría que el equipo buscara un dato personal que no
        # existe.
        print(f"Garita: {e}", file=sys.stderr)
        return 2
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

    ruta_lb = (Path(args.linea_base_ruta) if args.linea_base_ruta
               else raiz / NOMBRE_POR_OMISION)

    if args.linea_base:
        return _congelar(args, cfg, detectores, raiz, ruta_lb)

    base = None
    if not args.sin_linea_base:
        if args.linea_base_ruta and not ruta_lb.is_file():
            # Igual que con --config: correr sin la línea base que se pidió
            # marcaría en rojo toda la deuda ya aceptada, y ese reporte
            # inservible se atendería como si fuera cierto.
            print(f"Garita: no existe la línea base «{args.linea_base_ruta}». "
                  f"No se continúa sin ella.", file=sys.stderr)
            return 2
        try:
            base = cargar_linea_base(ruta_lb)
        except LineaBaseInvalida as e:
            # Código 2, nunca 1 y nunca seguir: sin ella todo lo aceptado
            # saldría en rojo; con la que se creyó leer, lo nuevo saldría
            # aprobado. Ninguna de las dos se vale.
            print(f"Garita: la línea base existe pero no se pudo usar.\n"
                  f"  {e}", file=sys.stderr)
            return 2

    res = revisar(
        raiz, detectores, cfg.exenciones,
        archivos=args.archivos or None,
    )

    if base is not None:
        nuevos, conocidos = base.filtrar(res.hallazgos)
        # Sobre archivos sueltos (pre-commit) no se acusa deuda pagada: las
        # entradas de los archivos que no se revisaron parecerían pagadas
        # sin estarlo.
        pagadas = base.obsoletas(res.hallazgos) if not args.archivos else []
    else:
        nuevos, conocidos, pagadas = list(res.hallazgos), [], []

    imprimir(res, base=base, nuevos=nuevos, conocidos=conocidos,
             pagadas=pagadas)
    anotaciones_github(res, conocidos=conocidos)

    resumen = os.environ.get("GITHUB_STEP_SUMMARY")
    if resumen:
        with open(resumen, "a", encoding="utf-8") as f:
            f.write(resumen_markdown(res, base=base, nuevos=nuevos,
                                     conocidos=conocidos))

    # Sólo lo nuevo decide el código de salida; la deuda aceptada ya se
    # imprimió aparte y no reprueba.
    if any(h.severidad == "error" for h in nuevos):
        return 1
    if cfg.fallar_en_aviso and any(h.severidad == "aviso" for h in nuevos):
        return 1
    return 0


def _congelar(args, cfg, detectores, raiz: Path, ruta_lb: Path) -> int:
    """Escribe la línea base. Sale 0 aunque haya 400 hallazgos: está
    registrando deuda, no reprobando."""
    if args.archivos:
        print("Garita: --linea-base congela el repositorio completo, no "
              "archivos sueltos. Una línea base parcial perdonaría de menos "
              "y reprobaría deuda que sí se aceptó.", file=sys.stderr)
        return 2

    res = revisar(raiz, detectores, cfg.exenciones)
    base = construir_linea_base(res.hallazgos, fecha=date.today().isoformat())

    if base.total == 0:
        print("Garita: nada que congelar — el repositorio está limpio.")
        if ruta_lb.is_file():
            print(f"  «{ruta_lb.name}» ya existe y toda su deuda está "
                  f"pagada: bórralo.")
        return 0

    guardar_linea_base(base, ruta_lb)
    # El tamaño se dice siempre: alguien tiene que ver cuánto acaba de
    # aceptar.
    print(f"Garita: {base.total} hallazgo{'s' if base.total != 1 else ''} "
          f"congelado{'s' if base.total != 1 else ''} en «{ruta_lb.name}» "
          f"como deuda aceptada.")
    print("  Esto detiene la sangría, no paga la deuda. Commitea el archivo "
          "y achícalo conforme limpies.")
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
