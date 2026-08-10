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
import json
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
from .historial import es_somero, revisar_historial
from .nucleo import revisar
from .reporte import (
    anotaciones_github, imprimir, imprimir_historial, resumen_markdown,
    resumen_markdown_historial,
)
from .reporte_html import (
    generar as generar_html,
    generar_historial as generar_html_historial,
)
from .sarif import (
    generar as generar_sarif,
    generar_historial as generar_sarif_historial,
)


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
    p.add_argument("--proponer-exenciones", action="store_true",
                   help="escribe el bloque de exenciones para lo que se "
                        "encontró, con el motivo EN BLANCO para que lo "
                        "llenes; sin motivo Garita no corre")
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
    p.add_argument("--historial", action="store_true",
                   help="revisa TODAS las versiones de TODOS los archivos "
                        "que han pasado por el repositorio, no sólo las "
                        "actuales — un secreto «borrado» sigue en git")
    p.add_argument("--formato", choices=("humano", "sarif", "html"),
                   default="humano",
                   help="sarif es lo que GitHub ingiere como alertas de code "
                        "scanning; html es un reporte gráfico autocontenido, "
                        "para entregar (por omisión, humano)")
    p.add_argument("--salida", metavar="RUTA",
                   help="con --formato sarif o html, escribe el documento "
                        "ahí en vez de stdout")
    p.add_argument("--sin-color", action="store_true",
                   help="reporte sin colores ANSI aunque la salida sea una "
                        "terminal")
    p.add_argument("--version", action="version", version=f"garita {__version__}")
    args = p.parse_args(argv)

    # El caso ordinario en CI: `--bandera "$RUTA"` con la variable sin
    # definir. La cadena vacía se trataba como bandera ausente, y Garita
    # corría con otra cosa de la que se le pidió —el documento a stdout, la
    # configuración por omisión, la línea base por omisión— aprobando con 0.
    # Es lo mismo que la guardia de --config inexistente declara
    # inaceptable: correr con otra configuración de la que se pidió es peor
    # que no correr.
    for bandera, valor in (("--salida", args.salida),
                           ("--config", args.config),
                           ("--linea-base-ruta", args.linea_base_ruta)):
        if valor == "":
            print(f"Garita: {bandera} está vacía (¿una variable sin definir "
                  f"en el workflow?). No se continúa con otra cosa de la que "
                  f"se pidió.", file=sys.stderr)
            return 2

    if args.salida and args.formato == "humano":
        # Callar el reporte humano hacia un archivo no tiene caso de uso;
        # aceptar la bandera y sorprender después es peor que rechazarla.
        print("Garita: --salida sólo aplica con --formato sarif o html.",
              file=sys.stderr)
        return 2

    if args.proponer_exenciones and (args.formato != "humano" or args.salida
                                     or args.explicar or args.linea_base
                                     or args.historial):
        print("Garita: --proponer-exenciones escribe un bloque de YAML para "
              "pegar; no produce documento ni se combina con los otros modos.",
              file=sys.stderr)
        return 2

    if (args.explicar or args.linea_base) and (args.formato != "humano"
                                               or args.salida):
        # Aceptar la bandera y no obedecerla es mentir dos veces: quien pide
        # SARIF de --linea-base recibiría una congelación sin documento y
        # esperaría un archivo que nunca se escribió.
        que = "--explicar" if args.explicar else "--linea-base"
        print(f"Garita: --formato/--salida no aplican con {que}; ese modo "
              f"no produce documento.", file=sys.stderr)
        return 2

    if args.explicar and (args.linea_base or args.sin_linea_base
                          or args.linea_base_ruta or args.historial
                          or args.archivos):
        # La misma mentira que la guardia de arriba: `--explicar` retornaba
        # antes que todo, así que `--linea-base --explicar` salía 0 sin
        # congelar nada y `--explicar archivo.py` salía 0 sin revisarlo.
        # Quien automatiza lee ese 0 como «hecho y limpio».
        print("Garita: --explicar sólo explica; combinarlo con --historial, "
              "la línea base o archivos aceptaría una orden que no se va a "
              "cumplir.", file=sys.stderr)
        return 2

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

    listas_ausentes: list[str] = []
    try:
        detectores = construir(cfg, raiz, listas_ausentes)
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

    # Una lista opcional ausente se DICE, siempre y por stderr: revisar de
    # menos en silencio es una marca verde sin revisión. Va a stderr porque
    # stdout puede ser un documento (SARIF, HTML) y no se le mezcla nada.
    for ausente in listas_ausentes:
        print(f"Garita: la lista opcional «{ausente}» no está en esta "
              f"máquina; el detector que depende de ella no corre aquí.",
              file=sys.stderr)

    if args.explicar:
        return _explicar(cfg, detectores, raiz)

    if args.historial:
        return _historial(args, cfg, detectores, raiz)

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

    if args.archivos:
        # Las rutas se verifican ANTES de revisar. Un nombre mal tecleado en
        # la config del hook se contaba como «omitido» y Garita aprobaba con
        # 0 — una marca verde sin revisión, el peor modo de falla. Se
        # resuelven contra el directorio actual (pre-commit invoca desde la
        # raíz; un humano, desde donde esté) y se relativizan a la raíz del
        # repositorio, que es el idioma de las exenciones y la línea base.
        raiz_real = raiz.resolve()
        normalizados: list[str] = []
        for pedido in args.archivos:
            # Se resuelve el directorio, NUNCA el componente final:
            # `resolve()` completo sigue los enlaces simbólicos, y un
            # symlink rastreado que apunte fuera del repo «quedaba fuera
            # del repositorio» — el commit se bloqueaba con 2 mientras el
            # repo completo pasaba con 0. El enlace es del repo aunque su
            # destino no lo sea; se revisa (o se omite diciéndolo) igual
            # que en el modo completo.
            p = Path(pedido)
            ruta = p.parent.resolve() / p.name
            try:
                rel = ruta.relative_to(raiz_real)
            except ValueError:
                print(f"Garita: «{pedido}» queda fuera del repositorio "
                      f"({raiz}). Sus hallazgos escaparían a las exenciones "
                      f"y a la línea base, que hablan en rutas del repo.",
                      file=sys.stderr)
                return 2
            if not (ruta.is_file() or ruta.is_symlink()):
                print(f"Garita: no existe el archivo «{pedido}». No se "
                      f"omite en silencio: aprobar sin revisar lo que se "
                      f"pidió es una marca verde sin revisión.",
                      file=sys.stderr)
                return 2
            normalizados.append(rel.as_posix())
        args.archivos = normalizados

    res = revisar(
        raiz, detectores, cfg.exenciones,
        archivos=args.archivos or None,
    )

    if args.proponer_exenciones:
        return _proponer_exenciones(res, raiz)

    if base is not None:
        nuevos, conocidos = base.filtrar(res.hallazgos)
        # Sobre archivos sueltos (pre-commit) no se acusa deuda pagada: las
        # entradas de los archivos que no se revisaron parecerían pagadas
        # sin estarlo.
        pagadas = base.obsoletas(res.hallazgos) if not args.archivos else []
    else:
        nuevos, conocidos, pagadas = list(res.hallazgos), [], []

    if args.formato == "sarif":
        documento = json.dumps(generar_sarif(res, detectores,
                                             conocidos=conocidos, cfg=cfg),
                               indent=2, ensure_ascii=False) + "\n"
    elif args.formato == "html":
        documento = generar_html(
            res, raiz=raiz.name, fecha=date.today().isoformat(),
            base=base, nuevos=nuevos, conocidos=conocidos, pagadas=pagadas,
            cfg=cfg)
    else:
        documento = None

    if documento is not None:
        if args.salida:
            if not _escribir_documento(args.salida, documento):
                return 2
            # El documento ya quedó en su archivo; la consola sigue siendo
            # para humanos.
            imprimir(res, base=base, nuevos=nuevos, conocidos=conocidos,
                     pagadas=pagadas, sin_color=args.sin_color, cfg=cfg)
            anotaciones_github(res, conocidos=conocidos)
        else:
            # stdout ES el documento: cualquier otra cosa ahí —reporte,
            # anotaciones— lo corrompería.
            sys.stdout.write(documento)
    else:
        imprimir(res, base=base, nuevos=nuevos, conocidos=conocidos,
                 pagadas=pagadas, sin_color=args.sin_color, cfg=cfg)
        anotaciones_github(res, conocidos=conocidos)

    resumen = os.environ.get("GITHUB_STEP_SUMMARY")
    if resumen and not _anexar(resumen, resumen_markdown(
            res, base=base, nuevos=nuevos, conocidos=conocidos, cfg=cfg)):
        return 2
    if not _salida_de_action(len(nuevos)):
        return 2

    # Un archivo que git rastrea y no se pudo abrir es error de ENTORNO,
    # no un hallazgo: código 2, y nunca 0. La misma regla que la lista de
    # nombres que no carga — un guardián que no pudo revisar no aprueba.
    if res.ilegibles:
        return 2

    # Sólo lo nuevo decide el código de salida; la deuda aceptada ya se
    # imprimió aparte y no reprueba.
    if any(h.severidad == "error" for h in nuevos):
        return 1
    if cfg.fallar_en_aviso and any(h.severidad == "aviso" for h in nuevos):
        return 1
    return 0


def _guardar_linea_base(base, ruta_lb: Path) -> bool:
    """Escribe la línea base; si no se puede, se DICE y es código 2.

    `--linea-base-ruta` a un directorio inexistente tronaba con traceback y
    código 1 — el reservado a «hay hallazgos»—, la misma clase que
    `_escribir_documento` ya cerró para `--salida`."""
    try:
        guardar_linea_base(base, ruta_lb)
        return True
    except OSError as e:
        print(f"Garita: no pude escribir la línea base «{ruta_lb}»: "
              f"{e.strerror or e}.", file=sys.stderr)
        return False


def _escribir_documento(ruta: str, documento: str) -> bool:
    """Escribe el documento pedido; si no se puede, se DICE y es código 2.

    Sin esto, un directorio inexistente en --salida tronaba con traceback y
    código 1 — el reservado para «hay hallazgos» — y mandaba a alguien a
    buscar un dato personal que no existe."""
    try:
        Path(ruta).write_text(documento, encoding="utf-8")
        return True
    except OSError as e:
        print(f"Garita: no pude escribir --salida «{ruta}»: "
              f"{e.strerror or e}.", file=sys.stderr)
        return False


def _anexar(ruta: str, texto: str) -> bool:
    """El espejo de `_escribir_documento` para las escrituras en anexar.

    GITHUB_OUTPUT y GITHUB_STEP_SUMMARY vienen del entorno: una ruta
    heredada y rota (contenedor de sólo lectura, disco lleno) tronaba con
    traceback y código 1 —el reservado para «hay hallazgos»— sobre un repo
    limpio, después de haberlo revisado."""
    try:
        with open(ruta, "a", encoding="utf-8") as f:
            f.write(texto)
        return True
    except OSError as e:
        print(f"Garita: no pude escribir «{ruta}»: {e.strerror or e}.",
              file=sys.stderr)
        return False


def _salida_de_action(hallazgos: int) -> bool:
    """La salida `hallazgos` que la Action declara. Vive aquí y no en el
    envoltorio de la Action porque el conteo vive aquí: el envoltorio sólo
    ve el código de salida, y una salida documentada que siempre llega
    vacía es una opción inoperante — la clase de bug que ya se pagó una
    vez con el input `config`."""
    destino = os.environ.get("GITHUB_OUTPUT")
    if destino:
        return _anexar(destino, f"hallazgos={hallazgos}\n")
    return True


def _historial(args, cfg, detectores, raiz: Path) -> int:
    """El modo auditoría: todo lo que git recuerda, no sólo lo que muestra.

    Es un comando aparte y no el modo normal a propósito: recorre todas las
    versiones de todos los archivos, tarda lo que eso tarda, y su veredicto
    no depende de la línea base — una auditoría que perdona no es una
    auditoría."""
    if args.archivos:
        print("Garita: --historial revisa el repositorio completo; no "
              "admite archivos sueltos.", file=sys.stderr)
        return 2
    if args.linea_base or args.sin_linea_base or args.linea_base_ruta:
        print("Garita: la línea base no aplica al historial. La deuda "
              "aceptada congela el PRESENTE; la auditoría del pasado no "
              "perdona, porque perdonar ahí es no auditar.", file=sys.stderr)
        return 2
    if es_somero(raiz):
        # El default de actions/checkout es --depth 1: el entorno MÁS
        # probable de la auditoría es justo donde git no trae la historia.
        # Auditar lo poco visible y decir «limpio» es peor que no auditar.
        print("Garita: este clon es somero (shallow) y git no trae el "
              "historial completo; un secreto borrado hace meses sería "
              "invisible y el «limpio» sería mentira. Trae la historia "
              "entera antes de auditar:\n"
              "  git fetch --unshallow\n"
              "  (en GitHub Actions: fetch-depth: 0 en actions/checkout)",
              file=sys.stderr)
        return 2
    res = revisar_historial(raiz, detectores, cfg.exenciones)

    if args.formato == "sarif":
        documento = json.dumps(generar_sarif_historial(res, detectores),
                               indent=2, ensure_ascii=False) + "\n"
    elif args.formato == "html":
        # El entregable: la auditoría del pasado es justo lo que se anexa a
        # un informe para alguien que no vive en la terminal.
        documento = generar_html_historial(
            res, raiz=raiz.name, fecha=date.today().isoformat())
    else:
        documento = None

    if documento is not None:
        if args.salida:
            if not _escribir_documento(args.salida, documento):
                return 2
            imprimir_historial(res, sin_color=args.sin_color)
        else:
            sys.stdout.write(documento)
    else:
        imprimir_historial(res, sin_color=args.sin_color)

    # El panel del job, que a `--historial` le faltaba. Es el modo de la
    # auditoría programada: el que corre solo y cuyo resultado nadie va a
    # buscar a los registros. Sin esto el panel salía vacío y la auditoría
    # parecía no haber corrido.
    resumen = os.environ.get("GITHUB_STEP_SUMMARY")
    if resumen and not _anexar(resumen, resumen_markdown_historial(res)):
        return 2
    if not _salida_de_action(len(res.hallazgos)):
        return 2
    if res.errores:
        return 1
    if res.avisos and cfg.fallar_en_aviso:
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
            # Se BORRA, no se sugiere borrar. Dejarlo era un no-op con
            # código 0 sobre el comando que la propia herramienta manda
            # usar para regenerar: la base vieja seguía en disco
            # perdonando hallazgos que aparecieran después.
            try:
                ruta_lb.unlink()
            except OSError as e:
                print(f"Garita: no pude borrar «{ruta_lb}»: "
                      f"{e.strerror or e}.", file=sys.stderr)
                return 2
            print(f"  «{ruta_lb.name}» tenía deuda ya pagada y se borró: "
                  f"si se quedaba, seguiría perdonando lo que llegue "
                  f"después.")
        return 0

    if not _guardar_linea_base(base, ruta_lb):
        return 2
    # El tamaño se dice siempre: alguien tiene que ver cuánto acaba de
    # aceptar.
    print(f"Garita: {base.total} hallazgo{'s' if base.total != 1 else ''} "
          f"congelado{'s' if base.total != 1 else ''} en «{ruta_lb.name}» "
          f"como deuda aceptada.")
    print("  Esto detiene la sangría, no paga la deuda. Commitea el archivo "
          "y achícalo conforme limpies.")
    return 0


def _proponer_exenciones(res, raiz: Path) -> int:
    """El bloque de exenciones para lo que se acaba de encontrar, listo
    para pegar — y con el motivo EN BLANCO.

    Existe porque el reporte decía «exenta el archivo con su motivo» sin
    decir cómo, y escribir YAML de memoria es la clase de fricción que
    termina en «mejor apago el paso». El esqueleto no puede abrir un
    agujero en silencio: `cargar()` rechaza con código 2 la exención sin
    motivo, así que pegarlo y no llenarlo DETIENE a Garita en vez de
    callarla. Quien lo llena está escribiendo la justificación que dentro
    de un año permitirá evaluar si sigue valiendo.

    NO se imprime ningún valor: el bloque nombra archivo y detectores, que
    es lo que la exención necesita.
    """
    if not res.hallazgos:
        print("Garita: nada que exentar — no se encontró nada.")
        return 0

    por_archivo: dict[str, set] = {}
    for h in res.hallazgos:
        por_archivo.setdefault(h.archivo, set()).add(h.detector)

    print("# Pega esto en .garita.yml y ESCRIBE CADA MOTIVO.")
    print("# Garita no corre con un motivo en blanco: es código 2, a")
    print("# propósito. Una lista de exenciones sin razones se convierte,")
    print("# en pocos meses, en la lista de archivos que nadie se atreve a")
    print("# tocar porque nadie sabe por qué están ahí.")
    print("#")
    print("# Y antes de exentar, pregúntate si el dato debería estar ahí:")
    print("# la exención es para lo que SÍ va (un catálogo público, un")
    print("# vector de prueba oficial), no para lo que estorba.")
    print("exenciones:")
    for archivo in sorted(por_archivo):
        dets = ", ".join(sorted(por_archivo[archivo]))
        # Un archivo de la RAÍZ se nombra anclado. Sin la barra inicial el
        # patrón no tiene «/», y eso casa el NOMBRE a cualquier profundidad:
        # la exención propuesta salía más ancha que el hallazgo que la
        # produjo y tapaba en silencio un homónimo de cualquier subcarpeta,
        # hoy o el día que alguien lo agregue. Lo que la herramienta propone
        # nunca puede exentar más de lo que encontró.
        patron = archivo if "/" in archivo else f"/{archivo}"
        print(f"  - archivo: {patron}")
        print(f"    motivo:")
        print(f"    detectores: {dets}")
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
    if cfg.fuentes_clientes:
        print("\nLista de clientes, leída de:")
        for f in cfg.fuentes_clientes:
            print(f"  · {f}")
    if cfg.exenciones:
        print("\nExenciones declaradas:")
        for e in cfg.exenciones:
            ambito = ", ".join(e.detectores) if e.detectores else "todos"
            print(f"  · {e.patron}  [{ambito}]")
            print(f"      {e.motivo}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
