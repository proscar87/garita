#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cómo se cuenta lo que se encontró.

UN REPORTE QUE NO SE PUEDE ACTUAR ES RUIDO

La diferencia entre un guardián que el equipo respeta y uno que aprende a
saltarse casi nunca está en la detección: está en el mensaje. «patrón
prohibido en línea 47» obliga a quien lo lee a investigar qué patrón, por
qué importa y qué se supone que haga. Al tercer mensaje así, alguien
propone desactivar el paso «mientras tanto».

Por eso cada hallazgo se imprime con las tres cosas: QUÉ se encontró, POR
QUÉ importa, y CÓMO se arregla. Cuesta más escribirlo una vez y ahorra la
conversación cada vez.

Y hay una regla que este archivo respeta sin excepción: **nunca se imprime
el valor completo de un secreto**. La salida de una ejecución de CI suele
ser visible para más gente que el propio repositorio, y a menudo se
conserva más tiempo. Volcar ahí la credencial la filtra otra vez, ahora en
un lugar donde nadie la busca.
"""
from __future__ import annotations

import os
import sys
from collections import defaultdict

from .nucleo import Resultado


def _en_github() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _color(activo: bool):
    if not activo:
        return lambda t, _c: t
    codigos = {"rojo": "31", "amarillo": "33", "verde": "32",
               "gris": "90", "negrita": "1"}
    return lambda t, c: f"\033[{codigos.get(c, '0')}m{t}\033[0m"


def imprimir(res: Resultado, salida=sys.stdout) -> None:
    color = _color(salida.isatty() and not _en_github())
    n = color

    # Los archivos que se saltaron por tamaño se dicen SIEMPRE, haya o no
    # hallazgos. Un volcado grande omitido en silencio es una marca verde sin
    # revisión, que es exactamente lo que esta herramienta existe para no
    # producir.
    if res.omitidos_grandes:
        print(file=salida)
        print(n("! Sin revisar por tamaño:", "amarillo"), file=salida)
        for archivo, motivo in res.omitidos_grandes[:10]:
            print(n(f"    {archivo} — {motivo}", "gris"), file=salida)
        if len(res.omitidos_grandes) > 10:
            print(n(f"    …y {len(res.omitidos_grandes) - 10} más", "gris"), file=salida)
        print(n("  Un archivo grande es justo donde cabe un padrón entero. "
                "Revísalos aparte.", "gris"), file=salida)

    if res.exenciones_muertas:
        print(file=salida)
        print(n("! Exenciones que no aplicaron a ningún archivo:", "amarillo"),
              file=salida)
        for patron in res.exenciones_muertas:
            print(n(f"    {patron}", "gris"), file=salida)
        print(n("  El archivo se renombró o se borró. Si se renombró, lleva "
                "revisándose sin exención\n  desde entonces; si se borró, la "
                "regla esconfiguración muerta. Actualiza .garita.yml.", "gris"),
              file=salida)

    if not res.hallazgos:
        print(n("✓ Garita: nada que reportar.", "verde"), file=salida)
        print(n(f"  {res.archivos_revisados} archivos revisados, "
                f"{res.archivos_omitidos} omitidos (binarios o muy grandes).",
                "gris"), file=salida)
        if res.exentos_aplicados:
            total = sum(res.exentos_aplicados.values())
            print(n(f"  {total} revisiones omitidas por exenciones declaradas.",
                    "gris"), file=salida)
        return

    # Agrupado por archivo: quien va a arreglar abre un archivo a la vez, no
    # un detector a la vez.
    por_archivo: dict[str, list] = defaultdict(list)
    for h in res.hallazgos:
        por_archivo[h.archivo].append(h)

    print(file=salida)
    for archivo, hs in sorted(por_archivo.items()):
        print(n(archivo, "negrita"), file=salida)
        for h in sorted(hs, key=lambda x: x.linea):
            marca = "✗" if h.severidad == "error" else "!"
            tono = "rojo" if h.severidad == "error" else "amarillo"
            print(f"  {n(marca, tono)} línea {h.linea}  "
                  f"{n(h.detector, 'negrita')}  {h.que}", file=salida)
            print(f"      {n(h.por_que, 'gris')}", file=salida)
            print(f"      {n('→ ' + h.como_arreglar, 'gris')}", file=salida)
        print(file=salida)

    e, a = len(res.errores), len(res.avisos)
    resumen = []
    if e:
        resumen.append(n(f"{e} error{'es' if e != 1 else ''}", "rojo"))
    if a:
        resumen.append(n(f"{a} aviso{'s' if a != 1 else ''}", "amarillo"))
    print("Garita: " + " · ".join(resumen)
          + n(f"  ({res.archivos_revisados} archivos revisados)", "gris"),
          file=salida)

    if e:
        print(file=salida)
        print(n("Un dato personal o una credencial que llega a un repositorio "
                "no se borra editando el archivo:", "gris"), file=salida)
        print(n("  · Si es una credencial, ROTALA primero. Eso invalida la "
                "copia filtrada; el resto es limpieza.", "gris"), file=salida)
        print(n("  · Si es un dato personal, sácalo del archivo y evalúa si "
                "hay que limpiar el historial.", "gris"), file=salida)
        print(n("  · Si el hallazgo es legítimo, exenta el archivo en "
                ".garita.yml CON SU MOTIVO.", "gris"), file=salida)


def anotaciones_github(res: Resultado, salida=sys.stdout) -> None:
    """Marca las líneas en la interfaz de GitHub.

    Sin esto el hallazgo vive sólo en el registro de la ejecución, que casi
    nadie abre. Con esto aparece sobre la línea exacta en la pestaña de
    archivos del pull request, que es donde la persona ya está mirando.
    """
    if not _en_github():
        return
    for h in res.hallazgos:
        tipo = "error" if h.severidad == "error" else "warning"
        # Los saltos de línea rompen el formato de anotación; van como %0A.
        mensaje = f"{h.por_que} → {h.como_arreglar}".replace("\n", "%0A")
        print(f"::{tipo} file={h.archivo},line={h.linea},"
              f"title=Garita: {h.detector}::{mensaje}", file=salida)


def resumen_markdown(res: Resultado) -> str:
    """Para el resumen del job, que es lo que se ve sin abrir los registros."""
    if not res.hallazgos:
        return (f"## ✅ Garita\n\nNada que reportar. "
                f"{res.archivos_revisados} archivos revisados.\n")

    lineas = ["## 🚧 Garita", ""]
    e, a = len(res.errores), len(res.avisos)
    lineas.append(f"**{e} error{'es' if e != 1 else ''}**"
                  + (f" y {a} aviso{'s' if a != 1 else ''}" if a else "")
                  + f" en {res.archivos_revisados} archivos revisados.")
    lineas += ["", "| Archivo | Línea | Detector | Qué |", "|---|---:|---|---|"]
    for h in res.hallazgos[:50]:
        lineas.append(f"| `{h.archivo}` | {h.linea} | {h.detector} | {h.que} |")
    if len(res.hallazgos) > 50:
        lineas.append(f"| … | | | {len(res.hallazgos) - 50} más |")
    lineas += ["", "Cada hallazgo trae su motivo y su arreglo en el registro "
               "completo de la ejecución."]
    return "\n".join(lineas) + "\n"
