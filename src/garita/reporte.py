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


def imprimir(res: Resultado, salida=None, base=None,
             nuevos=None, conocidos=None, pagadas=None) -> None:
    # sys.stdout se resuelve al llamar, no al importar: un default evaluado
    # en el import ignora las redirecciones (contextlib.redirect_stdout).
    salida = salida if salida is not None else sys.stdout
    color = _color(salida.isatty() and not _en_github())
    n = color

    # Sin línea base, todo hallazgo es nuevo y el reporte queda como siempre.
    if nuevos is None:
        nuevos = res.hallazgos
    conocidos = conocidos or []

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

    if not nuevos:
        if conocidos:
            # Todo lo encontrado quedó cubierto por la línea base. Decir
            # «nada que reportar» a secas sería mentir por omisión.
            print(n("✓ Garita: nada nuevo que reportar.", "verde"), file=salida)
        else:
            print(n("✓ Garita: nada que reportar.", "verde"), file=salida)
        print(n(f"  {res.archivos_revisados} archivos revisados, "
                f"{res.archivos_omitidos} omitidos (binarios o muy grandes).",
                "gris"), file=salida)
        if res.exentos_aplicados:
            total = sum(res.exentos_aplicados.values())
            print(n(f"  {total} revisiones omitidas por exenciones declaradas.",
                    "gris"), file=salida)
        _bloque_linea_base(base, conocidos, pagadas, n, salida)
        return

    # Agrupado por archivo: quien va a arreglar abre un archivo a la vez, no
    # un detector a la vez. Sólo lo nuevo; la deuda aceptada va aparte.
    por_archivo: dict[str, list] = defaultdict(list)
    for h in nuevos:
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

    e = sum(1 for h in nuevos if h.severidad == "error")
    a = sum(1 for h in nuevos if h.severidad == "aviso")
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

    _bloque_linea_base(base, conocidos, pagadas, n, salida)


def _meses_desde(fecha_iso: str) -> int | None:
    from datetime import date
    try:
        creada = date.fromisoformat(fecha_iso)
    except ValueError:
        return None
    return (date.today() - creada).days // 30


def _bloque_linea_base(base, conocidos, pagadas, n, salida) -> None:
    """La deuda aceptada no desaparece del reporte: desaparecerla convertiría
    la línea base en una alfombra. Se imprime aparte y en gris, y no decide
    el código de salida.

    `pagadas` la calcula quien sabe si la revisión fue completa: sobre
    archivos sueltos (el hook de pre-commit) las entradas de los archivos no
    revisados parecerían pagadas sin estarlo — la misma trampa que las
    exenciones muertas."""
    if base is None:
        return

    if conocidos:
        print(file=salida)
        print(n(f"Deuda aceptada — línea base del {base.creada}, "
                f"{len(conocidos)} hallazgo"
                f"{'s' if len(conocidos) != 1 else ''}:", "gris"), file=salida)
        for h in conocidos[:20]:
            print(n(f"    {h.archivo} · línea {h.linea} · {h.detector}",
                    "gris"), file=salida)
        if len(conocidos) > 20:
            print(n(f"    …y {len(conocidos) - 20} más (corre con "
                    f"--sin-linea-base para verlos todos)", "gris"),
                  file=salida)

    meses = _meses_desde(base.creada)
    if meses is not None and meses >= 6:
        # Una línea base es una promesa de limpiar después, y las promesas
        # sin fecha no se cumplen. Ésta ya tiene fecha, y ya venció.
        print(n(f"  ! Esta línea base tiene {meses} meses. Ya toca pagar la "
                f"deuda o volver a justificarla.", "amarillo"), file=salida)

    if pagadas:
        print(file=salida)
        print(n("Deuda pagada — entradas de la línea base que ya no "
                "corresponden a nada:", "verde"), file=salida)
        for entrada in pagadas[:10]:
            print(n(f"    {entrada}", "gris"), file=salida)
        if len(pagadas) > 10:
            print(n(f"    …y {len(pagadas) - 10} más", "gris"), file=salida)
        print(n("  Regenera con «garita --linea-base» para achicar el "
                "archivo.", "gris"), file=salida)


def anotaciones_github(res: Resultado, salida=None, conocidos=()) -> None:
    """Marca las líneas en la interfaz de GitHub.

    Sin esto el hallazgo vive sólo en el registro de la ejecución, que casi
    nadie abre. Con esto aparece sobre la línea exacta en la pestaña de
    archivos del pull request, que es donde la persona ya está mirando.
    """
    salida = salida if salida is not None else sys.stdout
    if not _en_github():
        return
    # La deuda aceptada se anota como aviso informativo, no como error: la
    # línea sigue marcada donde la persona ya está mirando, pero sin gritar
    # por algo que el equipo ya aceptó.
    aceptados = {id(h) for h in conocidos}
    for h in res.hallazgos:
        if id(h) in aceptados:
            tipo, detalle = "notice", " (deuda aceptada)"
        else:
            tipo = "error" if h.severidad == "error" else "warning"
            detalle = ""
        # Los saltos de línea rompen el formato de anotación; van como %0A.
        mensaje = f"{h.por_que} → {h.como_arreglar}".replace("\n", "%0A")
        print(f"::{tipo} file={h.archivo},line={h.linea},"
              f"title=Garita: {h.detector}{detalle}::{mensaje}", file=salida)


def resumen_markdown(res: Resultado, base=None, nuevos=None,
                     conocidos=None) -> str:
    """Para el resumen del job, que es lo que se ve sin abrir los registros."""
    if nuevos is None:
        nuevos = res.hallazgos
    conocidos = conocidos or []
    deuda = (f" {len(conocidos)} hallazgo{'s' if len(conocidos) != 1 else ''} "
             f"previo{'s' if len(conocidos) != 1 else ''} en deuda aceptada "
             f"(línea base del {base.creada})." if conocidos else "")

    if not nuevos:
        titulo = "Nada nuevo que reportar." if conocidos else "Nada que reportar."
        return (f"## ✅ Garita\n\n{titulo} "
                f"{res.archivos_revisados} archivos revisados.{deuda}\n")

    lineas = ["## 🚧 Garita", ""]
    e = sum(1 for h in nuevos if h.severidad == "error")
    a = sum(1 for h in nuevos if h.severidad == "aviso")
    lineas.append(f"**{e} error{'es' if e != 1 else ''}**"
                  + (f" y {a} aviso{'s' if a != 1 else ''}" if a else "")
                  + f" en {res.archivos_revisados} archivos revisados."
                  + deuda)
    lineas += ["", "| Archivo | Línea | Detector | Qué |", "|---|---:|---|---|"]
    for h in nuevos[:50]:
        lineas.append(f"| `{h.archivo}` | {h.linea} | {h.detector} | {h.que} |")
    if len(nuevos) > 50:
        lineas.append(f"| … | | | {len(nuevos) - 50} más |")
    lineas += ["", "Cada hallazgo trae su motivo y su arreglo en el registro "
               "completo de la ejecución."]
    return "\n".join(lineas) + "\n"


def imprimir_historial(res, salida=None) -> None:
    """El reporte del historial separa lo que la revisión normal ya ve de lo
    que sólo el historial recuerda, porque el arreglo es distinto: lo vivo
    se arregla editando; lo «borrado» sólo se arregla rotando — y, si se
    decide, reescribiendo historia con respaldo. Decirlos revueltos invita
    a arreglar el que se ve y creer que el otro no existe."""
    salida = salida if salida is not None else sys.stdout
    n = _color(salida.isatty() and not _en_github())

    if res.omitidos_grandes:
        print(file=salida)
        print(n("! Sin revisar por tamaño:", "amarillo"), file=salida)
        for etiqueta, motivo in res.omitidos_grandes[:10]:
            print(n(f"    {etiqueta} — {motivo}", "gris"), file=salida)
        if len(res.omitidos_grandes) > 10:
            print(n(f"    …y {len(res.omitidos_grandes) - 10} más", "gris"),
                  file=salida)

    print(file=salida)
    print(n(f"Historial: {res.blobs_revisados} versiones de archivo "
            f"revisadas en {res.commits} commits "
            f"({res.blobs_omitidos} omitidas: binarias, muy grandes o sin "
            f"datos).", "gris"), file=salida)

    if not res.hallazgos:
        print(n("✓ Garita: el historial está limpio.", "verde"), file=salida)
        return

    muertos = [h for h in res.hallazgos if not h.vivo]
    vivos = [h for h in res.hallazgos if h.vivo]

    def _bloque(titulo, tono, hs):
        print(file=salida)
        print(n(titulo, tono), file=salida)
        for hh in hs:
            h = hh.hallazgo
            marca = "✗" if h.severidad == "error" else "!"
            tono_h = "rojo" if h.severidad == "error" else "amarillo"
            duracion = (f" · en {hh.versiones} versiones del archivo"
                        if hh.versiones > 1 else "")
            print(f"  {n(marca, tono_h)} {n(h.archivo, 'negrita')} · "
                  f"desde el commit {hh.commit} ({hh.fecha}) · línea {h.linea}"
                  f"{duracion}  {n(h.detector, 'negrita')}  {h.que}",
                  file=salida)
            print(f"      {n(h.por_que, 'gris')}", file=salida)

    if muertos:
        _bloque("Sólo en el historial — se borró del árbol, pero git no "
                "olvida (vive en cada clon y cada fork):", "rojo", muertos)
    if vivos:
        _bloque("Todavía en el árbol — la revisión normal también lo ve:",
                "amarillo", vivos)

    e, a = len(res.errores), len(res.avisos)
    resumen = []
    if e:
        resumen.append(n(f"{e} error{'es' if e != 1 else ''}", "rojo"))
    if a:
        resumen.append(n(f"{a} aviso{'s' if a != 1 else ''}", "amarillo"))
    print(file=salida)
    print("Garita: " + " · ".join(resumen) + n(" en el historial", "gris"),
          file=salida)

    if muertos:
        print(file=salida)
        print(n("Borrar el archivo no borró el dato. En orden:", "gris"),
              file=salida)
        print(n("  1. Si es una credencial, RÓTALA HOY. Eso invalida todas "
                "las copias; lo demás es limpieza.", "gris"), file=salida)
        print(n("  2. Si es un dato personal, evalúa si el historial debe "
                "limpiarse (git-filter-repo), CON respaldo previo y "
                "avisando a quien haya clonado. Garita no reescribe "
                "historia: esa decisión es humana.", "gris"), file=salida)
        print(n("  3. Si es legítimo que esté ahí, exenta la ruta en "
                ".garita.yml con su motivo.", "gris"), file=salida)
