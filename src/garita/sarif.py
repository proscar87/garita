#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Salida SARIF: los hallazgos donde la gente ya mira.

Un hallazgo impreso en el registro de una corrida de CI muere ahí: casi
nadie abre los registros. GitHub ingiere SARIF de forma nativa
(`github/codeql-action/upload-sarif`) y lo convierte en alertas de code
scanning en la pestaña Security — con historial y estado por hallazgo.

DOS REGLAS QUE ESTE ARCHIVO RESPETA SIN EXCEPCIÓN

1. **Ningún valor completo entra al documento.** El texto de una alerta de
   code scanning suele ser visible para más gente que el propio repositorio.
   Se usa el `que` ya recortado, igual que el reporte de consola.

2. **Nada derivado del valor en las huellas.** `partialFingerprints` es lo
   que permite a GitHub seguir un hallazgo entre corridas aunque se muevan
   las líneas. La huella es `archivo + regla + ordinal` — la misma regla que
   la línea base, y por el mismo motivo: un hash de un dato con estructura
   es el dato con un candado de juguete.

Y un detalle de forma: `ruleId` va por DETECTOR, no por hallazgo. GitHub
agrupa por regla; un `ruleId` distinto por hallazgo llena la pestaña de
reglas de un solo uso.
"""
from __future__ import annotations

from collections import defaultdict

from . import __version__
from .nucleo import Resultado

# Sin el esquema y la versión exactos, la subida a GitHub falla con un error
# que no dice nada útil.
ESQUEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION_SARIF = "2.1.0"


def generar(res: Resultado, detectores, conocidos=()) -> dict:
    """El documento SARIF como dict listo para json.dumps.

    Los hallazgos cubiertos por la línea base (`conocidos`) salen con nivel
    `note`: siguen visibles en la pestaña Security, pero sin gritar por algo
    que el equipo ya aceptó.
    """
    reglas = {d.nombre: d.descripcion for d in detectores}
    # Un hallazgo cuya regla no esté declarada no debe tirar la subida:
    # mejor una regla sin descripción que un documento rechazado.
    for h in res.hallazgos:
        reglas.setdefault(h.detector, "")

    aceptados = {id(h) for h in conocidos}

    # El ordinal es la posición del hallazgo entre los de su mismo archivo y
    # detector, ordenados por línea — el mismo orden que usa la línea base al
    # perdonar. Es estable mientras no cambie el CONJUNTO de hallazgos, que
    # es exactamente lo que se quiere seguir.
    ordinales: dict[tuple[str, str], int] = defaultdict(int)
    resultados = []
    for h in sorted(res.hallazgos, key=lambda x: (x.archivo, x.detector, x.linea)):
        n = ordinales[(h.archivo, h.detector)]
        ordinales[(h.archivo, h.detector)] += 1
        if id(h) in aceptados:
            nivel = "note"
            texto = f"[deuda aceptada] {h.que} — {h.por_que} → {h.como_arreglar}"
        else:
            nivel = "error" if h.severidad == "error" else "warning"
            texto = f"{h.que} — {h.por_que} → {h.como_arreglar}"
        resultados.append({
            "ruleId": h.detector,
            "level": nivel,
            "message": {"text": texto},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": h.archivo},
                    "region": {"startLine": h.linea},
                },
            }],
            "partialFingerprints": {
                "garitaOrdinal/v1": f"{h.archivo}::{h.detector}::{n}",
            },
        })

    return {
        "$schema": ESQUEMA,
        "version": VERSION_SARIF,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Garita",
                    "version": __version__,
                    "informationUri": "https://github.com/proscar87/garita",
                    "rules": [
                        {
                            "id": nombre,
                            "shortDescription": {"text": descripcion or nombre},
                        }
                        for nombre, descripcion in sorted(reglas.items())
                    ],
                },
            },
            "results": resultados,
        }],
    }


def generar_historial(res, detectores) -> dict:
    """SARIF de una auditoría de historial.

    La diferencia con el del árbol está en dos decisiones:

    1. **La ruta puede no existir en HEAD** — y está bien. La alerta apunta
       a la ruta del commit que introdujo el dato, que es la que quien va a
       limpiar tiene que buscar; el mensaje carga el commit y la fecha, y
       si el archivo ya se borró lo dice: borrar el archivo no borró nada.

    2. **La huella no usa la línea ni el valor.** El historial es inmutable,
       así que `commit + ruta + regla + ordinal` identifica el hallazgo para
       siempre — y no deriva nada del dato, la misma regla de siempre.
    """
    reglas = {d.nombre: d.descripcion for d in detectores}
    for hh in res.hallazgos:
        reglas.setdefault(hh.hallazgo.detector, "")

    ordinales: dict[tuple[str, str, str], int] = defaultdict(int)
    resultados = []
    for hh in sorted(res.hallazgos,
                     key=lambda x: (x.hallazgo.archivo, x.hallazgo.detector,
                                    x.commit, x.hallazgo.linea)):
        h = hh.hallazgo
        clave = (hh.commit, h.archivo, h.detector)
        n = ordinales[clave]
        ordinales[clave] += 1
        estado = ("todavía en el árbol" if hh.vivo else
                  "SÓLO EN EL HISTORIAL: el archivo ya no existe, el dato sí "
                  "— vive en cada clon y cada fork")
        duracion = (f"; duró {hh.versiones} versiones del archivo"
                    if hh.versiones > 1 else "")
        texto = (f"[{estado}] {h.que} — {h.por_que} Entró en el commit "
                 f"{hh.commit} ({hh.fecha}){duracion}. → {h.como_arreglar}")
        resultados.append({
            "ruleId": h.detector,
            "level": "error" if h.severidad == "error" else "warning",
            "message": {"text": texto},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": h.archivo},
                    "region": {"startLine": h.linea},
                },
            }],
            "partialFingerprints": {
                "garitaHistorial/v1":
                    f"{hh.commit}::{h.archivo}::{h.detector}::{n}",
            },
        })

    return {
        "$schema": ESQUEMA,
        "version": VERSION_SARIF,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Garita (historial)",
                    "version": __version__,
                    "informationUri": "https://github.com/proscar87/garita",
                    "rules": [
                        {"id": nombre,
                         "shortDescription": {"text": descripcion or nombre}}
                        for nombre, descripcion in sorted(reglas.items())
                    ],
                },
            },
            "results": resultados,
        }],
    }
