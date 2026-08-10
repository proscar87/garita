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
from urllib.parse import quote

from . import __version__
from .nucleo import Resultado


def _uri(ruta: str) -> str:
    """La ruta como referencia URI, que es lo que el esquema 2.1.0 pide.

    Un espacio o unas comillas producían un documento que no valida; un
    `#` es peor aunque cuele, porque RFC 3986 lo lee como fragmento y la
    alerta termina apuntando a un artefacto que no existe. «mi archivo.txt»
    es cotidiano, no adversarial.
    """
    return quote(ruta, safe="/")

# Sin el esquema y la versión exactos, la subida a GitHub falla con un error
# que no dice nada útil.
ESQUEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION_SARIF = "2.1.0"


def generar(res: Resultado, detectores, conocidos=(), cfg=None) -> dict:
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
                    "artifactLocation": {"uri": _uri(h.archivo)},
                    "region": {"startLine": h.linea},
                },
            }],
            "partialFingerprints": {
                "garitaOrdinal/v1": f"{h.archivo}::{h.detector}::{n}",
            },
        })

    # Lo que NO se pudo revisar entra al documento como alerta propia. El
    # SARIF es el ÚNICO canal de la auditoría mensual: sin esto, la pestaña
    # Security decía «cero alertas» sobre un padrón de 2 MB que nadie leyó
    # o sobre un archivo que ni se pudo abrir. Un guardián que calla lo que
    # no miró es el que esta herramienta existe para no ser.
    resultados += _alertas_de_lo_no_revisado(res)
    resultados += alertas_de_configuracion(cfg)
    reglas.setdefault(
        "sin_revisar", "Archivos que Garita no pudo o no debió leer")

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


def _alertas_de_lo_no_revisado(res) -> list:
    """Una alerta por archivo que quedó sin mirar, con su motivo."""
    fuera = []
    for archivo, motivo in getattr(res, "ilegibles", ()):
        fuera.append(_alerta_sin_revisar(
            archivo, "error",
            f"No se pudo leer ({motivo}). Garita no puede decir que está "
            f"limpio: no lo miró. Arregla el acceso y vuelve a correr."))
    for archivo, motivo in getattr(res, "omitidos_grandes", ()):
        fuera.append(_alerta_sin_revisar(
            archivo, "warning",
            f"Sin revisar: {motivo}. Un archivo grande es justo donde cabe "
            f"un padrón entero — revísalo aparte."))
    # Una exención que no aplicó también es una reserva sobre el veredicto:
    # quien la escribió cree que sigue tapando algo. Vivía sólo en la
    # terminal, y la pestaña Security es lo que mira quien no corre Garita.
    for patron in getattr(res, "exenciones_muertas", ()):
        fuera.append(_alerta_sin_revisar(
            ".garita.yml", "note",
            f"La exención «{patron}» no aplicó a ningún archivo. El archivo "
            f"se renombró o se borró: si se renombró, lleva revisándose sin "
            f"exención desde entonces; si se borró, la regla es "
            f"configuración muerta.", huella=f"exencion:{patron}"))
    return fuera


def alertas_de_configuracion(cfg) -> list:
    """Los detectores que la configuración apagó, como alerta propia.

    La consola y el resumen del job lo dicen desde que se descubrió que
    tres líneas apagando detectores producían un «✓ nada que reportar» con
    código 0. El SARIF no: la pestaña Security mostraba cero alertas sobre
    un repositorio con la mitad del guardián apagado.
    """
    from .reporte import recortes_de_configuracion

    return [_alerta_sin_revisar(".garita.yml", "note",
                                f"Configuración: {recorte}.",
                                huella=f"config:{recorte}")
            for recorte in (recortes_de_configuracion(cfg) if cfg else [])]


def _alerta_sin_revisar(archivo: str, nivel: str, texto: str,
                        huella: str | None = None) -> dict:
    return {
        "ruleId": "sin_revisar",
        "level": nivel,
        "message": {"text": texto},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": _uri(archivo)},
                "region": {"startLine": 1},
            },
        }],
        # La huella distingue las alertas que comparten archivo: sin esto,
        # dos exenciones muertas y un recorte de configuración —los tres
        # anclados a `.garita.yml`— se fundían en una sola alerta y la
        # pestaña Security mostraba una de tres.
        "partialFingerprints": {"garitaSinRevisar/v1": huella or archivo},
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
        # Las OTRAS rutas del blob viajan al documento: la que encabeza es
        # la de origen, y ésa puede ser la inocente. Una llave nacida en
        # `tests/fixture.pem` y viva en `src/secreto.pem` se anunciaba con
        # el nombre del fixture, el que invita a cerrar la alerta.
        otras = getattr(hh, "otras_rutas", ())
        tambien = (f" También vivió en: {', '.join(otras[:5])}."
                   if otras else "")
        texto = (f"[{estado}] {h.que} — {h.por_que} Entró en el commit "
                 f"{hh.commit} ({hh.fecha}){duracion}.{tambien} "
                 f"→ {h.como_arreglar}")
        resultados.append({
            "ruleId": h.detector,
            "level": "error" if h.severidad == "error" else "warning",
            "message": {"text": texto},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(h.archivo)},
                    "region": {"startLine": h.linea},
                },
            }],
            "partialFingerprints": {
                "garitaHistorial/v1":
                    f"{hh.commit}::{h.archivo}::{h.detector}::{n}",
            },
        })

    # El historial no llamaba a esto: un blob de dos megas que nunca se
    # abrió salía como «cero alertas» en la pestaña Security, sobre el
    # modo cuyo propósito ENTERO es no dar nada por revisado.
    resultados += _alertas_de_lo_no_revisado(res)
    reglas.setdefault(
        "sin_revisar", "Archivos que Garita no pudo o no debió leer")

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
