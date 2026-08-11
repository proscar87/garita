#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chile: RUT/RUN.

Mismo tropiezo que el CPF brasileño: **todo RUT de dígito repetido valida**.
`11.111.111-1`, `22.222.222-2` y así hasta el nueve pasan el módulo 11 sin
despeinarse, y son los marcadores de facto en las pruebas de medio Chile. Sin
lista negra, el detector grita en cada repositorio.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import bases_de_relleno, buscador, limpio

_RUT = re.compile(r"(?<![\w.\-])\d{1,2}\.?\d{3}\.?\d{3}\s?-?\s?[0-9kK](?![\w\-])")

# Genéricos del SII: extranjeros sin domicilio y creadores de contenido.
# Más los repetidos, que validan y son marcadores.

# El sustantivo va en plural opcional: el encabezado de una columna, la
# clave de un YAML y el nombre de una variable casi siempre lo llevan
# («cedulas», «rucs», «contribuyentes»), y con el `\b` pegado al
# singular el detector con contexto obligatorio quedaba CIEGO sobre
# justo la forma en que se exporta un padrón. Los acrónimos que en
# plural chocan con una palabra común («run»→«runs») se quedan sin la
# «s» a propósito: una palabra de contexto envenenada es peor que la
# forma que deja de casar.
_CONTEXTO = re.compile(r"(?i)\b(ruts?|run|sii|c[eé]dulas?|boletas?|facturas?)\b")


def rut_valido(v: str) -> bool:
    d = limpio(v)
    m = re.fullmatch(r"(\d{7,8})([0-9K])", d)
    if not m:
        return False
    s, mult = 0, 2
    for c in reversed(m.group(1)):
        s += int(c) * mult
        mult = 2 if mult == 7 else mult + 1
    r = 11 - s % 11
    return m.group(2) == ("0" if r == 11 else "K" if r == 10 else str(r))


# `range(10)`, no `range(1, 10)`: el módulo 11 del RUT de puros ceros da
# suma 0 y dígito «0», así que VALIDA — y es el relleno de campo vacío
# más común de cualquier export. Empezar el rango en 1 lo dejaba fuera
# de la lista y disparaba como una persona.
EXENTOS = ({"444444460", "444444479"}
           | {f"{str(d)*8}{d}" for d in range(10)}
           # SIETE y ocho dígitos: el RUT admite los dos largos, y el de
           # puros ceros —«0.000.000-0», el campo vacío de cualquier
           # export— es de siete. Cubrir sólo el de ocho lo dejaba fuera.
           | {b + dv for largo in (7, 8) for b in bases_de_relleno(largo)
              for dv in "0123456789K" if rut_valido(b + dv)})


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("rut"):
        return []
    return [Detector("rut", "RUT/RUN chileno", buscador(
        _RUT, rut_valido, "rut",
        "Es un RUT con dígito verificador válido. Identifica a una persona o "
        "empresa en Chile y es la llave de casi cualquier trámite.",
        EXENTOS, _CONTEXTO, exige_refuerzo=True))]
