#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Argentina: CUIT y CUIL.

El DNI argentino no tiene dígito verificador —son siete u ocho dígitos
consecutivos—, así que no hay detector propio. Pero hay un atajo mejor: **el
CUIT de una persona física CONTIENE su DNI** en las posiciones 3 a 10. Al
detectar el CUIT se detecta el DNI, y con validación de por medio.

Por eso los prefijos de persona (20, 23, 24, 25, 26, 27) se tratan con la
misma severidad que un documento de identidad, no como un dato meramente
fiscal.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

_CUIT = re.compile(r"(?<![\d\-])(?:20|23|24|25|26|27|30|33|34)\s?-?\s?\d{8}\s?-?\s?\d(?![\d\-])")
_PESOS = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
_PREFIJOS = {"20", "23", "24", "25", "26", "27", "30", "33", "34"}
_PERSONA = {"20", "23", "24", "25", "26", "27"}

# El sustantivo va en plural opcional: el encabezado de una columna, la
# clave de un YAML y el nombre de una variable casi siempre lo llevan
# («cedulas», «rucs», «contribuyentes»), y con el `\b` pegado al
# singular el detector con contexto obligatorio quedaba CIEGO sobre
# justo la forma en que se exporta un padrón. Los acrónimos que en
# plural chocan con una palabra común («run»→«runs») se quedan sin la
# «s» a propósito: una palabra de contexto envenenada es peor que la
# forma que deja de casar.
_CONTEXTO = re.compile(r"(?i)\b(cuits?|cuils?|afip|arca|dnis?|documentos?|facturas?)\b")


def cuit_valido(v: str) -> bool:
    d = limpio(v)
    if not re.fullmatch(r"\d{11}", d) or d[:2] not in _PREFIJOS:
        return False
    dv = 11 - sum(int(c) * p for c, p in zip(d[:10], _PESOS)) % 11
    if dv == 11:
        dv = 0
    elif dv == 10:
        # La AFIP no emite CUIT con verificador 10: reasigna el prefijo 23.
        return False
    return int(d[10]) == dv


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("cuit"):
        return []
    return [Detector("cuit", "CUIT/CUIL argentino", buscador(
        _CUIT, cuit_valido, "cuit",
        "Es un CUIT/CUIL válido. Si empieza en 20, 23, 24, 25, 26 o 27 es de "
        "una persona física y CONTIENE SU DNI en las posiciones 3 a 10.",
        contexto=_CONTEXTO, exige_refuerzo=True))]
