#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Estados Unidos: SSN.

EL ÚNICO SIN DÍGITO VERIFICADOR

El Social Security Number no trae verificador y desde 2011 la SSA asigna
las áreas al azar, así que tampoco hay geografía que validar. Lo único
verificable es la estructura que la propia SSA documenta como inválida:
área 000, 666 o 900-999, grupo 00, serie 0000.

Eso deja pasar demasiado. Por la regla de la casa (un identificador entra
sólo si su validación se verifica contra fuente oficial; si no hay dígito
verificador, se exige contexto), el SSN exige SIEMPRE la palabra que lo
nombre en la línea — el formato tres-dos-cuatro no basta, porque con
guiones también se escriben números de parte y folios.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

_SSN = re.compile(r"(?<![\d\-])\d{3}[\s\-]?\d{2}[\s\-]?\d{4}(?![\d\-])")
_CONTEXTO = re.compile(r"(?i)\b(ssn|social security|seguro social|itin)\b")

# La cartera de Woolworth (1938) y el anuncio de la SSA: los dos SSN más
# publicados de la historia, ambos retirados. Y los rellenos de siempre.
EXENTOS_SSN = {"078051120", "219099999", "123456789", "111111111",
               "121212121", "555555555"}


def ssn_valido(v: str) -> bool:
    d = limpio(v)
    if not re.fullmatch(r"\d{9}", d):
        return False
    area, grupo, serie = d[:3], d[3:5], d[5:]
    if area in ("000", "666") or area.startswith("9"):
        return False
    return grupo != "00" and serie != "0000"


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("ssn"):
        return []
    return [Detector("ssn", "SSN estadounidense (estructura SSA + contexto obligatorio)",
                     buscador(
        _SSN, ssn_valido, "ssn",
        "Parece un Social Security Number, mencionado junto a palabras que "
        "lo confirman. Un SSN identifica a una persona ante el gobierno y "
        "la banca de EE.UU. y es la pieza central del robo de identidad.",
        exentos=EXENTOS_SSN, contexto=_CONTEXTO, exige_contexto=True))]
