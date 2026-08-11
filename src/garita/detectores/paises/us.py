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
from ._comun import bases_de_relleno, buscador, limpio

_SSN = re.compile(r"(?<![\d\-])\d{3}[\s\-]?\d{2}[\s\-]?\d{4}(?![\d\-])")
# El sustantivo va en plural opcional: el encabezado de una columna, la
# clave de un YAML y el nombre de una variable casi siempre lo llevan
# («cedulas», «rucs», «contribuyentes»), y con el `\b` pegado al
# singular el detector con contexto obligatorio quedaba CIEGO sobre
# justo la forma en que se exporta un padrón. Los acrónimos que en
# plural chocan con una palabra común («run»→«runs») se quedan sin la
# «s» a propósito: una palabra de contexto envenenada es peor que la
# forma que deja de casar.
_CONTEXTO = re.compile(r"(?i)\b(ssns?|social security|seguros? sociales?|itins?)\b")

# La cartera de Woolworth (1938) y el anuncio de la SSA: los dos SSN más
# publicados de la historia, ambos retirados. Y los rellenos de siempre.
_PUBLICADOS = ({"078051120", "219099999", "123456789", "111111111",
                "121212121", "555555555"}
               # La SSA reserva 987-65-4320 … 987-65-4329 para publicidad y
               # material de ejemplo: nunca se emiten. Es el segundo relleno
               # más usado después del secuencial, y estaba fuera.
               | {f"98765432{d}" for d in range(10)})


def _rellenos_validos() -> set[str]:
    """Los rellenos de nueve dígitos que pasan la estructura de la SSA.

    La lista escrita a mano cubría seis y dejaba fuera los igual de
    comunes: el de nueves —que además cuela como ITIN por el rango
    94-99—, el secuencial descendente y cinco repetidos. Un relleno
    que se reporta como una persona es lo que enseña a apagar el paso.
    """
    return {v for v in bases_de_relleno(9) if ssn_valido(v)}


def ssn_valido(v: str) -> bool:
    d = limpio(v)
    if not re.fullmatch(r"\d{9}", d):
        return False
    area, grupo, serie = d[:3], d[3:5], d[5:]
    if grupo == "00" or serie == "0000":
        return False
    if area.startswith("9"):
        # Área 9xx no es un SSN — pero SÍ puede ser un ITIN, que el propio
        # contexto anuncia («itin»). El IRS los asigna con el grupo en rangos
        # fijos; fuera de ellos, sigue sin ser nada.
        g = int(grupo)
        return 50 <= g <= 65 or 70 <= g <= 88 or 90 <= g <= 92 or 94 <= g <= 99
    return area not in ("000", "666")


EXENTOS_SSN = _PUBLICADOS | _rellenos_validos()


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("ssn"):
        return []
    return [Detector("ssn", "SSN o ITIN estadounidense (estructura + contexto obligatorio)",
                     buscador(
        _SSN, ssn_valido, "ssn",
        "Parece un Social Security Number (o un ITIN, su equivalente para "
        "contribuyentes sin SSN), mencionado junto a palabras que lo "
        "confirman. Identifica a una persona ante el gobierno y la banca de "
        "EE.UU. y es la pieza central del robo de identidad.",
        exentos=EXENTOS_SSN, contexto=_CONTEXTO, exige_contexto=True))]
