#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Colombia: NIT.

La cédula de ciudadanía NO tiene dígito verificador: es un consecutivo de la
Registraduría. El «DV» que a veces la acompaña es el de la DIAN, de cuando la
cédula se usa como NIT — no forma parte del documento. Por eso aquí no hay
detector de cédula: sería puro ruido.

El NIT sí lo tiene, pero deja pasar ~1 de cada 10 números de diez dígitos —y
en Colombia los celulares y las cédulas nuevas son de diez dígitos—, así que
exige formato con separadores o contexto.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

# Base de 8 O 9 dígitos: las cédulas antiguas (hoy NIT de persona natural)
# tienen ocho, y exigir nueve las dejaba todas fuera.
_NIT = re.compile(r"(?<![\d.\-])\d{2,3}\.?\d{3}\.?\d{3}\s?-?\s?\d(?![\d\-])")
_PESOS = [3, 7, 13, 17, 19, 23, 29, 37, 41, 43, 47, 53, 59, 67, 71]

# El «222222222222» de consumidor final (Resolución DIAN 000042 de 2020) NO
# está exento a propósito: son doce dígitos, la regex admite diez a lo sumo y
# sus truncados no pasan el dígito de la DIAN — nunca llega a validarse. Un
# exento que no puede casar es código muerto que aparenta protección.
EXENTOS: set[str] = set()

_CONTEXTO = re.compile(r"(?i)\b(nit|r[uú]t|dian|c[eé]dula|c\.?c\.?|nuip|factura)\b")


def nit_valido(v: str) -> bool:
    d = limpio(v)
    if not re.fullmatch(r"\d{9,10}", d):
        return False
    base = d[:-1]
    s = sum(int(c) * _PESOS[i] for i, c in enumerate(reversed(base)))
    r = s % 11
    return (r if r < 2 else 11 - r) == int(d[-1])


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("nit"):
        return []
    return [Detector("nit", "NIT colombiano (dígito de la DIAN)", buscador(
        _NIT, nit_valido, "nit",
        "Es un NIT con dígito de verificación válido. Identifica a un "
        "contribuyente; si es persona natural, es su cédula.",
        EXENTOS, _CONTEXTO, exige_refuerzo=True))]
