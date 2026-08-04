#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ecuador: cédula de identidad.

Diez dígitos: los dos primeros son la provincia (01-24, y 30 para
inscripciones en el exterior), el tercero es menor a 6 para personas
naturales, y el décimo es el verificador módulo 10 del Registro Civil
(coeficientes 2-1-2-1…, restando 9 a los productos de dos cifras).

Diez dígitos pelones son también un teléfono o un folio, así que la
cédula exige SIEMPRE la palabra que la nombre — la misma regla que todo
identificador cuyo formato compite con la vida diaria.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

_CEDULA = re.compile(r"(?<![\d\-])\d{10}(?![\d\-])")
_CONTEXTO = re.compile(r"(?i)\b(c[eé]dula|identidad)\b")

_PROVINCIAS = {f"{n:02d}" for n in range(1, 25)} | {"30"}


def _repetidas_validas() -> set[str]:
    fuera = set()
    for d in range(10):
        v = str(d) * 10
        if cedula_ec_valida(v):
            fuera.add(v)
    return fuera


def cedula_ec_valida(v: str) -> bool:
    d = limpio(v)
    if not re.fullmatch(r"\d{10}", d):
        return False
    if d[:2] not in _PROVINCIAS or int(d[2]) > 5:
        return False
    suma = 0
    for i, c in enumerate(d[:9]):
        n = int(c) * (2 if i % 2 == 0 else 1)
        suma += n - 9 if n > 9 else n
    return int(d[9]) == (10 - suma % 10) % 10


# Los dígitos repetidos que pasan el módulo son el relleno de siempre.
EXENTOS_EC = _repetidas_validas()


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("cedula_ec"):
        return []
    return [Detector("cedula_ec", "cédula ecuatoriana (módulo 10 del Registro Civil)",
                     buscador(
        _CEDULA, cedula_ec_valida, "cedula_ec",
        "Es una cédula ecuatoriana con dígito verificador válido. "
        "Identifica a una persona en todo trámite en Ecuador.",
        exentos=EXENTOS_EC, contexto=_CONTEXTO, exige_contexto=True))]
