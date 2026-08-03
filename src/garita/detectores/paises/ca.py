#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Canadá: SIN.

El Social Insurance Number valida por Luhn — el mismo algoritmo que el NSS
mexicano y las tarjetas bancarias. El primer dígito codifica la región de
registro: el 0 no se asigna y el 8 tampoco; el 9 es de residentes
temporales y es perfectamente válido.

Luhn deja pasar 1 de cada 10 cadenas, y el mundo está lleno de grupos de
tres dígitos con espacios: una ruta SVG del bundle de KaTeX pasaba Luhn
completa. Por eso el SIN exige contexto SIEMPRE — la misma regla que el
NSS mexicano, que también es Luhn. (El vector literal vive en las
pruebas, no aquí: citarlo en este docstring hacía que Garita se
encontrara a sí misma.)

Y el contexto es SENSIBLE a mayúsculas en las siglas: «sin» es la
preposición más común del español, y con ella de gatillo cualquier
repo hispano dispararía. SIN y NAS van en mayúsculas o no cuentan.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

_SIN = re.compile(r"(?<![\d\-])\d{3}[\s\-]?\d{3}[\s\-]?\d{3}(?![\d\-])")
_CONTEXTO = re.compile(
    r"\bSIN\b|\bNAS\b|[sS]ocial [iI]nsurance|[aA]ssurance [sS]ociale")

# 123 456 782 es el número de prueba que usa la documentación de medio
# mundo. El ejemplo de la CRA (046 454 286) no necesita exención: empieza
# en 0, región que no se asigna, y el validador ya lo rechaza — la CRA lo
# eligió de ejemplo exactamente por eso.
EXENTOS_SIN = {"123456782"}


def sin_valido(v: str) -> bool:
    d = limpio(v)
    if not re.fullmatch(r"\d{9}", d) or d[0] in "08":
        return False
    suma = 0
    for i, c in enumerate(d):
        n = int(c) * (2 if i % 2 else 1)
        suma += n - 9 if n > 9 else n
    return suma % 10 == 0


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("sin_ca"):
        return []
    return [Detector("sin_ca", "SIN canadiense (Luhn)", buscador(
        _SIN, sin_valido, "sin_ca",
        "Es un Social Insurance Number con Luhn válido. Identifica a una "
        "persona ante el gobierno canadiense; su ley exige recabarlo y "
        "guardarlo sólo cuando es indispensable.",
        exentos=EXENTOS_SIN, contexto=_CONTEXTO, exige_contexto=True))]
