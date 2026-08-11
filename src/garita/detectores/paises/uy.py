#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Uruguay: cédula de identidad.

La CI valida con un dígito verificador propio: coeficientes 2-9-8-7-6-3-4
sobre los siete dígitos, módulo 10. Se escribe «1.234.567-8» y así la
imprime todo documento uruguayo, aunque en bases de datos viva pelona.

Un solo dígito verificador → refuerzo: separadores o palabra que la
nombre.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

_CI = re.compile(r"(?<![\d.\-])\d\.?\d{3}\.?\d{3}\s?-?\s?\d(?![\d\-])")
# «ci» pelona NO refuerza: en un repositorio de software, CI es integración
# continua («CI corrió el 20250801» — y una fecha AAAAMMDD pasa el módulo 10
# una de cada diez veces). La misma lección que ca.py documenta con «SIN».
# Con puntos —«c.i.»— sí es la cédula, porque así la abrevian los documentos.
# El sustantivo va en plural opcional: el encabezado de una columna, la
# clave de un YAML y el nombre de una variable casi siempre lo llevan
# («cedulas», «rucs», «contribuyentes»), y con el `\b` pegado al
# singular el detector con contexto obligatorio quedaba CIEGO sobre
# justo la forma en que se exporta un padrón. Los acrónimos que en
# plural chocan con una palabra común («run»→«runs») se quedan sin la
# «s» a propósito: una palabra de contexto envenenada es peor que la
# forma que deja de casar.
_CONTEXTO = re.compile(r"(?i)\b(c[eé]dulas?|documentos?|identidad(?:es)?)\b|\bc\.\s?i\.")
_PESOS = (2, 9, 8, 7, 6, 3, 4)

# 1.234.567-2 valida y es el ejemplo de los instructivos; los repetidos
# también pasan el algoritmo y son el relleno de siempre.
EXENTOS_CI = {"12345672"} | {str(d) * 7 + str((10 - sum(int(str(d)) * p for p in _PESOS) % 10) % 10) for d in range(10)}


def ci_valida(v: str) -> bool:
    d = limpio(v)
    if not re.fullmatch(r"\d{8}", d):
        return False
    dv = (10 - sum(int(c) * p for c, p in zip(d[:7], _PESOS)) % 10) % 10
    return int(d[7]) == dv


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("ci_uy"):
        return []
    return [Detector("ci_uy", "cédula uruguaya (dígito verificador)", buscador(
        _CI, ci_valida, "ci_uy",
        "Es una cédula uruguaya con dígito verificador válido. Identifica a "
        "una persona en todo trámite y es la llave de su historia clínica y "
        "crediticia.",
        exentos=EXENTOS_CI, contexto=_CONTEXTO, exige_refuerzo=True))]
