#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Perú: RUC.

El DNI peruano queda fuera a propósito. Tiene un carácter verificador en la
tarjeta física y RENIEC confirma que es módulo 11, pero **no publica el
algoritmo** —lo que circula son reconstrucciones de terceros— y, sobre todo,
en texto el DNI casi siempre aparece como ocho dígitos pelados, sin el
verificador. Aunque tuviéramos la fórmula no habría nada que validar.

El atajo útil es el mismo que en Argentina: un RUC de tipo 10 contiene el DNI
de la persona, y ése sí se valida.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

_RUC = re.compile(r"(?<![\d\-])(?:10|15|16|17|20)\d{9}(?![\d\-])")
_PESOS = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]

_CONTEXTO = re.compile(r"(?i)\b(ruc|sunat|dni|comprobante|factura|boleta)\b")


def ruc_valido(v: str) -> bool:
    d = limpio(v)
    if not re.fullmatch(r"\d{11}", d) or d[:2] not in {"10", "15", "16", "17", "20"}:
        return False
    dv = (11 - sum(int(c) * p for c, p in zip(d[:10], _PESOS)) % 11) % 10
    return int(d[10]) == dv


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("ruc"):
        return []
    return [Detector("ruc", "RUC peruano", buscador(
        _RUC, ruc_valido, "ruc",
        "Es un RUC válido. Si empieza en 10 es de una persona natural y "
        "CONTIENE SU DNI en las posiciones 3 a 10.",
        contexto=_CONTEXTO, exige_refuerzo=True))]
