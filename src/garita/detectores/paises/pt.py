#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Portugal: NIF.

El Número de Identificação Fiscal valida por módulo 11 sobre nueve
dígitos. El primero dice qué es: 1, 2 y 3 son personas singulares; 5, 6,
8 y 9, entidades. El 0 y el 4 no se asignan.

Un solo dígito módulo 11 deja pasar 1 de cada 11 cadenas, y su formato
por grupos de tres («123 456 789») es idéntico a media plantilla de HTML:
un `slice 300 400 500` de hugo valida. Por eso el NIF exige contexto
SIEMPRE: en Portugal nadie escribe un NIF sin llamarlo NIF.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

_NIF = re.compile(r"(?<![\d.\-])[1-9]\d{2}[\s.]?\d{3}[\s.]?\d{3}(?![\d\-])")
_CONTEXTO = re.compile(r"(?i)\b(nif|contribuinte|fiscal|finan[cç]as)\b")

# 123456789 pasa el módulo 11 y es el marcador de posición de todos los
# formularios portugueses de ejemplo.
EXENTOS_NIF = {"123456789"}


def nif_valido(v: str) -> bool:
    d = limpio(v)
    if not re.fullmatch(r"[1-35-9]\d{8}", d):
        return False
    r = sum(int(c) * (9 - i) for i, c in enumerate(d[:8])) % 11
    dv = 0 if r < 2 else 11 - r
    return int(d[8]) == dv


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("nif_pt"):
        return []
    return [Detector("nif_pt", "NIF portugués (módulo 11)", buscador(
        _NIF, nif_valido, "nif_pt",
        "Es un NIF portugués con dígito de control válido. Si empieza en 1, "
        "2 o 3 es de una persona singular e identifica al contribuyente en "
        "todo trámite fiscal.",
        exentos=EXENTOS_NIF, contexto=_CONTEXTO, exige_contexto=True))]
