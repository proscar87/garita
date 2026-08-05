#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Guatemala: NIT.

El CUI del DPI queda fuera a propósito: el RENAP no publica el algoritmo de
su verificador —lo que circula son reconstrucciones de terceros— y la regla
de la casa exige fuente. El NIT sí está documentado por la SAT para la
factura electrónica (FEL): pesos descendentes desde la izquierda (n+1 … 2),
módulo 11, y el residuo 10 se escribe «K» — «3602978-5» es el vector de
toda la documentación y reproduce.

Base corta y un solo carácter de control: la forma también es un rango o un
folio, así que el NIT exige SIEMPRE la palabra que lo nombre. Y «sat» no
cuenta como contexto: en un repositorio es sábado («Sat») o el SAT
mexicano — nit, fel, factura y contribuyente sí.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

_NIT = re.compile(r"(?<![\w.\-])\d{4,8}\s?-?\s?[0-9Kk](?![\w\-])")

_CONTEXTO = re.compile(r"(?i)\b(nit|fel|factura|contribuyente)\b")


def nit_gt_valido(v: str) -> bool:
    d = limpio(v)
    m = re.fullmatch(r"(\d{4,8})([0-9K])", d)
    if not m:
        return False
    base = m.group(1)
    s = sum(int(c) * (len(base) + 1 - i) for i, c in enumerate(base))
    dv = (11 - s % 11) % 11
    return m.group(2) == ("K" if dv == 10 else str(dv))


def _repetidos_validos() -> set[str]:
    fuera = set()
    for n in range(10):
        for largo in range(4, 9):
            base = str(n) * largo
            for dv in "0123456789K":
                v = base + dv
                if nit_gt_valido(v):
                    fuera.add(v)
    return fuera


EXENTOS_NIT = _repetidos_validos()


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("nit_gt"):
        return []
    return [Detector("nit_gt", "NIT guatemalteco (módulo 11 de la SAT)",
                     buscador(
        _NIT, nit_gt_valido, "nit_gt",
        "Es un NIT guatemalteco con dígito de control válido. Identifica a "
        "un contribuyente; si es persona individual, señala a la persona.",
        exentos=EXENTOS_NIT, contexto=_CONTEXTO, exige_contexto=True))]
