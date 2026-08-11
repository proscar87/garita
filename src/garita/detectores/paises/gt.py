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
from ._comun import bases_de_relleno, buscador, limpio

_NIT = re.compile(r"(?<![\w.\-])\d{4,8}\s?-?\s?[0-9Kk](?![\w\-])")

# El sustantivo va en plural opcional: el encabezado de una columna, la
# clave de un YAML y el nombre de una variable casi siempre lo llevan
# («cedulas», «rucs», «contribuyentes»), y con el `\b` pegado al
# singular el detector con contexto obligatorio quedaba CIEGO sobre
# justo la forma en que se exporta un padrón. Los acrónimos que en
# plural chocan con una palabra común («run»→«runs») se quedan sin la
# «s» a propósito: una palabra de contexto envenenada es peor que la
# forma que deja de casar.
_CONTEXTO = re.compile(r"(?i)\b(nits?|fel|facturas?|contribuyentes?)\b")


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


# Más el vector de toda la documentación FEL de la SAT, que el docstring
# cita y el código no exentaba: citar el instructivo oficial daba error.
# El vector oficial de la SAT, los repetidos, y los SECUENCIALES: el
# «12345678-9» pasa el módulo 11 y es el relleno de ejemplo más obvio
# que existe. br.py ya exenta el suyo por exactamente esta razón.
EXENTOS_NIT = (_repetidos_validos() | {"36029785"}
               | {b + dv for largo in range(4, 9)
                  for b in bases_de_relleno(largo)
                  for dv in "0123456789K" if nit_gt_valido(b + dv)})


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("nit_gt"):
        return []
    return [Detector("nit_gt", "NIT guatemalteco (módulo 11 de la SAT)",
                     buscador(
        _NIT, nit_gt_valido, "nit_gt",
        "Es un NIT guatemalteco con dígito de control válido. Identifica a "
        "un contribuyente; si es persona individual, señala a la persona.",
        exentos=EXENTOS_NIT, contexto=_CONTEXTO, exige_contexto=True))]
