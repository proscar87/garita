#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Paraguay: RUC.

La cédula paraguaya se escribe pelona, sin verificador a la vista, así que
no hay detector propio. El RUC sí lo trae — el de una persona física ES su
cédula más el dígito («1946520-3»); el de una jurídica arranca en 80
(«80009735-1») — y el algoritmo es público: la propia SET (hoy DNIT)
distribuye el código fuente. Pesos 2, 3, 4… de derecha a izquierda,
módulo 11; si el residuo es 0 o 1, el verificador es 0.

«Dígitos-guion-dígito» es también un rango de páginas, un intervalo de
líneas o un número de parte, así que el RUC exige SIEMPRE la palabra que
lo nombre. Y la sigla vieja de la autoridad no cuenta como contexto:
«set» es palabra común del inglés — la misma lección que «SIN» en ca.py
y «ci» en uy.py. RUC, DNIT y timbrado sí.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

# El guion es parte de la forma: sin él, la base es indistinguible de
# cualquier número, y el contexto solo no alcanza para separarlos.
_RUC = re.compile(r"(?<![\d.\-])\d{5,8}\s?-\s?\d(?![\d\-])")

_CONTEXTO = re.compile(r"(?i)\b(ruc|dnit|timbrado|contribuyente|factura)\b")

def ruc_py_valido(v: str) -> bool:
    d = limpio(v)
    m = re.fullmatch(r"(\d{5,8})(\d)", d)
    if not m:
        return False
    s = sum(int(c) * (i + 2) for i, c in enumerate(reversed(m.group(1))))
    r = s % 11
    return int(m.group(2)) == (11 - r if r > 1 else 0)


def _repetidos_validos() -> set[str]:
    """El RUC de puros ceros valida (suma 0, residuo 0, dv 0) en sus
    cuatro largos, y es el relleno de placeholder de siempre. ve.py y
    gt.py ya generaban sus repetidos; aquí faltaban."""
    fuera = set()
    for largo in range(5, 9):
        for n in range(10):
            for dv in range(10):
                v = f"{str(n) * largo}{dv}"
                if ruc_py_valido(v):
                    fuera.add(v)
    return fuera


# Los repetidos que validan, más los dos ejemplos de la documentación
# oficial y de media guía en línea.
EXENTOS_RUC = _repetidos_validos() | {"19465203", "800097351"}


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("ruc_py"):
        return []
    return [Detector("ruc_py", "RUC paraguayo (módulo 11 de la SET/DNIT)",
                     buscador(
        _RUC, ruc_py_valido, "ruc_py",
        "Es un RUC paraguayo con dígito verificador válido. Si no empieza "
        "en 80 es de una persona física y ES SU CÉDULA con el verificador "
        "añadido.",
        exentos=EXENTOS_RUC, contexto=_CONTEXTO, exige_contexto=True))]
