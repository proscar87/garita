#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Venezuela: RIF.

La cédula de identidad venezolana no tiene dígito verificador —es un
consecutivo del SAIME—, así que no hay detector propio. El atajo es el
argentino: **el RIF de una persona natural (V o E) CONTIENE su cédula** en
los ocho dígitos, y el RIF sí valida: la letra vale V=1, E=2, J=3, P=4,
G=5 —y C=3, igual que J: los consejos comunales y comunas llevan C desde
2015, migrados de la J— y se multiplica por 4; los dígitos, por
3-2-7-6-5-4-3-2; módulo 11, y si 11 menos el residuo pasa de 9, el
verificador es 0.

El SENIAT no publica la fórmula — la misma situación que el CURP mexicano,
y la misma respuesta: el estándar de la industria, comprobado reproduciendo
RIF públicos de entidades. El del propio SENIAT (G-20000303-0) y el de
PDVSA (J-00123072-6) cuadran; están en la papelería oficial de ambos.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

_RIF = re.compile(r"(?<![\w-])[VEJPGCvejpgc]\s?-?\s?\d{8}\s?-?\s?\d(?![\w-])")
_LETRAS = {"V": 1, "E": 2, "J": 3, "P": 4, "G": 5, "C": 3}
_PESOS = (3, 2, 7, 6, 5, 4, 3, 2)

_CONTEXTO = re.compile(r"(?i)\b(rif|seniat|contribuyente|factura|c[eé]dula)\b")


def rif_valido(v: str) -> bool:
    d = limpio(v)
    m = re.fullmatch(r"([VEJPGC])(\d{8})(\d)", d)
    if not m:
        return False
    s = _LETRAS[m.group(1)] * 4 + sum(
        int(c) * p for c, p in zip(m.group(2), _PESOS))
    dv = 11 - s % 11
    if dv > 9:
        dv = 0
    return int(m.group(3)) == dv


def _repetidos_validos() -> set[str]:
    """J-00000000-0 y compañía validan y son el relleno de siempre."""
    fuera = set()
    for letra in "VEJPGC":
        for n in range(10):
            for dv in range(10):
                v = f"{letra}{str(n) * 8}{dv}"
                if rif_valido(v):
                    fuera.add(v)
    return fuera


EXENTOS_RIF = _repetidos_validos()


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("rif"):
        return []
    return [Detector("rif", "RIF venezolano (módulo 11)", buscador(
        _RIF, rif_valido, "rif",
        "Es un RIF con dígito verificador válido. Si empieza en V o E es de "
        "una persona natural y CONTIENE SU CÉDULA en los ocho dígitos.",
        exentos=EXENTOS_RIF, contexto=_CONTEXTO, exige_refuerzo=True))]
