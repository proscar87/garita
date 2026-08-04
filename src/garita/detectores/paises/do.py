#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
República Dominicana: cédula de identidad y electoral.

Once dígitos que validan por Luhn — el algoritmo de la JCE es el mismo de
las tarjetas bancarias. Se escribe «001-1234567-8».

Luhn solo deja pasar 1 de cada 10 cadenas, así que la cédula exige
SIEMPRE la palabra que la nombre: la misma regla que el NSS mexicano, el
SIN canadiense y todo identificador que valide únicamente por Luhn.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

_CEDULA = re.compile(r"(?<![\d\-])\d{3}[\s\-]?\d{7}[\s\-]?\d(?![\d\-])")
_CONTEXTO = re.compile(r"(?i)\b(c[eé]dula|electoral|jce|identidad)\b")


def _repetidas_validas() -> set[str]:
    fuera = set()
    for d in range(10):
        v = str(d) * 11
        if cedula_do_valida(v):
            fuera.add(v)
    return fuera


def cedula_do_valida(v: str) -> bool:
    d = limpio(v)
    if not re.fullmatch(r"\d{11}", d):
        return False
    suma = 0
    for i, c in enumerate(d):
        n = int(c) * (2 if i % 2 else 1)
        suma += n - 9 if n > 9 else n
    return suma % 10 == 0


EXENTOS_DO = _repetidas_validas()


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("cedula_do"):
        return []
    return [Detector("cedula_do", "cédula dominicana (Luhn de la JCE)",
                     buscador(
        _CEDULA, cedula_do_valida, "cedula_do",
        "Es una cédula dominicana con Luhn válido. Identifica a una "
        "persona ante el estado dominicano y es la llave de su registro "
        "electoral.",
        exentos=EXENTOS_DO, contexto=_CONTEXTO, exige_contexto=True))]
