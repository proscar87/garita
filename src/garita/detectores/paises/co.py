#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Colombia: NIT.

La cédula de ciudadanía NO tiene dígito verificador: es un consecutivo de la
Registraduría. El «DV» que a veces la acompaña es el de la DIAN, de cuando la
cédula se usa como NIT — no forma parte del documento. Por eso aquí no hay
detector de cédula: sería puro ruido.

El NIT sí lo tiene, pero deja pasar ~1 de cada 10 números de diez dígitos —y
en Colombia los celulares y las cédulas nuevas son de diez dígitos—, así que
exige formato con separadores o contexto.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

# Dos niveles a propósito. La base de NUEVE dígitos es la normal y exige
# refuerzo (separadores o palabra). La de OCHO —las cédulas antiguas, hoy
# NIT de persona natural— existe, pero su forma es exactamente la del RUT
# chileno (XX.XXX.XXX-D, y ~9% de los RUT válidos también pasan el dígito
# de la DIAN) y cualquier folio de nueve dígitos junto a «factura» valida
# ~10% de las veces. Para esa base el formato no es evidencia: sólo la
# palabra que la nombra de verdad (nit/dian/nuip) la sostiene.
_NIT9 = re.compile(r"(?<![\d.\-])\d{3}\.?\d{3}\.?\d{3}\s?-?\s?\d(?![\d\-])")
_NIT8 = re.compile(r"(?<![\d.\-])\d{2}\.?\d{3}\.?\d{3}\s?-?\s?\d(?![\d\-])")
_PESOS = [3, 7, 13, 17, 19, 23, 29, 37, 41, 43, 47, 53, 59, 67, 71]

# El «222222222222» de consumidor final (Resolución DIAN 000042 de 2020) NO
# está exento a propósito: son doce dígitos, la regex admite diez a lo sumo y
# sus truncados no pasan el dígito de la DIAN — nunca llega a validarse. Un
# exento que no puede casar es código muerto que aparenta protección.
EXENTOS: set[str] = set()

_CONTEXTO = re.compile(r"(?i)\b(nit|r[uú]t|dian|c[eé]dula|c\.?c\.?|nuip|factura)\b")

# El contexto fuerte para la base de ocho: «rut» aquí sería veneno (nombraría
# NIT colombiano a todo RUT chileno bien escrito) y «factura»/«cc» acompañan
# a cualquier folio. Sólo lo que nombra al NIT sin ambigüedad.
_CONTEXTO_FUERTE = re.compile(r"(?i)\b(nit|dian|nuip)\b")


def nit_valido(v: str) -> bool:
    d = limpio(v)
    if not re.fullmatch(r"\d{9,10}", d):
        return False
    base = d[:-1]
    s = sum(int(c) * _PESOS[i] for i, c in enumerate(reversed(base)))
    r = s % 11
    return (r if r < 2 else 11 - r) == int(d[-1])


def detectores(cfg: Config) -> list[Detector]:
    if not cfg.activo("nit"):
        return []
    por_que = ("Es un NIT con dígito de verificación válido. Identifica a un "
               "contribuyente; si es persona natural, es su cédula.")
    b9 = buscador(_NIT9, nit_valido, "nit", por_que,
                  EXENTOS, _CONTEXTO, exige_refuerzo=True)
    b8 = buscador(_NIT8, nit_valido, "nit", por_que,
                  EXENTOS, _CONTEXTO_FUERTE, exige_contexto=True)

    def busca(texto, archivo):
        yield from b9(texto, archivo)
        yield from b8(texto, archivo)

    return [Detector("nit", "NIT colombiano (dígito de la DIAN)", busca)]
