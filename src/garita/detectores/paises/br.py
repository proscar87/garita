#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Brasil: CPF y CNPJ.

DOS COSAS QUE SE EQUIVOCAN SEGUIDO Y AQUÍ NO

**Los CPF de dígito repetido PASAN el módulo 11.** Los once (`000.000.000-00`
hasta `999.999.999-99`) validan perfectamente. Sin lista negra, cualquier
archivo de pruebas del mundo dispara el detector. Lo mismo pasa con el RUT
chileno, y es el error clásico de quien implementa esto por primera vez.

**El CNPJ es alfanumérico desde julio de 2026.** Las doce primeras posiciones
admiten letras (Nota Técnica Conjunta 2025.001 de la Receita Federal); sólo
los dos dígitos verificadores siguen siendo numéricos, y cada carácter vale
su ASCII menos 48. Un detector que sólo acepte dígitos se volvió obsoleto en
julio: no es un cambio futuro, ya está vigente.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import buscador, limpio

_CPF = re.compile(r"(?<![\d.\-])\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?![\d\-])")
# Doce posiciones alfanuméricas y dos dígitos: la forma vigente desde 2026.
_CNPJ = re.compile(
    r"(?<![\w.\-/])[0-9A-Za-z]{2}\.?[0-9A-Za-z]{3}\.?[0-9A-Za-z]{3}"
    r"/?[0-9A-Za-z]{4}-?\d{2}(?![\w\-])"
)

_P1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
_P2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]

# El ejemplo universal de la documentación brasileña. Marcarlo produciría un
# falso positivo en cualquier tutorial.
# Además de los repetidos, los secuenciales: `01234567890` valida y es el
# marcador que usa medio mundo en sus pruebas.
EXENTOS_CPF = ({"12345678909", "01234567890", "12345678901"}
               | {str(d) * 11 for d in range(10)})
EXENTOS_CNPJ = {"12ABC34501DE35"}   # ejemplo oficial del manual de la Receita


def cpf_valido(cpf: str) -> bool:
    d = limpio(cpf)
    if not re.fullmatch(r"\d{11}", d) or d == d[0] * 11:
        return False
    n = [int(c) for c in d]
    dv1 = (sum(n[i] * (10 - i) for i in range(9)) * 10) % 11
    dv2 = (sum(n[i] * (11 - i) for i in range(10)) * 10) % 11
    return n[9] == (0 if dv1 == 10 else dv1) and n[10] == (0 if dv2 == 10 else dv2)


def cnpj_valido(cnpj: str) -> bool:
    d = limpio(cnpj)
    # Si trae letras, exige la puntuación oficial. Catorce caracteres
    # alfanuméricos sueltos son un trozo de hash con la misma probabilidad
    # que un CNPJ, y los archivos de bloqueo de dependencias están llenos.
    if any(c.isalpha() for c in d) and not any(x in cnpj for x in "./-"):
        return False
    if not re.fullmatch(r"[0-9A-Z]{12}\d{2}", d) or d == d[0] * 14:
        return False
    v = [ord(c) - 48 for c in d[:12]]        # regla oficial: ASCII menos 48
    r1 = sum(a * b for a, b in zip(v, _P1)) % 11
    dv1 = 0 if r1 < 2 else 11 - r1
    r2 = sum(a * b for a, b in zip(v + [dv1], _P2)) % 11
    dv2 = 0 if r2 < 2 else 11 - r2
    return int(d[12]) == dv1 and int(d[13]) == dv2


def detectores(cfg: Config) -> list[Detector]:
    d = []
    if cfg.activo("cpf"):
        # Refuerzo a pesar del doble dígito verificador: uno de cada cien
        # números de once dígitos lo pasa por azar, y las tablas de datos
        # (unicode, coordenadas, catálogos) están llenas de números de once
        # dígitos. Con puntos y guión dispara solo; a los dígitos pelones
        # se les exige la palabra que los nombre.
        d.append(Detector(
            nombre="cpf", descripcion="CPF brasileño (doble dígito verificador)",
            buscar=buscador(
                _CPF, cpf_valido, "cpf",
                "Es un CPF válido. Identifica a una persona física en Brasil "
                "y es la llave con la que se abre casi cualquier trámite.",
                exentos=EXENTOS_CPF,
                contexto=re.compile(r"(?i)\bcpf\b"),
                exige_refuerzo=True)))
    if cfg.activo("cnpj"):
        # La misma medicina que el CPF, por otra enfermedad: catorce
        # dígitos pelones también son una marca de tiempo — un timestamp
        # del Wayback Machine pasó el doble módulo 11 en un repo real.
        # Con la puntuación oficial dispara solo; a los dígitos corridos
        # se les exige la palabra que los nombre. (El vector vive en las
        # pruebas: citarlo aquí haría que Garita se encontrara a sí misma.)
        d.append(Detector(
            nombre="cnpj", descripcion="CNPJ brasileño, incluido el alfanumérico de 2026",
            buscar=buscador(
                _CNPJ, cnpj_valido, "cnpj",
                "Es un CNPJ válido. Identifica a una empresa; no es dato "
                "personal, pero suele venir acompañado de quien la representa.",
                exentos=EXENTOS_CNPJ,
                contexto=re.compile(r"(?i)\bcnpj\b"),
                exige_refuerzo=True)))
    return d
