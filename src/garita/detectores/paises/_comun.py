#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lo que comparten los paquetes de país.

LA REGLA DE LOS DÍGITOS ÚNICOS

Un identificador con UN dígito verificador módulo 11 deja pasar cerca de 1 de
cada 10 cadenas de esa forma. Suena bien hasta que se recuerda contra qué
compite: números de teléfono, folios, marcas de tiempo, identificadores de
pedido. Sobre datos de la vida real ese 10% sigue siendo mucho ruido.

Por eso los identificadores de un solo dígito exigen, además de la
validación, **formato con separadores o contexto léxico en la línea**. Los de
doble dígito (CPF, CNPJ) y el IBAN pueden vivir sin eso: sus tasas están dos
órdenes de magnitud más abajo.

No es una precaución teórica. La diferencia entre una herramienta que se
conserva y una que se desinstala está casi siempre aquí.
"""
from __future__ import annotations

import re
from typing import Iterator

from ...nucleo import Hallazgo

SEPARADORES = re.compile(r"[.\-\s/]")

# Un identificador no vive dentro de un número. La mantisa de un doble en
# notación científica tiene dieciocho dígitos y un punto de por medio, así que
# se lee como «CLABE agrupada»; una tabla de constantes producía decenas de
# hallazgos. El punto decimal NO es un separador de identificador.
_ES_NUMERO = re.compile(r"[0-9][.,][0-9]|[eE][+-]?\d|0[xXbBo]")


def dentro_de_un_numero(linea: str, ini: int, fin: int) -> bool:
    """¿La coincidencia es parte de un literal numérico más largo?"""
    izq = linea[max(0, ini - 3):ini]
    der = linea[fin:fin + 4]
    if re.search(r"[\d.][eE][+-]?$|[\d][.,]$", izq):
        return True
    if re.match(r"[eE][+-]?\d|[.,]\d", der):
        return True
    # Un contexto lleno de comas y puntos entre dígitos es una tabla numérica.
    ventana = linea[max(0, ini - 24):fin + 24]
    return len(_ES_NUMERO.findall(ventana)) >= 3


def dentro_de_url(linea: str, ini: int) -> bool:
    """¿La coincidencia vive dentro de una URL?

    Los CDN y las wikis cargan tiras de dígitos que validan por azar: un
    identificador de foto de Instagram pasa el módulo de la CLABE y un
    cache-buster pasa el del CNPJ. Dentro de una URL el hallazgo BAJA A
    AVISO — no se calla, porque una CLABE en la ruta de un API sí puede
    ser una fuga real, y cegarse está prohibido. Pero tampoco grita: en
    datos raspados de internet, un error por cada foto es la clase de
    ruido que desinstala guardianes."""
    pedazo = linea[:ini]
    corte = max(pedazo.rfind(" "), pedazo.rfind("\t"),
                pedazo.rfind("'"), pedazo.rfind('"'), pedazo.rfind("<"))
    token = pedazo[corte + 1:]
    return "://" in token or token.startswith("www.")


def limpio(v: str) -> str:
    return SEPARADORES.sub("", v).upper()


def recortar(v: str) -> str:
    """Nunca el valor completo, ni siquiera en el reporte local."""
    return v if len(v) <= 8 else f"{v[:4]}…{v[-2:]}"


ARREGLO = (
    "Un identificador oficial señala a una persona o entidad por sí solo. "
    "Quítalo del archivo y usa una referencia interna. Si el dato es "
    "necesario, guárdalo en la base con control de acceso, no en el "
    "repositorio."
)


def hallazgo(archivo, linea, detector, valor, por_que, severidad="error"):
    return Hallazgo(archivo=archivo, linea=linea, detector=detector,
                    que=recortar(valor), por_que=por_que,
                    como_arreglar=ARREGLO, severidad=severidad)


def buscador(
    patron: re.Pattern[str],
    validar,
    detector: str,
    por_que: str,
    exentos: set[str] = frozenset(),
    contexto: re.Pattern[str] | None = None,
    exige_refuerzo: bool = False,
    exige_contexto: bool = False,
):
    """Arma un buscador de línea con la política de refuerzo.

    `exige_refuerzo` marca los identificadores de un solo dígito verificador:
    además de validar, la coincidencia tiene que traer separadores o venir
    acompañada de una palabra que la nombre.

    `exige_contexto` es el escalón de arriba, para identificadores SIN dígito
    verificador (el SSN estadounidense): la validación estructural sola deja
    pasar demasiado, así que la palabra que lo nombre es obligatoria — el
    formato no basta, porque tres-dos-cuatro con guiones también es un
    número de parte o un folio.
    """
    def buscar(texto: str, archivo: str) -> Iterator[Hallazgo]:
        for i, linea in enumerate(texto.splitlines(), 1):
            hay_contexto = bool(contexto.search(linea)) if contexto else False
            for m in patron.finditer(linea):
                bruto = m.group(0)
                v = limpio(bruto)
                if v in exentos or not validar(v):
                    continue
                if dentro_de_un_numero(linea, m.start(), m.end()):
                    continue
                if exige_contexto and not hay_contexto:
                    continue
                if exige_refuerzo:
                    # Un punto decimal no cuenta como formato de identificador:
                    # sólo guiones, espacios o barras.
                    con_formato = bool(re.search(r"[-\s/]", bruto.strip()))
                    if not (con_formato or hay_contexto):
                        continue
                sev = "aviso" if dentro_de_url(linea, m.start()) else "error"
                yield hallazgo(archivo, i, detector, v, por_que, severidad=sev)
    return buscar
