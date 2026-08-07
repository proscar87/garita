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


_SEPARA_CAMPO = frozenset(",;\t|")


def _es_campo_completo(linea: str, ini: int, fin: int) -> bool:
    """¿La coincidencia ocupa una celda entera de una fila delimitada?"""
    antes = linea[:ini].rstrip()
    despues = linea[fin:].lstrip()
    izq = not antes or antes[-1] in _SEPARA_CAMPO
    der = not despues or despues[0] in _SEPARA_CAMPO
    return izq and der


def dentro_de_un_numero(linea: str, ini: int, fin: int) -> bool:
    """¿La coincidencia es parte de un literal numérico más largo?

    LA COMA PEGADA NO CUENTA COMO PUNTO DECIMAL. Contarla convertía la coma
    del CSV en prueba de literal numérico, y una fila
    `nombre,edad,<CLABE>,saldo` —el formato en que viaja un padrón— se
    descartaba entera antes de mirar nada más. La tabla de decimales con
    coma europea sigue cubierta por la ventana de abajo, que necesita tres
    coincidencias.

    Y la ventana se cuenta SIN la coincidencia: los separadores internos
    del propio identificador («12.345.678» aporta dos pares) la llevaban al
    umbral por sí solos, así que arreglar los bordes no bastaba.
    """
    izq = linea[max(0, ini - 3):ini]
    der = linea[fin:fin + 4]
    if re.search(r"[\d.][eE][+-]?$|[\d]\.$", izq):
        return True
    if re.match(r"[eE][+-]?\d|\.\d", der):
        return True
    # Si la coincidencia es un CAMPO COMPLETO —delimitada por separadores a
    # los dos lados, o por los bordes de la línea— no vive dentro de ningún
    # número, y la heurística de tabla no aplica. Sin esto, una fila de
    # export bancario («cuenta, monto, comisión, IVA») llegaba a las tres
    # coincidencias de la ventana con sus propios importes y la CLABE
    # VÁLIDA se descartaba antes de validar nada: el formato en que viaja
    # un padrón, otra vez.
    if _es_campo_completo(linea, ini, fin):
        return False
    # Un contexto lleno de comas y puntos entre dígitos es una tabla numérica.
    ventana = linea[max(0, ini - 24):ini] + " " + linea[fin:fin + 24]
    return len(_ES_NUMERO.findall(ventana)) >= 3


_SEPARA_TOKEN = frozenset(" \t'\"<,;|")
# Una «URL» de más de dos mil caracteres pegados no es una URL: es un
# volcado. El tope evita que una línea minificada se recorra entera.
_TOKEN_MAXIMO = 2048


def dentro_de_url(linea: str, ini: int) -> bool:
    """¿La coincidencia vive dentro de una URL?

    Los CDN y las wikis cargan tiras de dígitos que validan por azar: un
    identificador de foto de Instagram pasa el módulo de la CLABE y un
    cache-buster pasa el del CNPJ. Dentro de una URL el hallazgo BAJA A
    AVISO — no se calla, porque una CLABE en la ruta de un API sí puede
    ser una fuga real, y cegarse está prohibido. Pero tampoco grita: en
    datos raspados de internet, un error por cada foto es la clase de
    ruido que desinstala guardianes.

    La coma corta el token igual que el espacio: en `Juan,https://…,<CLABE>`
    la CLABE es una COLUMNA APARTE, no parte de la URL, y sin cortar ahí el
    error se degradaba a aviso y el veredicto salía 0 — justo en datos
    raspados, que es donde ese layout es la norma."""
    # Se camina hacia atrás desde la coincidencia hasta el primer
    # separador, con tope. Las dos versiones anteriores recorrían todo el
    # prefijo de la línea en cada coincidencia —primero copiándolo, luego
    # con siete `rfind` que, al no encontrar su carácter, lo barrían
    # entero—, así que una línea larga con muchos hallazgos seguía
    # costando O(n) por hallazgo. Ahora cuesta lo que mida el token.
    inicio = ini
    tope = max(0, ini - _TOKEN_MAXIMO)
    while inicio > tope and linea[inicio - 1] not in _SEPARA_TOKEN:
        inicio -= 1
    token = linea[inicio:ini]
    return "://" in token or token.startswith("www.")


def limpio(v: str) -> str:
    return SEPARADORES.sub("", v).upper()


def recortar(v: str) -> str:
    """Nunca el valor completo, ni siquiera en el reporte local.

    NUNCA quiere decir nunca: el `if len(v) <= 8` que había aquí devolvía
    íntegras las cédulas uruguayas y los RUT chilenos de ocho dígitos, y
    ese valor viajaba al SARIF —que la pestaña Security muestra a más
    gente que el repositorio— y a la tabla del HTML, cuyo pie jura que
    ningún valor completo aparece. El documento no puede mentir sobre sí
    mismo, y menos re-filtrando el dato que denuncia.
    """
    if len(v) <= 4:
        return "…" * len(v)
    if len(v) <= 8:
        return f"{v[:2]}…{v[-1:]}"
    return f"{v[:4]}…{v[-2:]}"


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
