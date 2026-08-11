#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
España: DNI, NIE, CIF e IBAN.

El IBAN español es el detector más limpio de toda la herramienta: valida dos
veces —el módulo 97 del IBAN y los dos dígitos de control internos del CCC
que envuelve— y eso deja la tasa de falsos positivos en 0.0095%. Cuatro
órdenes de magnitud mejor que un patrón de forma.

El CIF es el más flojo: las letras que admiten control numérico O alfabético
aceptan dos de veinte posibilidades, así que deja pasar ~7%. Por eso exige
refuerzo.
"""
from __future__ import annotations

import re

from ...config import Config
from ...nucleo import Detector
from ._comun import bases_de_relleno, buscador, limpio

_TABLA = "TRWAGMYFPDXBNJZSQVHLCKE"
# Con separador de MILLARES además del guion: «12.345.678-Z» es como se
# escribe un DNI en una carta, una factura o una hoja de cálculo española,
# y sin admitirlo esa forma era invisible. El punto no cuenta como refuerzo
# —eso lo decide `_comun` con su propia regla— así que admitirlo aquí no
# afloja nada: sólo deja que el validador llegue a verlo.
_DNI = re.compile(
    r"(?<![\w.-])(?:\d{8}|\d{2}\.\d{3}\.\d{3})\s?-?\s?[A-Za-z](?![\w-])")
_NIE = re.compile(
    r"(?<![\w.-])[XYZxyz]\s?-?\s?(?:\d{7}|\d\.\d{3}\.\d{3})"
    r"\s?-?\s?[A-Za-z](?![\w-])")
# «B-12345678» es la forma más común por escrito, y sin admitirla la rama
# de separadores del refuerzo quedaba muerta. Pero el separador es el
# GUION, nunca el espacio solo: con \s en la regex, el mismo espacio que
# permitía el match satisfacía el refuerzo de _comun, y una letra con siete
# dígitos y un control separados por espacios disparaba como error sin
# palabra alguna — la lección del espacio como señal demasiado débil para
# un solo carácter de control.
_CIF = re.compile(
    r"(?<![\w-])[A-HJ-NP-SUVWa-hj-np-suvw](?:\s?-\s?)?\d{7}(?:\s?-\s?)?[0-9A-Ja-j](?![\w-])")
_IBAN = re.compile(r"(?<![\w])ES\s?\d{2}(?:\s?\d{4}){5}(?![\w])", re.IGNORECASE)

_CTRL_CIF = "JABCDEFGHI"
_ORG = "ABCDEFGHJKLMNPQRSUVW"

# Ejemplos que la propia autoridad publica, más el NIF de los certificados de
# prueba de la FNMT: aparecen en miles de documentos y en fixtures reales.

# El sustantivo va en plural opcional: el encabezado de una columna, la
# clave de un YAML y el nombre de una variable casi siempre lo llevan
# («cedulas», «rucs», «contribuyentes»), y con el `\b` pegado al
# singular el detector con contexto obligatorio quedaba CIEGO sobre
# justo la forma en que se exporta un padrón. Los acrónimos que en
# plural chocan con una palabra común («run»→«runs») se quedan sin la
# «s» a propósito: una palabra de contexto envenenada es peor que la
# forma que deja de casar.
_CONTEXTO = re.compile(r"(?i)\b(dnis?|nies?|nifs?|cifs?|documentos?|identidad(?:es)?|s\.?[la]\.?)\b")


def dni_valido(v: str) -> bool:
    m = re.fullmatch(r"(\d{8})([A-Z])", limpio(v))
    return bool(m) and _TABLA[int(m.group(1)) % 23] == m.group(2)


def nie_valido(v: str) -> bool:
    m = re.fullmatch(r"([XYZ])(\d{7})([A-Z])", limpio(v))
    if not m:
        return False
    n = int(str("XYZ".index(m.group(1))) + m.group(2))
    return _TABLA[n % 23] == m.group(3)


def cif_valido(v: str) -> bool:
    m = re.fullmatch(r"([A-Z])(\d{7})([0-9A-J])", limpio(v))
    if not m or m.group(1) not in _ORG:
        return False
    s = 0
    for i, ch in enumerate(m.group(2)):
        n = int(ch) * 2 if i % 2 == 0 else int(ch)
        s += n // 10 + n % 10
    c = (10 - s % 10) % 10
    dig, let = str(c), _CTRL_CIF[c]
    # La Orden EHA/451/2008 fija qué letras exigen control numérico, cuáles
    # alfabético y cuáles admiten ambos.
    if m.group(1) in set("KPQRSNW"):
        return m.group(3) == let
    if m.group(1) in set("ABEH"):
        return m.group(3) == dig
    return m.group(3) in (dig, let)


def _rellenos_validos() -> set[str]:
    """Los rellenos de DNI y de CIF que pasan su control.

    La letra del DNI es el resto módulo 23, así que los ocho repetidos y el
    secuencial SIEMPRE producen un DNI válido: «11111111H» y sus hermanos
    son el fixture más común de cualquier proyecto español y disparaban
    como una persona. El CIF es peor: trece de las veinte letras de
    organización admiten control numérico o alfabético, así que «A00000000»
    y «U-00000000» —el marcador de «pendiente de alta»— validan igual.

    Se generan con los mismos validadores del módulo: una lista escrita a
    mano envejece en cuanto cambie el algoritmo, y una lista incompleta es
    la que hace que alguien apague el detector.
    """
    fuera = set()
    for cuerpo in bases_de_relleno(8):
        v = cuerpo + _TABLA[int(cuerpo) % 23]
        if dni_valido(v):
            fuera.add(v)
    for org in _ORG:
        for cuerpo in bases_de_relleno(7):
            for ctrl in "0123456789" + _CTRL_CIF:
                v = f"{org}{cuerpo}{ctrl}"
                if cif_valido(v):
                    fuera.add(v)
    return fuera


# Ejemplos que la propia autoridad publica, más el NIF de los certificados
# de prueba de la FNMT, más los rellenos que validan por construcción.
EXENTOS = {"12345678Z", "00000000T", "99999999R"} | _rellenos_validos()


def _dc_ccc(pesos, digitos) -> int:
    r = sum(int(d) * p for d, p in zip(digitos, pesos)) % 11
    r = 11 - r
    return 0 if r == 11 else 1 if r == 10 else r


def iban_valido(v: str) -> bool:
    d = limpio(v)
    if not re.fullmatch(r"ES\d{22}", d):
        return False
    # Módulo 97 del IBAN.
    reordenado = d[4:] + d[:4]
    numerico = "".join(str(ord(c) - 55) if c.isalpha() else c for c in reordenado)
    if int(numerico) % 97 != 1:
        return False
    # Y los dos dígitos de control internos del CCC que envuelve. Validar los
    # dos es lo que lleva la tasa de ruido de ~1% a 0.0095%.
    ccc = d[4:]
    pesos = [1, 2, 4, 8, 5, 10, 9, 7, 3, 6]
    if _dc_ccc(pesos, "00" + ccc[:8]) != int(ccc[8]):
        return False
    return _dc_ccc(pesos, ccc[10:]) == int(ccc[9])


def detectores(cfg: Config) -> list[Detector]:
    d = []
    if cfg.activo("dni_es"):
        d.append(Detector("dni_es", "DNI español (letra de control)", buscador(
            _DNI, dni_valido, "dni_es",
            "Es un DNI español con letra de control válida. Identifica a una "
            "persona de forma única.", EXENTOS, _CONTEXTO, exige_refuerzo=True)))
    if cfg.activo("nie"):
        # Una sola letra de control (1/23) → refuerzo, como el DNI y como
        # manda la regla de _comun: «lote X1234567L» valida por azar.
        d.append(Detector("nie", "NIE español", buscador(
            _NIE, nie_valido, "nie",
            "Es un NIE con letra de control válida. Identifica a una persona "
            "extranjera residente.", EXENTOS, _CONTEXTO, exige_refuerzo=True)))
    if cfg.activo("cif"):
        d.append(Detector("cif", "CIF de entidad española", buscador(
            _CIF, cif_valido, "cif",
            "Es un CIF válido. Identifica a una entidad; no es dato personal, "
            "pero suele venir junto a quien la administra.",
            EXENTOS, _CONTEXTO, exige_refuerzo=True)))
    if cfg.activo("iban_es"):
        d.append(Detector("iban_es", "IBAN español (módulo 97 + control del CCC)", buscador(
            _IBAN, iban_valido, "iban_es",
            "Es un IBAN español válido. Basta para domiciliar cargos contra "
            "esa cuenta.")))
    return d
