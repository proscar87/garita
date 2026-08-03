#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
México: CURP, RFC, CLABE, NSS y teléfono.

POR QUÉ ESTO NO EXISTE EN OTRAS HERRAMIENTAS

Presidio (Microsoft) trae reconocedores para más de veinte países. México no
está. Las plataformas que sí lo cubren —Purview, Macie, Google DLP— son de
paga y viven lejos de git. Así que quien desarrolla en México y quiere que
un CURP no entre a un repositorio, hoy no tiene con qué.

POR QUÉ SE VALIDA EL DÍGITO Y NO SÓLO LA FORMA

Un detector que marca cualquier cadena de dieciocho caracteres como CURP
grita en falso todo el tiempo, y un guardián que grita en falso se acaba
ignorando. Ese día deja pasar el dato de verdad. Con el dígito verificador
la diferencia es de órdenes de magnitud:

    CURP    ~5,000 veces menos falsos positivos (dígito + fecha + entidad)
    RFC       ~300 veces menos (dígito + fecha)
    CLABE      ~90 veces menos (dígito + catálogo de bancos)
    NSS        ~10 veces menos (Luhn) — el más ruidoso, exige contexto
    Teléfono   sin dígito verificador; sólo estructura y contexto

Los algoritmos se verificaron reproduciendo identificadores de muestra
publicados por la autoridad. Las fuentes están en `docs/IDENTIFICADORES.md`.
"""
from __future__ import annotations

import re
from typing import Iterator

from ...config import Config
from ...nucleo import Detector, Hallazgo
from ._mx_ladas import LADAS


# ── CURP ───────────────────────────────────────────────────────────────────

# El alfabeto incluye la Ñ en la posición 24; no es el alfabeto corrido.
_CURP_ALFABETO = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"

_ENTIDADES = (
    "AS BC BS CC CL CM CS CH DF DG GT GR HG JC MC MN MS NT NL OC PL QT QR "
    "SP SL SR TC TS TL VZ YN ZS NE"
).split()

_CURP = re.compile(
    r"\b[A-Z][AEIOUX][A-Z]{2}"
    r"\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])"
    r"[HMX](" + "|".join(_ENTIDADES) + r")"
    r"[B-DF-HJ-NP-TV-ZÑ]{3}[0-9A-Z]\d\b",
    re.IGNORECASE,
)

# Claves de muestra que la propia autoridad publica en sus instructivos y
# constancias modelo. Pasan el dígito verificador, así que sin esta lista
# marcarían en cualquier documentación que las cite.
CURP_DE_MUESTRA = {
    "HEGG560427MVZRRL04",   # muestra histórica de RENAPO
    "SASO750909HDFNNS05",   # constancia modelo del instructivo vigente
    "ZUNA540308MNELTN05",   # constancia modelo para nacidos en el extranjero
}


def curp_valido(curp: str) -> bool:
    """Verifica el dígito de la posición 18.

    Suma el valor de cada carácter por su peso (18 hasta 2) y toma el
    complemento a 10 del módulo 10.
    """
    curp = curp.upper()
    if len(curp) != 18:
        return False
    try:
        suma = sum(_CURP_ALFABETO.index(c) * (18 - i)
                   for i, c in enumerate(curp[:17]))
    except ValueError:
        return False
    return str((10 - suma % 10) % 10) == curp[17]


# ── RFC ────────────────────────────────────────────────────────────────────

# Tabla del SAT. El `&` vale 24 y va ENTRE la N y la O: no es alfabeto
# corrido. El espacio vale 37 y la Ñ 38.
_RFC_VALOR = {c: v for v, c in enumerate("0123456789ABCDEFGHIJKLMN&OPQRSTUVWXYZ")}
_RFC_VALOR[" "] = 37
_RFC_VALOR["Ñ"] = 38

_RFC = re.compile(
    r"\b[A-ZÑ&]{3,4}"
    r"\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])"
    r"[A-Z0-9]{2}[0-9A]\b",
    re.IGNORECASE,
)

# Los RFC genéricos del SAT NO identifican a nadie: uno es "público en
# general" y el otro "residente en el extranjero". Se facturan millones de
# operaciones con ellos.
#
# Detalle que sólo se ve implementando: XEXX010101000 SÍ pasa el módulo 11,
# así que sin esta lista se marcaría. XAXX010101000 no lo pasa y se
# descartaría solo — se incluye de todas formas para que el comportamiento
# no dependa de esa casualidad.
RFC_GENERICOS = {"XAXX010101000", "XEXX010101000", "CACX7605101P8"}


def rfc_valido(rfc: str) -> bool:
    """Verifica el último carácter (módulo 11).

    A una persona moral (12 caracteres) se le antepone un espacio para
    completar 12 posiciones antes del dígito; ese espacio vale 37 y entra a
    la suma con peso 13.
    """
    rfc = rfc.upper()
    if len(rfc) not in (12, 13):
        return False
    cuerpo, dv = rfc[:-1], rfc[-1]
    s = cuerpo.rjust(12)
    try:
        suma = sum(_RFC_VALOR[c] * (13 - i) for i, c in enumerate(s))
    except KeyError:
        return False
    d = 11 - (suma % 11)
    esperado = "0" if d == 11 else "A" if d == 10 else str(d)
    return esperado == dv


# ── CLABE ──────────────────────────────────────────────────────────────────

# Los estados de cuenta imprimen la CLABE agrupada («0000-0000-0000-0000-00»),
# así que se aceptan guiones y espacios entre grupos y se quitan antes de
# validar. Sin esto, el formato en que un banco la entrega es justamente el
# que se escapa.
#
# El ejemplo de arriba a propósito NO pasa el dígito de control: la primera
# versión de este comentario traía una CLABE válida y Garita la marcó al
# revisarse a sí misma. Es la práctica que la herramienta recomienda —
# documentar formatos con valores que no validan— y la aprendimos siendo el
# primer usuario que la incumple.
_CLABE = re.compile(r"(?<![\d-])\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{2}(?![\d-])")
_SEPARADORES = re.compile(r"[\s-]")


def clabe_valida(clabe: str) -> bool:
    """Dígito de control: ponderación 3,7,1 cíclica, módulo 10."""
    if len(clabe) != 18 or not clabe.isdigit():
        return False
    pesos = [3, 7, 1] * 6
    suma = sum((int(d) * pesos[i]) % 10 for i, d in enumerate(clabe[:17]))
    return str((10 - suma % 10) % 10) == clabe[17]


# Códigos de institución vigentes del catálogo de la ABM/Banxico. El
# catálogo NO es un adorno: sin él, el dígito de control por sí solo deja
# pasar ~1 de cada 10 cadenas de 18 dígitos, y una tabla de constantes
# científicas produce decenas de falsos positivos — pasó, con cincuenta
# hallazgos en un solo archivo de numpy, todos con «bancos» inexistentes
# como 9568 o 4762.
#
# Se listan los tres primeros dígitos. Es un subconjunto de instituciones
# activas, no el catálogo completo: prefiero dejar pasar una CLABE de un
# banco recién autorizado que marcar cincuenta números que no lo son.
_BANCOS = {
    "002", "006", "009", "012", "014", "019", "021", "022", "030", "032",
    "036", "037", "040",
    "042", "044", "058", "059", "060", "062", "072", "103", "106", "108",
    "110", "112", "113", "116", "124", "126", "127", "128", "129", "130",
    "131", "132", "133", "135", "136", "137", "138", "139", "140", "141",
    "143", "145", "147", "148", "150", "151", "152", "154", "155", "156",
    "157", "158", "159", "160", "166", "168", "600", "601", "602", "605",
    "606", "607", "608", "610", "611", "613", "614", "615", "616", "617",
    "618", "619", "620", "621", "622", "623", "626", "627", "628", "629",
    "630", "631", "632", "633", "634", "636", "637", "638", "640", "642",
    "646", "647", "648", "649", "651", "652", "653", "655", "656", "659",
    "670", "677", "679", "684", "901", "902",
}


# La CLABE del material de difusión de la banca mexicana (la trae el
# instructivo de la ABM y medio tutorial en línea). Es el equivalente de la
# llave de ejemplo de AWS: aparecerá en documentación por siempre, y no es
# la cuenta de nadie.
CLABE_DE_MUESTRA = {"032180000118359719"}


def _clabe_es_relleno(clabe: str) -> bool:
    """Cuentas en ceros o nueves: son marcadores de documentación."""
    cuenta = clabe[6:17]
    return cuenta in ("0" * 11, "9" * 11)


def _banco_existe(clabe: str) -> bool:
    return clabe[:3] in _BANCOS


# ── NSS ────────────────────────────────────────────────────────────────────

_NSS = re.compile(r"(?<!\d)\d{11}(?!\d)")

# El NSS es el más ruidoso: once dígitos también son un teléfono con lada
# internacional, un folio o una CLABE truncada. Luhn corta el 90%, que no
# basta. Por eso además se exige contexto léxico en la misma línea — es el
# único detector que lo pide, y se documenta para que nadie lo tome por
# descuido.
_CONTEXTO_NSS = re.compile(
    r"(?i)\b(nss|n\.?s\.?s\.?|seguro\s+social|imss|afiliaci[oó]n|"
    r"n[uú]mero\s+de\s+seguridad)\b"
)


def nss_valido(nss: str) -> bool:
    """Dígito verificador por Luhn."""
    if len(nss) != 11 or not nss.isdigit():
        return False
    suma = 0
    for i, d in enumerate(nss[:10]):
        n = int(d) * (1 if i % 2 == 0 else 2)
        suma += n - 9 if n > 9 else n
    return str((10 - suma % 10) % 10) == nss[10]


# ── Teléfono ───────────────────────────────────────────────────────────────

# Desde el 3 de agosto de 2019 todos los números nacionales son de diez
# dígitos; los prefijos 01, 044 y 045 desaparecieron. Las ladas de dos
# dígitos son 55, 56, 33 y 81; el resto del país usa tres.
#
# El prefijo `521` sigue vivo aunque ya no se marque: los exports de
# WhatsApp lo usan en los identificadores, y un chat exportado es
# justamente el tipo de archivo que alguien versiona sin pensarlo.
# El prefijo va en su propio grupo. Sin eso no se puede distinguir un número
# con lada internacional de uno cuyos dos primeros dígitos son 52 por
# casualidad — y un identificador de diez dígitos que empieza en 52 es de lo
# más común. Preguntarle a la cadena «¿empiezas con 52?» marcaba como
# teléfono cualquier folio de ese rango: el falso positivo que habría vuelto
# inservible al detector.
_TELEFONO = re.compile(r"""
    (?<![\d.])
    (?P<prefijo>\+?52[\s.-]?1?[\s.-]?)?
    (?P<numero>
        (?P<lada2>55|56|33|81)[\s.-]?\d{4}[\s.-]?\d{4}
      | (?P<lada3>[2-9]\d{2})[\s.-]?\d{3}[\s.-]?\d{4}
    )
    (?![\d.])
""", re.VERBOSE)
# Las ramas llevan la lada en su propio grupo porque los dígitos solos no
# la determinan: diez dígitos que empiezan en 555 pueden agruparse
# 55-XXXX-XXXX (lada 55, CDMX) o 555-XXX-XXXX (el 555 ficticio de
# Norteamérica). La AGRUPACIÓN del número —2-4-4 contra 3-3-4— es la que
# dice cuál quiso escribir quien lo escribió.

_CONTEXTO_TEL = re.compile(
    r"(?i)\b(tel|tel[eé]fono|cel|celular|m[oó]vil|whats?app|contacto|"
    r"llamar|llamada|lada)\b"
)


# ── Ensamblado ─────────────────────────────────────────────────────────────

_ARREGLO_ID = (
    "Un identificador oficial señala a una persona por sí solo. Quítalo del "
    "archivo y usa una referencia interna (un número de lote, un id de "
    "registro). Si el dato es necesario, guárdalo en la base con control de "
    "acceso, no en el repositorio."
)


def _hallazgo(archivo, linea, det, valor, por_que) -> Hallazgo:
    # Los identificadores se recortan como los secretos: el registro de una
    # ejecución de CI suele verlo más gente que el propio repositorio.
    corto = valor if len(valor) <= 8 else f"{valor[:4]}…{valor[-2:]}"
    return Hallazgo(archivo=archivo, linea=linea, detector=det, que=corto,
                    por_que=por_que, como_arreglar=_ARREGLO_ID)


def _buscar_curp(texto: str, archivo: str) -> Iterator[Hallazgo]:
    for i, linea in enumerate(texto.splitlines(), 1):
        for m in _CURP.finditer(linea):
            v = m.group(0)
            if v.upper() in CURP_DE_MUESTRA or not curp_valido(v):
                continue
            yield _hallazgo(archivo, i, "curp", v,
                            "Es un CURP con dígito verificador válido. "
                            "Identifica a una persona de forma única e "
                            "incluye su fecha de nacimiento y su sexo.")


def _buscar_rfc(texto: str, archivo: str) -> Iterator[Hallazgo]:
    for i, linea in enumerate(texto.splitlines(), 1):
        for m in _RFC.finditer(linea):
            v = m.group(0)
            if v.upper() in RFC_GENERICOS or not rfc_valido(v):
                continue
            yield _hallazgo(archivo, i, "rfc", v,
                            "Es un RFC con dígito verificador válido. "
                            "Identifica a un contribuyente y, si es persona "
                            "física, contiene su fecha de nacimiento.")


def _buscar_clabe(texto: str, archivo: str) -> Iterator[Hallazgo]:
    for i, linea in enumerate(texto.splitlines(), 1):
        for m in _CLABE.finditer(linea):
            from ._comun import dentro_de_un_numero
            if dentro_de_un_numero(linea, m.start(), m.end()):
                continue
            v = _SEPARADORES.sub("", m.group(0))
            if (v in CLABE_DE_MUESTRA or not clabe_valida(v)
                    or _clabe_es_relleno(v) or not _banco_existe(v)):
                continue
            yield _hallazgo(archivo, i, "clabe", v,
                            "Es una CLABE con dígito de control válido. "
                            "Basta para depositar en esa cuenta y, con ella, "
                            "para intentar cargos.")


def _buscar_nss(texto: str, archivo: str) -> Iterator[Hallazgo]:
    for i, linea in enumerate(texto.splitlines(), 1):
        if not _CONTEXTO_NSS.search(linea):
            continue
        for m in _NSS.finditer(linea):
            v = m.group(0)
            if not nss_valido(v):
                continue
            yield _hallazgo(archivo, i, "nss", v,
                            "Es un número de seguridad social válido, "
                            "mencionado junto a palabras que lo confirman. "
                            "Da acceso a trámites del IMSS.")


def _buscar_telefono(texto: str, archivo: str) -> Iterator[Hallazgo]:
    for i, linea in enumerate(texto.splitlines(), 1):
        con_contexto = bool(_CONTEXTO_TEL.search(linea))
        for m in _TELEFONO.finditer(linea):
            v = m.group(0)
            # «Explícito» es que el REGEX haya capturado el prefijo, no que la
            # cadena empiece con esos dígitos.
            explicito = bool(m.group("prefijo"))
            separado = bool(re.search(r"[\s.-]", m.group("numero").strip()))
            # Sin prefijo, sin separadores y sin contexto, diez dígitos
            # seguidos son indistinguibles de un folio o una marca de tiempo.
            if not (explicito or separado or con_contexto):
                continue
            # La lada tiene que estar asignada en el Plan Nacional de
            # Numeración. Un 555, un 212 de Manhattan o un 202 de Washington
            # comparten el formato 3-3-4 pero NO son numeración mexicana:
            # reportarlos hacía ruido justo en los proyectos que más
            # documentan teléfonos. Esto aplica aun con prefijo +52: un
            # «+52 555…» es un número inventado para una prueba, no una
            # persona alcanzable.
            lada = m.group("lada2") or m.group("lada3")
            if lada not in LADAS:
                continue
            # Sólo el prefijo +52 vuelve esto una certeza. Un 3-3-4 sin
            # prefijo es tan mexicano como estadounidense y la palabra «tel»
            # en la línea no decide el país — por eso una lada válida de
            # tres dígitos (272 Córdoba, 961 Tuxtla) se queda en AVISO: la
            # coincidencia con un número extranjero es posible y forzar el
            # cero ahí sería cegar el detector. Con contexto y lada de dos
            # dígitos sí es error: ésas no existen fuera de México.
            severidad = ("error"
                         if (explicito or (con_contexto and len(lada) == 2))
                         else "aviso")
            h = _hallazgo(archivo, i, "telefono", v,
                          "Parece un teléfono mexicano. Un número de contacto "
                          "es dato personal y, a diferencia de un nombre, "
                          "permite contactar directamente a quien lo tiene.")
            yield Hallazgo(**{**h.__dict__, "severidad": severidad})


_DETECTORES = [
    ("curp", "CURP con dígito verificador válido", _buscar_curp),
    ("rfc", "RFC con dígito verificador válido", _buscar_rfc),
    ("clabe", "CLABE con dígito de control válido", _buscar_clabe),
    ("nss", "NSS del IMSS (exige contexto en la línea)", _buscar_nss),
    ("telefono", "teléfono de 10 dígitos con lada asignada en el PNN del IFT",
     _buscar_telefono),
]


def detectores(cfg: Config) -> list[Detector]:
    return [
        Detector(nombre=n, descripcion=d, buscar=f)
        for n, d, f in _DETECTORES
        if cfg.activo(n)
    ]
