#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
De dónde sale la lista de nombres prohibidos.

EL PROBLEMA QUE ESTO RESUELVE

Un guardián que compara contra una lista escrita en su propia configuración
tiene un defecto fatal: la lista es un dato personal más. Para impedir que
los nombres del padrón entren al repositorio, tendrías que escribir los
nombres del padrón en el repositorio. El remedio filtra lo que cura.

LA SALIDA

Casi todo proyecto serio que maneja datos reales ya tiene un generador de
datos sintéticos para sus pruebas y su `seed`. Ese generador necesita saber
qué nombres reales NO debe producir por accidente, así que ya contiene la
lista — y ya vive donde debe, con su propio control de acceso.

Este módulo la lee de ahí, por AST, sin ejecutar el archivo. Así:

  · No hay dos listas que mantener sincronizadas. Cuando alguien agrega un
    propietario al generador, el guardián se entera solo.
  · La lista no se transcribe a la configuración del guardián.
  · Si el archivo desaparece o le quitan la constante, el guardián FALLA
    RUIDOSAMENTE en vez de quedarse ciego y aprobar todo. Un guardián ciego
    que dice "OK" es peor que no tener guardián, porque genera confianza.

Se lee por AST y no con `import` a propósito: importar ejecuta código
arbitrario del repositorio revisado dentro del proceso del guardián, en CI,
normalmente con permisos de escritura sobre el propio repositorio. `ast` lo
lee como texto y no ejecuta nada.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path


class FuenteInvalida(Exception):
    """La lista no se pudo leer. Nunca se degrada a lista vacía."""


def _de_python(ruta: Path, constante: str) -> list[str]:
    """Extrae una constante literal de un archivo Python, sin ejecutarlo."""
    try:
        arbol = ast.parse(ruta.read_text(encoding="utf-8-sig"))
    except (OSError, SyntaxError) as e:
        raise FuenteInvalida(f"no pude leer {ruta}: {e}") from e

    for nodo in ast.walk(arbol):
        if not isinstance(nodo, (ast.Assign, ast.AnnAssign)):
            continue
        objetivos = nodo.targets if isinstance(nodo, ast.Assign) else [nodo.target]
        if not any(getattr(t, "id", None) == constante for t in objetivos):
            continue
        if nodo.value is None:
            continue
        try:
            valor = ast.literal_eval(nodo.value)
        except ValueError as e:
            raise FuenteInvalida(
                f"{constante} en {ruta} no es un literal. Debe ser una lista "
                f"de cadenas escrita directamente, no construida en tiempo de "
                f"ejecución: si se calcula, este guardián no puede leerla sin "
                f"ejecutar el archivo, y ejecutar código del repositorio "
                f"revisado dentro del guardián es justo lo que evitamos."
            ) from e
        return _normalizar(valor, f"{ruta}:{constante}")

    raise FuenteInvalida(
        f"no encontré la constante {constante} en {ruta}. Sin ella este "
        f"guardián queda ciego: restaura la constante o corrige la ruta en la "
        f"configuración. No se continúa con una lista vacía porque un "
        f"guardián que aprueba todo es peor que ninguno."
    )


def _de_json(ruta: Path, llave: str) -> list[str]:
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as e:
        raise FuenteInvalida(f"no pude leer {ruta}: {e}") from e
    actual = datos
    for parte in llave.split("."):
        if not isinstance(actual, dict) or parte not in actual:
            raise FuenteInvalida(f"no encontré la llave '{llave}' en {ruta}")
        actual = actual[parte]
    return _normalizar(actual, f"{ruta}:{llave}")


def _de_texto(ruta: Path) -> list[str]:
    """Un nombre por línea. `#` comenta."""
    try:
        lineas = ruta.read_text(encoding="utf-8-sig").splitlines()
    except OSError as e:
        raise FuenteInvalida(f"no pude leer {ruta}: {e}") from e
    return _normalizar(
        [l.split("#")[0].strip() for l in lineas],
        str(ruta),
    )


def _normalizar(valor: object, origen: str) -> list[str]:
    if not isinstance(valor, (list, tuple, set)):
        raise FuenteInvalida(f"{origen} no es una lista")
    fuera = [str(v).strip() for v in valor if str(v).strip()]
    if not fuera:
        raise FuenteInvalida(
            f"{origen} está vacía. Si de verdad no hay nombres que proteger, "
            f"desactiva el detector 'nombre' en la configuración en vez de "
            f"dejar una lista vacía: así queda explícito y no parece un "
            f"descuido."
        )
    # Descartar entradas demasiado cortas: un patrón de 2 letras casa con
    # medio repositorio y ahoga el reporte en falsos positivos.
    cortas = [f for f in fuera if len(f) < 3]
    if cortas:
        raise FuenteInvalida(
            f"{origen} tiene entradas de menos de 3 caracteres ({cortas}). "
            f"Un patrón tan corto casa con casi cualquier texto y llenaría el "
            f"reporte de falsos positivos, que es como se acaba ignorando un "
            f"guardián."
        )
    return sorted(set(fuera))


def existe(spec: str, raiz: Path) -> bool:
    """¿El archivo de la fuente está en esta máquina?

    Existe para las fuentes OPCIONALES (prefijo «?» en la configuración):
    la ausencia se tolera avisando, pero sólo la ausencia — un archivo
    presente y roto sigue tronando, porque opcional no es perdonado.
    """
    rel = spec.rsplit(":", 1)[0] if ":" in spec else spec
    return (raiz / rel).is_file()


def cargar(spec: str, raiz: Path) -> list[str]:
    """Carga una lista desde una especificación de la configuración.

    Formatos admitidos:

        ruta/generador.py:PROHIBIDOS     constante de Python, por AST
        ruta/datos.json:padron.nombres   llave de JSON, con puntos
        ruta/nombres.txt                 uno por línea

    La ruta se resuelve contra la raíz del repositorio revisado.
    """
    if ":" in spec:
        rel, llave = spec.rsplit(":", 1)
    else:
        rel, llave = spec, None

    ruta = (raiz / rel).resolve()
    # Un `..` en la especificación podría leer fuera del repositorio.
    if not str(ruta).startswith(str(raiz.resolve())):
        raise FuenteInvalida(
            f"la fuente '{spec}' apunta fuera del repositorio. Sólo se leen "
            f"archivos del propio proyecto."
        )
    if not ruta.is_file():
        raise FuenteInvalida(
            f"no existe {rel}. Es la fuente de la lista de nombres a proteger; "
            f"sin ella el guardián no puede hacer su trabajo."
        )

    if ruta.suffix == ".py":
        if not llave:
            raise FuenteInvalida(
                f"para un archivo Python indica la constante: '{rel}:NOMBRE'"
            )
        return _de_python(ruta, llave)
    if ruta.suffix == ".json":
        if not llave:
            raise FuenteInvalida(
                f"para un archivo JSON indica la llave: '{rel}:llave.anidada'"
            )
        return _de_json(ruta, llave)
    return _de_texto(ruta)


def a_patron(nombres: list[str]) -> re.Pattern[str]:
    """Une los nombres en una expresión regular con fronteras de palabra.

    Sin fronteras, "Ana" casaría dentro de "banana" y "Sonora". Con ellas,
    sólo casa cuando es la palabra. Se ignoran mayúsculas y se toleran los
    acentos ausentes, porque un padrón y un CSV rara vez coinciden en ellos
    y un nombre sin acento sigue identificando a la misma persona.
    """
    alternos = []
    for n in nombres:
        suelto = "".join(_flexible(c) for c in n)
        alternos.append(suelto)
    return re.compile(r"\b(?:" + "|".join(alternos) + r")\b", re.IGNORECASE)


_ACENTOS = {
    "a": "aá", "e": "eé", "i": "ií", "o": "oó", "u": "uúü", "n": "nñ",
    "á": "aá", "é": "eé", "í": "ií", "ó": "oó", "ú": "uúü", "ñ": "nñ",
}


def _flexible(c: str) -> str:
    bajo = c.lower()
    if bajo in _ACENTOS:
        return f"[{_ACENTOS[bajo]}]"
    return re.escape(c)
