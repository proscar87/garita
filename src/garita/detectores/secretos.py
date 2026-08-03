#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detectores de credenciales.

POR QUÉ ESTO EXISTE SI YA HAY HERRAMIENTAS DE SECRETOS

Porque la mitad de las fugas reales no son un token suelto: son un archivo
de configuración de ejemplo que alguien llenó con valores verdaderos "un
momentito para probar", y ahí se quedó. Un detector que sólo busca formatos
canónicos de proveedor no ve eso.

Aquí los patrones exigen ESTRUCTURA, no solo forma. Un JWT son tres partes
separadas por punto y sus dos primeras empiezan en `eyJ` porque son el
base64 de `{"`. Buscar únicamente `eyJ` marca los hashes `sha512-` de
cualquier `package-lock.json`, donde esas letras salen por coincidencia de
base64 — pasó, y perseguir ese falso positivo es exactamente cómo un equipo
aprende a ignorar a su guardián. Ese día deja pasar el secreto de verdad.
"""
from __future__ import annotations

import re
from re import error
from typing import Iterator

from ..nucleo import Hallazgo, recortar


def _h(archivo, linea, det, que, por_que, arreglo) -> Hallazgo:
    return Hallazgo(archivo=archivo, linea=linea, detector=det, que=que,
                    por_que=por_que, como_arreglar=arreglo)


# Rotar primero, limpiar después. Un secreto que llegó a un repositorio se
# considera quemado aunque el repositorio sea privado: estuvo en el disco de
# cada persona que clonó, en el caché de CI y en los respaldos. Reescribir el
# historial sin rotar da una sensación de limpieza sin quitar el riesgo.
ARREGLO_LLAVE = (
    "ROTA la credencial primero (eso invalida la copia filtrada); recién "
    "después limpia el archivo. Guárdala en el gestor de secretos del "
    "entorno o en un .env ignorado por git."
)

PATRONES: list[tuple[str, re.Pattern[str], str, str]] = [
    (
        "jwt",
        # Dos segmentos base64url que arrancan en `eyJ`, separados por punto:
        # cabecera y carga útil de un JWT. Exigir el segundo no afloja la red,
        # la aprieta — descarta los hashes que sólo contienen `eyJ` de paso.
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"),
        "Un JWT suele llevar dentro el rol y el proyecto; con la llave de "
        "servicio de un backend se salta cualquier control de acceso por fila.",
        ARREGLO_LLAVE,
    ),
    (
        "llave_privada",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Una llave privada da acceso directo, y a diferencia de una "
        "contraseña nadie la cambia por rutina.",
        ARREGLO_LLAVE,
    ),
    (
        "llave_proveedor",
        re.compile(
            r"\b("
            r"sb_secret_[A-Za-z0-9_-]{10,}"      # Supabase
            r"|sk-[A-Za-z0-9]{20,}"               # OpenAI y similares
            r"|sk-ant-[A-Za-z0-9_-]{20,}"         # Anthropic
            r"|ghp_[A-Za-z0-9]{36}"               # GitHub personal
            r"|github_pat_[A-Za-z0-9_]{22,}"      # GitHub fine-grained
            r"|AKIA[0-9A-Z]{16}"                  # AWS
            r"|AIza[0-9A-Za-z_-]{35}"             # Google
            r"|xox[baprs]-[A-Za-z0-9-]{10,}"      # Slack
            r"|glpat-[A-Za-z0-9_-]{20}"           # GitLab
            r")\b"
        ),
        "Es una credencial con formato reconocible de proveedor; quien "
        "rastrea repositorios busca exactamente estos prefijos.",
        ARREGLO_LLAVE,
    ),
    (
        "credencial_en_url",
        # Usuario y contraseña dentro de una URL de conexión. Es el formato en
        # que viajan las cadenas de base de datos y el que más se pega en un
        # archivo de ejemplo "de momento".
        re.compile(
            r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:(?P<secreto>[^/\s:@]{6,})@[^\s/]+",
            re.IGNORECASE,
        ),
        "Una cadena de conexión con contraseña embebida. Suele acabar en un "
        "archivo de ejemplo porque alguien la pegó para probar.",
        ARREGLO_LLAVE,
    ),
]

# Valores que a todas luces son marcadores de posición. Marcarlos empuja a la
# gente a poner algo «más realista» en la documentación, que es peor: la
# documentación se copia tal cual.
#
# SE EVALÚA SOBRE EL VALOR, NUNCA SOBRE LA LÍNEA. La primera versión
# descartaba la línea completa si contenía alguna de estas palabras, y eso
# abría un boquete: una credencial REAL en
#
#     DATABASE_URL=postgres://admin:tu_clave@db.example.com:5432/prod
#
# pasaba sin más, porque el host decía «example». Un comentario `# ejemplo`
# al final de la línea tenía el mismo efecto. Era simultáneamente el peor
# falso negativo y una causa de falsos positivos, porque tampoco se aplicaba
# donde sí correspondía: `AKIAIOSFODNN7EXAMPLE`, la llave canónica de la
# documentación de AWS, se marcaba por no casar con la frontera de palabra.
MARCADORES = re.compile(
    r"(?i)(tu[_-]?\w+|your[_-]?\w+|mi[_-]?(clave|llave|secreto)|xxx+|placeholder"
    r"|cambiame|change[_-]?me"
    r"|ejemplo|example|dummy|fake|test[_-]?key|redacted|s3cr3t|hunter2"
    r"|lorem|ipsum)$|^(pass(word)?|clave|secreto|secret|contrase[nñ]a|user|usuario|admin|root|token|apikey)$"
)

# Éstos sólo son marcador si constituyen casi todo el valor: «abcdef» dentro
# de una llave aleatoria de cuarenta caracteres no la vuelve un ejemplo.
_RELLENO = re.compile(r"(?i)^[\W_]*(abcdef(ghi?j?k?)?|123456(789?0?)?|foo|bar|baz)[\W_\d]*$")


def es_marcador(valor: str) -> bool:
    """¿El VALOR es un marcador de posición? No la línea: el valor."""
    v = valor.strip("\"'")
    if not v or v.startswith("<") or v.startswith("${") or v.startswith("$("):
        return True
    if MARCADORES.search(v) or _RELLENO.match(v):
        return True
    # Un valor de un solo carácter repetido no es un secreto.
    nucleo = re.sub(r"[^A-Za-z0-9]", "", v)
    return bool(nucleo) and len(set(nucleo.lower())) <= 2


def _jwt_de_demostracion(token: str) -> bool:
    """¿La carga útil del JWT delata que es de ejemplo?

    Un JWT lleva sus datos en base64 a la vista. Si al decodificarlos aparece
    un emisor de juguete o una expiración de hace años, es de demostración.
    Preferible a apagar el detector en `docs/`: ahí un JWT REAL sí sería una
    fuga, y es donde más se pegan por descuido.
    """
    import base64
    import json
    import time
    partes = token.split(".")
    if len(partes) < 2:
        return False
    try:
        relleno = partes[1] + "=" * (-len(partes[1]) % 4)
        carga = json.loads(base64.urlsafe_b64decode(relleno))
    except Exception:
        return False
    if not isinstance(carga, dict):
        return False
    # Expirado hace más de un año: ya no es una credencial, es un ejemplo.
    exp = carga.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time() - 31_536_000:
        return True
    texto_carga = json.dumps(carga).lower()
    return any(m in texto_carga for m in
               ("example", "ejemplo", "demo", "test", "foo", "1234567890",
                "john doe", "jane doe", "sample"))


def buscar(texto: str, archivo: str) -> Iterator[Hallazgo]:
    for i, linea in enumerate(texto.splitlines(), 1):
        for nombre, rx, por_que, arreglo in PATRONES:
            # `finditer`, no `search`: dos credenciales en una línea son dos
            # hallazgos. Con `search` la segunda quedaba invisible.
            for m in rx.finditer(linea):
                # Si el patrón aísla la parte sensible, el marcador se juzga
                # sobre ELLA. Una URL con host «example» y contraseña real
                # sigue siendo una fuga.
                try:
                    sensible = m.group("secreto")
                except (IndexError, error):
                    sensible = m.group(0)
                if es_marcador(sensible or m.group(0)):
                    continue
                if nombre == "jwt" and _jwt_de_demostracion(m.group(0)):
                    continue
                yield _h(archivo, i, nombre, recortar(m.group(0)), por_que, arreglo)


# ── Asignaciones sospechosas ───────────────────────────────────────────────
#
# Aparte de los formatos conocidos, hay un patrón que atrapa lo que ningún
# catálogo cubre: una variable que SE LLAMA como un secreto, asignada a algo
# largo y sin espacios. Cubre las credenciales caseras y las de proveedores
# que no están en la lista.

# EL VALOR TIENE QUE SER UN LITERAL ENTRECOMILLADO.
#
# La primera versión aceptaba cualquier cosa larga a la derecha del igual, y
# eso marcaba LECTURAS en vez de asignaciones de secreto:
#
#     username, password = get_auth_from_url(proxy)   ← no es un secreto
#     let token = RANGE_REP_REG.exec(string)          ← ni siquiera es auth
#     Password: c.Config.Password                      ← es una referencia
#
# En cinco repositorios públicos sin un solo dato personal, esto solo
# producía la mitad de los falsos positivos — incluido uno en el README de
# portada de un proyecto popular. Un guardián que falla ahí se desinstala
# antes de haber detectado nada.
#
# Un secreto de verdad se escribe entre comillas. Exigirlas descarta las
# llamadas, las referencias a campos y la desestructuración, que es
# exactamente lo que sobraba.
NOMBRES_SOSPECHOSOS = re.compile(
    r"(?i)(?:^|[\s,{(])"
    r"(pass(?:word|wd)?|secret|token|api[_-]?key|apikey|private[_-]?key"
    r"|service[_-]?role|client[_-]?secret|auth[_-]?token|access[_-]?key)"
    r"\s*[:=]\s*"
    r"([\"'])([A-Za-z0-9_./+=-]{16,})\2"
)


def buscar_asignaciones(texto: str, archivo: str) -> Iterator[Hallazgo]:
    for i, linea in enumerate(texto.splitlines(), 1):
        m = NOMBRES_SOSPECHOSOS.search(linea)
        if not m:
            continue
        valor = m.group(3)
        # Una interpolación no es un secreto: es lo correcto.
        if valor.startswith(("$", "process.env", "os.environ", "env.")):
            continue
        if es_marcador(valor):
            continue
        yield _h(
            archivo, i, "asignacion_sospechosa", recortar(valor),
            f"La variable «{m.group(1)}» está asignada a un valor literal "
            f"largo. Puede ser una credencial real: los formatos de "
            f"proveedor son sólo una parte de lo que se filtra.",
            "Si es un secreto, rótalo y muévelo al entorno. Si no lo es, "
            "renombra la variable o exenta el archivo con su motivo.",
        )
