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
            r"|sk-ant-[A-Za-z0-9_-]{20,}"         # Anthropic
            # OpenAI vigente: los prefijos con guion. El `sk-` pelón de abajo
            # se queda alfanumérico puro A PROPÓSITO: admitirle guiones haría
            # casar clases CSS de esqueleto («sk-loading-spinner-grande»).
            r"|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}"
            r"|sk-[A-Za-z0-9]{20,}"               # OpenAI legado y similares
            # Stripe: sólo `_live_`. La de `_test_` aparece a propósito en
            # media documentación del mundo y no toca dinero real.
            r"|[sr]k_live_[A-Za-z0-9]{16,}"
            # GitHub: personal, OAuth, app… La cota es INFERIOR: ghp_/gho_/
            # ghs_/ghu_ miden 36 tras el prefijo, pero los refresh ghr_
            # vigentes miden 76 y con longitud exacta no casaban jamás.
            r"|gh[opsur]_[A-Za-z0-9]{36,}"
            r"|github_pat_[A-Za-z0-9_]{22,}"      # GitHub fine-grained
            r"|npm_[A-Za-z0-9]{36}"               # npm granular
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
        # archivo de ejemplo "de momento". El usuario puede ser VACÍO:
        # `redis://:contraseña@host` es la forma normal de redis y memcached,
        # y exigir usuario la dejaba pasar limpia.
        # El esquema va ACOTADO a 15 caracteres. Sin cota, una tirada larga
        # de minúsculas con puntos —un archivo minificado— hacía retroceder
        # el motor desde cada posición buscando un «://» que no llega:
        # 120 KB en una línea tardaban 21 segundos, y un guardián que cuelga
        # el CI se desinstala igual que uno que grita. El esquema más largo
        # que existe cabe de sobra.
        re.compile(
            r"\b[a-z][a-z0-9+.-]{0,15}://"
            r"[^/\s:@]*:(?P<secreto>[^/\s:@]{6,})@[^\s/]+",
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
#
# LA SEGUNDA LECCIÓN: TAMPOCO VALE CUALQUIER SUBCADENA. El `.search` sin
# fronteras descartaba «VirtualPass2024» como placeholder porque «Virtual»
# contiene «tu». La regla que quedó: un marcador cuenta si NO está incrustado
# entre letras (ver `_marcador_delimitado`) — así «7EXAMPLE» al final de la
# llave de AWS sigue contando y el «tu» de «Virtual» ya no. Y «tu…»/«your…»
# pegado a cualquier cosa sólo absuelve si ES el valor completo.
# «mi clave» NO está aquí, a propósito: con la frontera camelCase de abajo,
# tenerlo convertía «MiClave»/«MiSecreto» en PREFIJO absolutorio, y así se
# llama la contraseña que una persona se pone a sí misma en español —
# «MiClaveSegura2024» salía limpia de una URL de producción. Como valor
# completo («miClave», «mi_secreto») sigue absuelto por _ES_TODO_MARCADOR,
# que ya lleva su propio prefijo `m[iy]`.
# «your» exige separador igual que «tu»: con el `?` absolvía «yourself…» y
# cualquier valor que empezara así, la misma falla que «mi clave» por otra
# puerta. Sin separador los cubre _POSESIVO_ES_TODO, que sí pide sustantivo.
MARCADORES = re.compile(
    r"(?i)(tu[_-]\w+|your[_-]\w+|xxx+|placeholder"
    r"|cambiame|change[_-]?me"
    r"|ejemplo|example|dummy|fake|test[_-]?key|redacted|s3cr3t|hunter2"
    r"|lorem|ipsum)"
)

# «tuclave», «yourkey123», «TuClaveAqui»: sin separador sólo son marcador
# siendo el valor entero, y el sustantivo tiene que venir PEGADO al
# posesivo — con `\w+` pelón, cualquier valor que empezara por tu/your
# («Turquesa9Fuerte42x», una contraseña «Turbina…») se absolvía.
#
# Después del sustantivo sí se admite cola («TuClaveAqui», «your_key_here»)
# y esto NO vale para «mi…»: la asimetría es del idioma, no un descuido.
# «Tu clave» se escribe DIRIGIÉNDOSE a quien lee — es una plantilla. «Mi
# clave» es como se nombra la propia, y ésa es de verdad.
_POSESIVO_ES_TODO = re.compile(
    r"(?i)^[\W_]*(tu|your)[_-]?"
    r"(clave|llave|secreto|contrase[nñ]a|pass(word)?|secret|key|token"
    r"|api[_-]?key|user|usuario|valor|value)\w*[\W_\d]*$"
)

_SUSTANTIVOS = frozenset((
    "clave", "llave", "secreto", "contrasena", "contraseña", "pass",
    "password", "secret", "key", "apikey", "token", "user", "usuario",
    "valor", "value",
))
# Palabras dentro de un valor: los separadores primero, y dentro de cada
# trozo la transición camelCase. «PASSWORD» en mayúsculas cuenta entero.
_PALABRAS = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]*|[a-z]+|\d+")


def _posesivo_con_calificativo(v: str) -> bool:
    """«yourDatabasePassword», «tu_clave_de_produccion»: el sustantivo no
    viene pegado al posesivo, sino más adelante.

    Se exige que el posesivo sea una PALABRA propia del valor (o que el
    sustantivo lo siga pegado, que es el caso de `_POSESIVO_ES_TODO`), y
    no una simple subcadena inicial: si no, «turbopass2024» —que empieza
    por «tu» por casualidad y trae «pass» dentro— se absolvería, y ésa es
    una contraseña, no una plantilla.
    """
    palabras = [p.lower() for parte in re.split(r"[\W_]+", v)
                for p in _PALABRAS.findall(parte)]
    if len(palabras) < 2 or palabras[0] not in ("tu", "your"):
        return False
    return any(p in _SUSTANTIVOS for p in palabras[1:])


def _marcador_delimitado(v: str) -> bool:
    """¿Hay un marcador delimitado de verdad dentro del valor?

    Tres reglas, cada una con su cicatriz:
    - La transición minúscula→Mayúscula cuenta como frontera: los
      placeholders camelCase («DummyPassword1234», «FakeApiKey…») son el
      estilo de media documentación JS/Java y dejaron de absolverse en
      v0.9.0 por accidente.
    - Un dígito sólo cuenta como frontera si el OTRO extremo del marcador
      toca el borde del valor: así «AKIAIOSFODNN7EXAMPLE» sigue siendo
      ejemplo, pero «fake» o «EXAMPLE» flotando entre dígitos dentro de
      una llave con formato de proveedor ya no la absuelven.
    - «VirtualPass2024» no se descarta: su «tu» vive dentro de «Virtual»
      y ni siquiera casa MARCADORES.
    """
    for m in MARCADORES.finditer(v):
        a, b = m.span()
        ini = (a == 0
               or not v[a - 1].isalnum()
               or (v[a - 1].islower() and v[a].isupper())
               or (b == len(v) and not v[a - 1].isalpha()))
        fin = (b == len(v)
               or not v[b].isalnum()
               or (v[b - 1].islower() and v[b].isupper())
               or (a == 0 and not v[b].isalpha()))
        if ini and fin:
            return True
    return False

# Éstos sólo son marcador si constituyen casi todo el valor: «abcdef» dentro
# de una llave aleatoria de cuarenta caracteres no la vuelve un ejemplo.
_RELLENO = re.compile(r"(?i)^[\W_]*(abcdef(ghi?j?k?)?|123456(789?0?)?|foo|bar|baz)[\W_\d]*$")


# Valores que SON el marcador completo, no que lo contienen.
_ES_TODO_MARCADOR = re.compile(
    r"(?i)^[\W_]*(m[iy][\W_]?)?(pass(word)?|clave|llave|secreto|secret"
    r"|contrase[nñ]a|user|usuario"
    r"|admin|root|token|apikey|api[_-]?key|value|valor)[\W_\d]*$"
)


def es_marcador(valor: str) -> bool:
    """¿El VALOR es un marcador de posición? No la línea: el valor."""
    v = valor.strip("\"'")
    # Codificado en porcentaje, «p%40ss» aparenta seis caracteres y son
    # cuatro. Se juzga lo que de verdad es.
    if "%" in v:
        from urllib.parse import unquote
        d = unquote(v)
        if len(d) < 6:
            return True
        v = d
    if not v or v.startswith("<") or v.startswith("${") or v.startswith("$("):
        return True
    if (_POSESIVO_ES_TODO.match(v) or _posesivo_con_calificativo(v)
            or _RELLENO.match(v)
            or _ES_TODO_MARCADOR.match(v) or _marcador_delimitado(v)):
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
    if any(m in texto_carga for m in
           ("example", "ejemplo", "demo", "test", "foo", "1234567890",
            "john doe", "jane doe", "sample", "acme", "widget", "contoso",
            "localhost", "your-", "tu-")):
        return True

    # UN TOKEN QUE NO IDENTIFICA A NADIE NO ES UNA CREDENCIAL. Si la carga
    # útil no trae ni sujeto, ni rol, ni correo, ni emisor real —sólo fechas—
    # no da acceso a nada y es de ilustración. Es el caso de los ejemplos de
    # documentación que sólo enseñan la forma del token.
    IDENTIDAD = {"sub", "uid", "user", "user_id", "username", "email", "role",
                 "roles", "scope", "scp", "aud", "client_id", "azp", "name",
                 "preferred_username", "groups", "permissions"}
    return not (IDENTIDAD & set(k.lower() for k in carga))


_BASE64 = re.compile(r"[A-Za-z0-9+/=]{16,}")
_CABECERA_PEM = re.compile(r"[A-Za-z][A-Za-z-]*:\s*\S")
_CUERPO_PEGADO = re.compile(
    r'(?:(?:\\r)?\\n|["\']\s*\+?\s*["\']?)?[A-Za-z0-9+/=]{16,}')


def _pem_con_cuerpo(lineas: list[str], indice: int,
                    inicio: int, fin: int) -> bool:
    """¿La cabecera PEM viene seguida de llave, o sólo se la menciona?

    Una llave privada de verdad trae su cuerpo en base64 justo después: en
    la misma línea si viene escapada dentro de un JSON o un .env, o en la
    siguiente si es un archivo PEM normal. Un docstring que dice «el
    archivo debe empezar con -----BEGIN RSA PRIVATE KEY-----» trae prosa.

    Sin esta comprobación, medido sobre un repositorio público real, 48 de
    48 hallazgos de este detector eran una línea de documentación. Ese
    ruido es exactamente lo que enseña a un equipo a ignorar al guardián,
    y el día que lo ignora deja pasar la llave de verdad.
    """
    # Antes de mirar el cuerpo: si la cabecera viene precedida de una FRASE,
    # es documentación. Una llave de verdad vive tras `KEY="`, `"key": "` o
    # `private_key = "` — prefijos de dos o tres palabras. Lo que trae
    # veinte («:param private_key: [APN only] The URL-encoded representation
    # of the private key. Strip everything outside of the headers, e.g.») es
    # el manual explicando el formato con una llave recortada de ejemplo.
    if len(lineas[indice][:inicio].split()) >= 6:
        return False

    resto = lineas[indice][fin:]
    # En la MISMA línea, el cuerpo va pegado a la cabecera o tras un salto
    # escapado —«…KEY-----\nMIIE…», como se guarda en un .env o un JSON—.
    # Nunca tras un ESPACIO: un PEM de verdad lleva salto de línea ahí, y
    # lo que se ve con espacios es documentación enseñando el formato con
    # una llave recortada («For example, `-----BEGIN RSA PRIVATE KEY-----
    # MIIEpQ… -----END RSA PRIVATE KEY-----`»). Ésa fue la totalidad de los
    # 48 hallazgos medidos en un repositorio público real.
    if _CUERPO_PEGADO.match(resto):
        return True
    for siguiente in lineas[indice + 1:indice + 6]:
        if not siguiente.strip():
            continue
        # Una llave CIFRADA trae cabeceras RFC 1421 antes del cuerpo
        # —«Proc-Type: 4,ENCRYPTED», «DEK-Info: AES-256-CBC,…»— y sigue
        # siendo una llave. Se saltan y se sigue buscando.
        if _CABECERA_PEM.match(siguiente.strip()):
            continue
        # La línea de cuerpo es base64 y poco más; una frase trae espacios
        # y palabras cortas.
        limpia = siguiente.strip().strip("\"'\\,")
        return bool(_BASE64.match(limpia))
    return False


def buscar(texto: str, archivo: str) -> Iterator[Hallazgo]:
    lineas = texto.splitlines()
    for i, linea in enumerate(lineas, 1):
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
                if (nombre == "llave_privada"
                        and not _pem_con_cuerpo(lineas, i - 1,
                                                m.start(), m.end())):
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
    r"(?i)(?:^|[\s,{(])(?:[A-Za-z0-9]+[_.-])*"
    r"(pass(?:word|wd)?|secret|token|api[_-]?key|apikey|private[_-]?key"
    r"|service[_-]?role|client[_-]?secret|auth[_-]?token|access[_-]?key)"
    r"\s*[:=]\s*"
    r"([\"'])([A-Za-z0-9_./+=-]{16,})\2"
)

# El mismo nombre sospechoso, pero con el valor SIN COMILLAS y hasta el fin
# de la línea. El razonamiento de arriba —exigir comillas para no morder
# `username, password = get_auth(url)`— está pensado para CÓDIGO; los
# formatos donde de verdad se filtra una credencial por descuido no usan
# comillas por convención: .env, .properties, .ini, el bloque
# `environment:` de un docker-compose, un Secret de Kubernetes en YAML
# plano. Ahí `DB_PASSWORD=<20 aleatorios>` no lo veía nadie — y es justo el
# hueco bajo el consejo que esta herramienta imprime: «guárdala en un .env».
#
# Para no volver a morder el código, el valor sin comillas tiene que:
#   · ocupar la línea COMPLETA tras el signo (nada de comas ni paréntesis,
#     que delatan una llamada o un literal de diccionario), y
#   · no parecer una referencia (`config.get`, `os.environ[...]`, `$VAR`,
#     `${VAR}`, `%s`), que es lo que pone ahí quien hizo las cosas bien.
_ES_REFERENCIA = re.compile(
    r"(?i)^(\w+[.\[]|%s$|None$|null$|true$|false$)"
)
NOMBRES_SOSPECHOSOS_PELON = re.compile(
    r"(?i)(?:^|[\s])(?:[A-Za-z0-9]+[_.-])*"
    r"(pass(?:word|wd)?|secret|token|api[_-]?key|apikey|private[_-]?key"
    r"|service[_-]?role|client[_-]?secret|auth[_-]?token|access[_-]?key)"
    r"\s*[:=]\s*"
    r"(?P<valor>[A-Za-z0-9_./+=-]{16,})\s*$"
)


def _asignaciones_de_la_linea(linea: str):
    """Los pares (nombre, valor) sospechosos: con comillas y sin ellas."""
    vistos = set()
    # `finditer`, no `search` — la misma lección que en `buscar`: si la
    # primera asignación de la línea es un marcador, el `continue` no
    # debe tragarse la credencial real que viene después.
    #
    # El tercer elemento dice de qué rama viene: el filtro de referencias
    # es SÓLO para la pelona. Aplicado también a la entrecomillada mataba
    # las credenciales de prefijo punteado —`hvs.` de Vault, `dp.st.` de
    # Doppler, `cs.live.`— que v0.23.0 sí reportaba.
    for m in NOMBRES_SOSPECHOSOS.finditer(linea):
        vistos.add(m.group(3))
        yield m.group(1), m.group(3), False
    for m in NOMBRES_SOSPECHOSOS_PELON.finditer(linea):
        if m.group("valor") not in vistos:
            yield m.group(1), m.group("valor"), True


def buscar_asignaciones(texto: str, archivo: str) -> Iterator[Hallazgo]:
    for i, linea in enumerate(texto.splitlines(), 1):
        for nombre, valor, sin_comillas in _asignaciones_de_la_linea(linea):
            # Una interpolación no es un secreto: es lo correcto.
            if valor.startswith(("$", "process.env", "os.environ", "env.")):
                continue
            # Ni una referencia a otra cosa: `password: config.db_pass`,
            # `token = settings.TOKEN`. Sin comillas eso es lo normal en
            # código, y marcarlo enseñaría a ignorar al guardián.
            if sin_comillas and _ES_REFERENCIA.match(valor):
                continue
            if es_marcador(valor):
                continue
            yield Hallazgo(
                archivo=archivo, linea=i, detector="asignacion_sospechosa",
                que=recortar(valor), severidad="aviso",
                por_que=(
                    f"La variable «{nombre}» está asignada a un valor "
                    f"literal largo. PUEDE ser una credencial: los formatos "
                    f"de proveedor son sólo una parte de lo que se filtra. "
                    f"Va como aviso porque es una sospecha, no una certeza — "
                    f"hay llaves públicas por diseño, como las de búsqueda."),
                como_arreglar=(
                    "Si es un secreto, rótalo y muévelo al entorno. Si es "
                    "público a propósito, exenta el archivo con ese motivo."),
            )
