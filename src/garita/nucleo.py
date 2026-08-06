#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
El motor: recorre los archivos versionados y aplica detectores.

DECISIONES DE DISEÑO, Y POR QUÉ

Solo mira archivos RASTREADOS POR GIT. Lo que está en `.gitignore` no es
problema de esta herramienta: el daño de un dato personal empieza cuando se
publica, y aquí "publicar" es `git push`. Escanear el árbol completo haría
ruido con `node_modules`, `.venv` y descargas de trabajo.

Cada hallazgo trae LA RAZÓN, no solo la coincidencia. Un error que dice
"patrón X en línea Y" obliga a quien lo lee a adivinar qué hacer; uno que
dice "esto es un CURP y un CURP identifica a una persona; quítalo o exenta
el archivo con su motivo" se resuelve solo.

No hay modo "arreglar automáticamente". Borrar un dato personal de un
archivo sin que un humano vea el contexto es cómo se pierde información
legítima — y además el dato ya está en el historial de git, así que el
arreglo real casi nunca es editar la línea.
"""
from __future__ import annotations

import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Iterable, Iterator


# ── Lo que un detector encuentra ───────────────────────────────────────────

@dataclass(frozen=True)
class Hallazgo:
    archivo: str
    linea: int
    detector: str
    """Nombre corto, para agrupar: 'curp', 'jwt', 'nombre'."""
    que: str
    """Qué se encontró, ya recortado. NUNCA el valor completo de un secreto."""
    por_que: str
    """Por qué importa. Se le muestra a quien tiene que arreglarlo."""
    como_arreglar: str
    """La acción concreta. Sin esto el reporte es una queja, no una guía."""
    severidad: str = "error"   # error | aviso


@dataclass
class Detector:
    """Un detector es una función de (texto, ruta) a hallazgos."""
    nombre: str
    descripcion: str
    buscar: Callable[[str, str], Iterator[Hallazgo]]
    activo: bool = True


# ── Qué archivos se miran ──────────────────────────────────────────────────

# Binarios y artefactos que jamás contienen texto revisable. No es una lista
# de seguridad sino de ruido: escanear un PNG produce coincidencias azarosas.
EXTENSIONES_BINARIAS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".7z", ".mp4", ".mov", ".mp3", ".wav", ".woff", ".woff2", ".ttf",
    ".otf", ".eot", ".so", ".dylib", ".dll", ".pyc", ".class", ".jar",
    ".xlsx", ".xls", ".docx", ".doc", ".pptx",
}

# Carpetas donde el material con forma de secreto es, por definición, de
# mentira: fixtures de TLS, instantáneas de pruebas, datos de ejemplo. Todo
# proyecto que hable TLS versiona llaves de prueba; marcarlas garantiza que
# el primer día de uso sea rojo, y ese día alguien desactiva el paso.
#
# No se apagan TODOS los detectores en esas rutas: un dato personal en un
# archivo de pruebas sigue siendo un dato personal. Sólo se relajan los
# detectores de material criptográfico, que es lo que legítimamente vive ahí.
# `spec/` NO está aquí, a propósito: es la carpeta de los contratos OpenAPI y
# JSON-Schema, documentos que se ESCRIBEN — el mismo argumento por el que las
# carpetas de ejemplo no se suprimen. Los archivos de prueba estilo RSpec o
# Jasmine siguen cubiertos por ARCHIVOS_DE_PRUEBA (`foo_spec.rb`,
# `foo.spec.ts`) y `spec/fixtures/` sigue casando por `fixtures?`.
RUTAS_DE_PRUEBA = re.compile(
    r"(^|/)(tests?|testdata|test_data|fixtures?|__snapshots__|__fixtures__"
    r"|mocks?|stubs?|testing)(/|$)"
)
# Las carpetas de EJEMPLO no van con las de prueba, a propósito. Un fixture
# de pruebas se genera; un ejemplo se ESCRIBE, y la mitad de las fugas
# reales son el archivo de ejemplo que alguien llenó con valores verdaderos
# «de momento». Suprimir ahí las credenciales era regalar justo ese caso.
# Tampoco se reportan como error: el primer día de un repo con ejemplos
# legítimos sería rojo, y ese día alguien desactiva el paso. Se degradan a
# aviso: suenan, no reprueban, y quien tenga ejemplos inventados los exenta
# con su motivo.
RUTAS_DE_EJEMPLO = re.compile(r"(^|/)(examples?|ejemplos?)(/|$)")
# También por NOMBRE de archivo, no sólo por carpeta: `test_requests.py`
# vivió años en la raíz de requests, y las 258 credenciales de broma de sus
# versiones históricas son la prueba de que la carpeta no basta.
ARCHIVOS_DE_PRUEBA = re.compile(
    r"(^|/)(test_[^/]*\.py|conftest\.py)$"
    r"|[._-](tests?|specs?)\.[A-Za-z0-9]+$"
)
DETECTORES_RELAJADOS_EN_PRUEBAS = frozenset({
    "llave_privada", "llave_proveedor", "jwt", "credencial_en_url",
    "asignacion_sospechosa",
})


def es_de_prueba(rel: str) -> bool:
    return bool(RUTAS_DE_PRUEBA.search(rel) or ARCHIVOS_DE_PRUEBA.search(rel))


def es_de_ejemplo(rel: str) -> bool:
    return bool(RUTAS_DE_EJEMPLO.search(rel))


# Registros públicos: archivos cuyo contenido es un catálogo publicado a
# propósito. El caso concreto: los bundles de autoridades certificadoras
# traen el CIF real de Camerfirma en el asunto de sus certificados — es
# información pública POR DISEÑO, no una filtración. En estos archivos se
# relajan los detectores de identificadores, pero NUNCA los de secretos:
# un `fullchain.pem` mal armado puede traer la llave privada concatenada,
# y ésa sí tiene que sonar.
ARCHIVOS_DE_REGISTRO_PUBLICO = {
    "cacert.pem", "ca-bundle.crt", "ca-bundle.pem", "ca-certificates.crt",
}


def filtrar_por_ruta(h: Hallazgo, rel: str) -> Hallazgo | None:
    """Las reglas de ruta, en un solo lugar: pruebas, ejemplos y registros
    públicos. Devuelve el hallazgo (quizá degradado a aviso) o None si la
    ruta lo suprime. El motor normal y el del historial pasan por aquí:
    dos motores con reglas distintas darían dos verdades distintas."""
    if h.detector in DETECTORES_RELAJADOS_EN_PRUEBAS:
        if es_de_prueba(rel):
            return None
        if es_de_ejemplo(rel) and h.severidad == "error":
            return replace(
                h, severidad="aviso",
                por_que=h.por_que + " Está en una ruta de ejemplo: si el "
                "valor es inventado, exenta el archivo con ese motivo; si "
                "es real, es una fuga con instrucciones de uso.")
    elif Path(rel).name in ARCHIVOS_DE_REGISTRO_PUBLICO:
        return None
    return h

# Formatos que no contienen datos aunque sean texto: tipografías vectoriales,
# diagramas. Sus coordenadas producen cadenas numéricas indistinguibles de un
# identificador — una sola tipografía SVG generaba treinta y ocho falsos
# positivos de teléfono.
EXTENSIONES_SIN_DATOS = {".svg", ".fig", ".dxf", ".eps", ".ps"}

# Archivos de bloqueo de dependencias: miles de hashes base64 y ni un dato
# personal. Sus cadenas casan por azar con identificadores alfanuméricos.
ARCHIVOS_SIN_DATOS = {
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "composer.lock",
    "Cargo.lock", "poetry.lock", "Gemfile.lock", "go.sum", "pdm.lock",
    "uv.lock", "bun.lockb", "flake.lock",
}

# Tope de tamaño. Un archivo de varios MB versionado casi siempre es un
# volcado de datos, y revisarlo línea por línea cuesta minutos en CI. Se
# avisa en vez de callar: un volcado grande es justo donde se esconde un
# padrón entero.
MAX_BYTES = 2_000_000


def archivos_versionados(raiz: Path) -> list[str]:
    """Lo que git rastrea, sin lo binario."""
    salida = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=raiz, capture_output=True, check=True,
    ).stdout.decode("utf-8", "replace")
    return [f for f in salida.split("\0") if f]


def ruta_revisable(ruta: Path) -> tuple[bool, str]:
    """La parte de `es_revisable` que se decide con el puro nombre.

    Va aparte porque el historial revisa blobs que ya no existen como
    archivos: ahí no hay `stat`, pero la extensión y el nombre siguen
    diciendo lo mismo.
    """
    if ruta.suffix.lower() in EXTENSIONES_BINARIAS:
        return False, "binario"
    if ruta.suffix.lower() in EXTENSIONES_SIN_DATOS:
        return False, "formato vectorial"
    if ruta.name in ARCHIVOS_SIN_DATOS:
        return False, "archivo de bloqueo de dependencias"
    return True, ""


def es_revisable(ruta: Path) -> tuple[bool, str]:
    """¿Se revisa? Y si no, por qué.

    El motivo se devuelve para poder DECIRLO. Antes se omitía en silencio, y
    un archivo grande omitido calladamente es el peor modo de falla posible:
    una marca verde sin revisión. En repositorios reales eso ya escondía
    volcados de decenas de megabytes.
    """
    revisable, motivo = ruta_revisable(ruta)
    if not revisable:
        return False, motivo
    try:
        tam = ruta.stat().st_size
    except OSError:
        return False, "ilegible"
    if tam > MAX_BYTES:
        return False, f"pesa {tam // 1_000_000} MB, más del tope de {MAX_BYTES // 1_000_000} MB"
    return True, ""


# Marcas de orden de bytes. Se reconocen porque un archivo UTF-16 está lleno
# de bytes nulos y, sin esto, la detección de binario lo descartaría entero.
# No es un caso raro: las herramientas de Windows y varios exportadores de
# Excel escriben UTF-16 por omisión, y un padrón exportado así pasaría sin
# que nada lo mirara.
_BOM = (
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
)


def _utf16_sin_marca(crudo: bytes) -> str | None:
    """UTF-16 al que nadie le puso BOM, reconocido por sus nulos alternados.

    La marca cubre lo que escribe Windows; NO cubre `iconv -t UTF-16LE`,
    `java.io` con ese charset, `.NET UnicodeEncoding(false, …)` ni el
    `bcp -w` de SQL Server — o sea el exportador de padrones. Sin esto,
    ese archivo es «lleno de nulos» → binario → omitido en silencio, que
    es la marca verde sin revisión.
    """
    pares, impares = crudo[0::2], crudo[1::2]
    if not pares or not impares:
        return None
    nulos_pares = pares.count(0) / len(pares)
    nulos_impares = impares.count(0) / len(impares)
    # Texto latino en UTF-16: el byte alto de cada par es nulo casi siempre
    # y el bajo casi nunca. Un binario cualquiera no cumple ninguna de las
    # dos, y un bloque todo-nulos falla la segunda.
    if nulos_impares > 0.7 and nulos_pares < 0.1:
        return crudo.decode("utf-16-le", "replace")
    if nulos_pares > 0.7 and nulos_impares < 0.1:
        return crudo.decode("utf-16-be", "replace")
    return None


def descifrar(crudo: bytes) -> str | None:
    """Bytes a texto, o None si es binario de verdad.

    La detección de binario es por byte nulo y no por extensión: un `.dat`
    sin extensión conocida puede ser texto, y un `.txt` puede no serlo. Pero
    antes se prueban las marcas de orden de bytes, porque un archivo UTF-16
    está lleno de nulos y sí es texto — y después la forma del UTF-16 sin
    marca, que las marcas no alcanzan.

    Lo que no es UTF-8 se reintenta como CP1252 antes de rendirse: con
    `replace` a secas, «Cédula» de un archivo Latin-1 se vuelve «C�dula» y
    NINGUNA palabra de contexto con acento casa. El archivo se contaba como
    revisado y callaba — peor que omitirlo, porque el resumen jura que se
    miró. Es el default histórico de Excel y de los editores de Windows en
    español, o sea el formato en que llegan los padrones de esta región.
    """
    for marca, codificacion in _BOM:
        if crudo.startswith(marca):
            try:
                return crudo.decode(codificacion, "replace")
            except (UnicodeDecodeError, LookupError):
                return None

    if b"\0" in crudo:
        return _utf16_sin_marca(crudo)
    try:
        return crudo.decode("utf-8")
    except UnicodeDecodeError:
        pass
    # No es UTF-8 del todo. Pero caer a cp1252 por el archivo entero
    # ante UN byte malo —una ñ Latin-1 pegada en un export mezclado—
    # convertía «Cédula» en «CÃ©dula» y dejaba ciego a todo detector con
    # contexto acentuado, sobre archivos que en su mayoría eran UTF-8
    # correcto. Sólo se cambia de codificación cuando el intento UTF-8 no
    # rescata NINGUNA letra acentuada: ése es el Latin-1 puro que se
    # quería leer, y no el archivo mezclado.
    tentativa = crudo.decode("utf-8", "replace")
    if any(c > "\x7f" and c != "�" for c in tentativa):
        return tentativa
    return crudo.decode("cp1252", "replace")


class Ilegible(Exception):
    """El archivo existe y git lo rastrea, pero no se pudo abrir.

    No es lo mismo que binario, y confundirlos era el peor modo de falla:
    un permiso denegado o un E/S a media corrida se contaba como «omitido
    (binario o muy grande)», sin nombrar el archivo y sin tocar el
    veredicto. Se aprobaba con 0 algo que nadie miró — la marca verde sin
    revisión que esta herramienta existe para no producir."""


def leer(ruta: Path) -> str | None:
    """Devuelve el texto del archivo, o None si es binario.

    Levanta `Ilegible` si no se pudo abrir: eso no se decide en silencio.
    """
    try:
        crudo = ruta.read_bytes()
    except OSError as e:
        raise Ilegible(f"{e.strerror or e}") from e
    return descifrar(crudo)


# ── Exenciones ─────────────────────────────────────────────────────────────

def casa_ruta(archivo: str, patron: str) -> bool:
    """Como .gitignore: sin barra casa el NOMBRE a cualquier profundidad;
    con barra casa la RUTA por segmentos, donde `*` no cruza «/» y `**` sí.

    Con `fnmatch` a secas, un patrón escrito pensando en la carpeta
    `tests/` absorbía además `tests_reales/` y `tests_viejos.tar` — y
    `tests_reales/` no es ruta de prueba, así que ahí los hallazgos eran
    de verdad. Peor: la absorción era muda, porque el patrón sí coincidía
    y no salía como exención muerta. Con esto «tests*» no casa nada y
    aparece en el reporte como exención que no aplicó: quien la escribió
    se entera de que quería «tests/**».

    Pero la primera versión de este arreglo ancló TODO patrón a la raíz, y
    eso rompió `*.test.ts` —la forma en que medio mundo exenta sus
    vectores de prueba— en cada repo que lo usaba. La regla de gitignore
    es la que la gente ya tiene en la cabeza, y distingue los dos casos
    sin sorprender a nadie.
    """
    if "/" not in patron:
        return fnmatch.fnmatch(archivo.rsplit("/", 1)[-1], patron)

    partes_a = archivo.split("/")
    partes_p = patron.split("/")

    def desde(i: int, j: int) -> bool:
        while j < len(partes_p):
            if partes_p[j] == "**":
                if j + 1 == len(partes_p):
                    return True
                return any(desde(k, j + 1) for k in range(i, len(partes_a) + 1))
            if i >= len(partes_a) or not fnmatch.fnmatch(partes_a[i],
                                                        partes_p[j]):
                return False
            i, j = i + 1, j + 1
        return i == len(partes_a)

    return desde(0, 0)


@dataclass
class Exencion:
    """Un archivo exento, CON SU MOTIVO.

    El motivo es obligatorio a propósito. Una lista de exenciones sin
    razones se vuelve, en pocos meses, la lista de archivos que alguien no
    supo arreglar — y nadie se atreve a quitarlos porque no sabe por qué
    están. Con el motivo escrito, cualquiera puede evaluar si sigue siendo
    válido.
    """
    patron: str
    motivo: str
    detectores: tuple[str, ...] = ()
    """Vacío = exento de todos. Mejor acotar: exentar un archivo de 'curp'
    no debería exentarlo también de 'llave_privada'."""

    def cubre(self, archivo: str, detector: str) -> bool:
        """¿Esta exención tapa a este detector en este archivo?

        `detector` puede ser el nombre del detector («secretos») o la
        etiqueta con la que el reporte IMPRIME cada hallazgo suyo
        («llave_privada», «credencial_en_url», «jwt»). Las dos valen: quien
        escribe una exención copia lo que ve en el reporte, y antes esa
        exención no tapaba nada Y TAMPOCO salía como exención muerta.
        """
        if not casa_ruta(archivo, self.patron):
            return False
        return not self.detectores or detector in self.detectores


# ── El recorrido ───────────────────────────────────────────────────────────

@dataclass
class Resultado:
    hallazgos: list[Hallazgo] = field(default_factory=list)
    archivos_revisados: int = 0
    archivos_omitidos: int = 0
    omitidos_grandes: list[tuple[str, str]] = field(default_factory=list)
    """Los que se saltaron por tamaño, CON su motivo. Se reportan siempre:
    callarlos convierte la revisión en una promesa vacía."""
    exentos_aplicados: dict[str, int] = field(default_factory=dict)
    exenciones_muertas: list[str] = field(default_factory=list)
    """Exenciones cuyo patrón no coincidió con ningún archivo revisado."""
    ilegibles: list[tuple[str, str]] = field(default_factory=list)
    """Los que git rastrea y no se pudieron abrir, CON su motivo. Van
    aparte de los binarios porque no son lo mismo: un binario se decidió
    no revisar; éste no se pudo, y eso no puede terminar en «✓»."""

    @property
    def errores(self) -> list[Hallazgo]:
        return [h for h in self.hallazgos if h.severidad == "error"]

    @property
    def avisos(self) -> list[Hallazgo]:
        return [h for h in self.hallazgos if h.severidad == "aviso"]


def revisar(
    raiz: Path,
    detectores: Iterable[Detector],
    exenciones: Iterable[Exencion] = (),
    archivos: Iterable[str] | None = None,
) -> Resultado:
    """Aplica los detectores a los archivos versionados."""
    dets = [d for d in detectores if d.activo]
    exen = list(exenciones)
    res = Resultado()
    patrones_vistos: set[str] = set()

    for rel in (archivos if archivos is not None else archivos_versionados(raiz)):
        ruta = raiz / rel
        if not ruta.is_file():
            res.archivos_omitidos += 1
            continue
        revisable, motivo = es_revisable(ruta)
        if not revisable:
            res.archivos_omitidos += 1
            if "tope" in motivo:
                res.omitidos_grandes.append((rel, motivo))
            continue
        try:
            texto = leer(ruta)
        except Ilegible as e:
            # Se dice CON NOMBRE y decide el veredicto: no se aprueba lo
            # que no se pudo mirar.
            res.ilegibles.append((rel, str(e)))
            res.archivos_omitidos += 1
            continue
        if texto is None:
            res.archivos_omitidos += 1
            continue
        res.archivos_revisados += 1

        # Las exenciones cuyo PATRÓN casa este archivo se calculan UNA vez:
        # `cubre()` rehacía el casamiento de ruta por cada detector, así que
        # media docena de exenciones duplicaba el tiempo de escaneo.
        aplican = [e for e in exen if casa_ruta(rel, e.patron)]
        for e in aplican:
            patrones_vistos.add(e.patron)

        for det in dets:
            cubierto = next(
                (e for e in aplican
                 if not e.detectores or det.nombre in e.detectores), None)
            if cubierto is not None:
                res.exentos_aplicados[cubierto.patron] = (
                    res.exentos_aplicados.get(cubierto.patron, 0) + 1
                )
                continue
            for h in det.buscar(texto, rel):
                # Segunda pasada de exenciones, ahora por la ETIQUETA del
                # hallazgo: el reporte imprime `llave_privada` y quien
                # escribe la exención copia lo que ve. Antes eso no tapaba
                # nada y tampoco salía como exención muerta — la peor
                # combinación, porque quien la escribió cree que aplicó.
                por_etiqueta = next(
                    (e for e in aplican
                     if not e.detectores or h.detector in e.detectores), None)
                if por_etiqueta is not None:
                    res.exentos_aplicados[por_etiqueta.patron] = (
                        res.exentos_aplicados.get(por_etiqueta.patron, 0) + 1
                    )
                    continue
                # El filtro se aplica sobre la ETIQUETA del hallazgo, no sobre
                # el nombre del detector: `secretos` produce hallazgos de
                # `llave_privada`, `jwt` y demás, y sólo algunos se relajan en
                # rutas de prueba.
                filtrado = filtrar_por_ruta(h, rel)
                if filtrado is not None:
                    res.hallazgos.append(filtrado)

    # Una exención que nunca se aplicó apunta a un archivo que ya no existe o
    # que se renombró. En el segundo caso la exención se cayó sin avisar y el
    # archivo lleva quién sabe cuánto revisándose sin que nadie lo mirara; en
    # el primero es configuración muerta que da una sensación de cobertura que
    # no existe. Callarlo es lo mismo que mentir con silencio.
    if archivos is None:
        res.exenciones_muertas = [
            e.patron for e in exen if e.patron not in patrones_vistos
        ]

    return res


def recortar(valor: str, visible: int = 4) -> str:
    """Muestra lo justo para localizarlo, nunca el valor completo.

    Un reporte de CI queda en los registros de la ejecución, que suelen ser
    visibles para más gente que el propio repositorio. Imprimir el secreto
    completo ahí lo vuelve a filtrar, ahora en un lugar donde nadie lo busca.
    """
    if len(valor) <= visible * 2:
        return valor[:visible] + "…"
    return f"{valor[:visible]}…{valor[-visible:]}"
