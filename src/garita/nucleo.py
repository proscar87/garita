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
from dataclasses import dataclass, field
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
RUTAS_DE_PRUEBA = re.compile(
    r"(^|/)(tests?|testdata|test_data|fixtures?|__snapshots__|__fixtures__"
    r"|spec|specs|examples?|ejemplos?|mocks?|stubs?|testing)(/|$)"
)
DETECTORES_RELAJADOS_EN_PRUEBAS = frozenset({
    "llave_privada", "llave_proveedor", "jwt", "credencial_en_url",
    "asignacion_sospechosa",
})

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


def es_revisable(ruta: Path) -> tuple[bool, str]:
    """¿Se revisa? Y si no, por qué.

    El motivo se devuelve para poder DECIRLO. Antes se omitía en silencio, y
    un archivo grande omitido calladamente es el peor modo de falla posible:
    una marca verde sin revisión. En repositorios reales eso ya escondía
    volcados de decenas de megabytes.
    """
    if ruta.suffix.lower() in EXTENSIONES_BINARIAS:
        return False, "binario"
    if ruta.suffix.lower() in EXTENSIONES_SIN_DATOS:
        return False, "formato vectorial"
    if ruta.name in ARCHIVOS_SIN_DATOS:
        return False, "archivo de bloqueo de dependencias"
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


def leer(ruta: Path) -> str | None:
    """Devuelve el texto, o None si el archivo es binario de verdad.

    La detección de binario es por byte nulo y no por extensión: un `.dat`
    sin extensión conocida puede ser texto, y un `.txt` puede no serlo. Pero
    antes se prueban las marcas de orden de bytes, porque un archivo UTF-16
    está lleno de nulos y sí es texto.
    """
    try:
        crudo = ruta.read_bytes()
    except OSError:
        return None

    for marca, codificacion in _BOM:
        if crudo.startswith(marca):
            try:
                return crudo.decode(codificacion, "replace")
            except (UnicodeDecodeError, LookupError):
                return None

    if b"\0" in crudo:
        return None
    return crudo.decode("utf-8", "replace")


# ── Exenciones ─────────────────────────────────────────────────────────────

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
        if not fnmatch.fnmatch(archivo, self.patron):
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
        texto = leer(ruta)
        if texto is None:
            res.archivos_omitidos += 1
            continue
        res.archivos_revisados += 1

        en_pruebas = bool(RUTAS_DE_PRUEBA.search(rel))
        for det in dets:
            cubierto = next((e for e in exen if e.cubre(rel, det.nombre)), None)
            if cubierto is not None:
                res.exentos_aplicados[cubierto.patron] = (
                    res.exentos_aplicados.get(cubierto.patron, 0) + 1
                )
                continue
            for h in det.buscar(texto, rel):
                # El filtro se aplica sobre la ETIQUETA del hallazgo, no sobre
                # el nombre del detector: `secretos` produce hallazgos de
                # `llave_privada`, `jwt` y demás, y sólo algunos se relajan en
                # rutas de prueba.
                if en_pruebas and h.detector in DETECTORES_RELAJADOS_EN_PRUEBAS:
                    continue
                res.hallazgos.append(h)

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
