#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Revisar el historial: lo que git no olvida.

EL CASO QUE DUELE

La revisión normal mira el árbol de trabajo. Un secreto commiteado hace
tres meses y «borrado» al día siguiente le es invisible — y ese es justo
el caso que importa, porque el dato sigue ahí: en cada clon, en cada
fork, a un `git log -p` de distancia. Quien cree que borró la línea cree
que arregló el problema, y no arregló nada.

CÓMO SE RECORRE, Y POR QUÉ ASÍ

No se recorre commit por commit: un archivo que vivió sin cambios a
través de mil commits aparecería mil veces y la revisión tardaría horas.
Se recorren los BLOBS ÚNICOS — cada versión de cada archivo existe una
sola vez en la base de objetos de git — y cada uno se revisa una sola
vez. Es la diferencia entre revisar lo que se escribió y revisar cada
foto de lo que se escribió.

Sólo después, y sólo para los blobs sucios, se hace la segunda pasada
que responde a las dos preguntas que el reporte necesita:

  1. ¿En qué commit entró esto? (el más viejo que lo introdujo — ahí
     empieza la exposición, y ese es el commit del que hay que hablar)
  2. ¿Sigue en el árbol actual? Si sigue, la revisión normal también lo
     ve y el arreglo es el de siempre. Si ya no, el archivo se «borró»
     pero el dato no: el arreglo es rotar y, si se decide, reescribir
     historia — jamás en automático y jamás sin respaldo.

LO QUE SE REUSA A PROPÓSITO

Detectores, exenciones y filtros de ruta son LOS MISMOS del motor
normal. Una exención con motivo aplica a la ruta histórica igual que a
la actual, y las rutas de prueba relajan los mismos detectores. Dos
motores con reglas distintas darían dos verdades distintas, y una
herramienta con dos verdades no tiene ninguna.
"""
from __future__ import annotations

import fnmatch
import subprocess
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable

from .nucleo import (
    ARCHIVOS_DE_REGISTRO_PUBLICO, DETECTORES_RELAJADOS_EN_PRUEBAS, MAX_BYTES,
    Detector, Exencion, Hallazgo, descifrar, es_de_prueba, ruta_revisable,
)

# Cuántos blobs se piden por tanda a `git cat-file --batch`. Las peticiones
# de una tanda caben holgadas en el búfer de la tubería (41 bytes cada una),
# así que se puede escribir la tanda completa y leerla después sin
# interbloqueo. Tandas más grandes no aceleran nada medible.
_TANDA = 200


@dataclass(frozen=True)
class HallazgoHistorico:
    hallazgo: Hallazgo
    commit: str
    """Abreviado, del commit MÁS VIEJO que introdujo el blob."""
    fecha: str
    vivo: bool
    """True si el blob sigue tal cual en el árbol de HEAD."""
    versiones: int = 1
    """En cuántas versiones del archivo vivió la misma cadena. La misma
    apiKey a través de veinte ediciones del archivo es UN hallazgo que
    duró veinte versiones, no veinte hallazgos."""


@dataclass
class ResultadoHistorial:
    hallazgos: list[HallazgoHistorico] = field(default_factory=list)
    blobs_revisados: int = 0
    blobs_omitidos: int = 0
    commits: int = 0
    omitidos_grandes: list[tuple[str, str]] = field(default_factory=list)
    exentos_aplicados: dict[str, int] = field(default_factory=dict)

    @property
    def errores(self) -> list[HallazgoHistorico]:
        return [h for h in self.hallazgos if h.hallazgo.severidad == "error"]

    @property
    def avisos(self) -> list[HallazgoHistorico]:
        return [h for h in self.hallazgos if h.hallazgo.severidad == "aviso"]


def _git(raiz: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=raiz, capture_output=True, check=True,
    ).stdout


def _blobs_del_historial(raiz: Path) -> dict[str, str]:
    """Cada blob alcanzable desde ramas y tags, con una ruta de ejemplo.

    `rev-list --objects` ya deduplica: cada objeto sale una vez, con la
    primera ruta donde se le vio. Los commits y árboles se filtran después
    con `cat-file --batch-check`, que además trae el tamaño.
    """
    crudo = _git(raiz, "rev-list", "--objects", "--branches", "--tags")
    blobs: dict[str, str] = {}
    for linea in crudo.decode("utf-8", "replace").splitlines():
        sha, _, ruta = linea.partition(" ")
        if ruta:  # los commits vienen sin ruta; los árboles se filtran luego
            blobs.setdefault(sha, ruta)
    return blobs


def _tamanos(raiz: Path, shas: list[str]) -> dict[str, int]:
    """sha → tamaño, sólo de los que de verdad son blobs."""
    with subprocess.Popen(
        ["git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        cwd=raiz, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    ) as proc:
        salida, _ = proc.communicate("\n".join(shas).encode() + b"\n")
    tamanos: dict[str, int] = {}
    for linea in salida.decode("utf-8", "replace").splitlines():
        partes = linea.split()
        if len(partes) == 3 and partes[1] == "blob":
            tamanos[partes[0]] = int(partes[2])
    return tamanos


def _contenidos(raiz: Path, shas: list[str]):
    """Itera (sha, bytes) leyendo por tandas de una sola tubería."""
    proc = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=raiz, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    try:
        for i in range(0, len(shas), _TANDA):
            tanda = shas[i:i + _TANDA]
            proc.stdin.write("\n".join(tanda).encode() + b"\n")
            proc.stdin.flush()
            for sha in tanda:
                encabezado = proc.stdout.readline().decode("utf-8", "replace")
                partes = encabezado.split()
                if len(partes) != 3:
                    continue
                cuerpo = proc.stdout.read(int(partes[2]))
                proc.stdout.read(1)  # el salto de línea final
                yield sha, cuerpo
    finally:
        proc.stdin.close()
        proc.stdout.close()
        proc.wait()


def _origen_de(raiz: Path, sucios: set[str]) -> dict[str, tuple[str, str, str]]:
    """sha → (commit_abreviado, fecha, ruta) del commit MÁS VIEJO que lo trae.

    Una sola pasada por `git log --raw`, que lista el blob nuevo de cada
    cambio. El log va del presente al pasado, así que la última aparición
    que se ve es la más vieja — se sobreescribe sin más.
    """
    if not sucios:
        return {}
    crudo = _git(
        raiz, "log", "--branches", "--tags", "--raw", "--no-abbrev",
        "--date=short", "--format=%x01%h %ad",
    )
    origen: dict[str, tuple[str, str, str]] = {}
    commit, fecha = "", ""
    for linea in crudo.decode("utf-8", "replace").splitlines():
        if linea.startswith("\x01"):
            commit, _, fecha = linea[1:].partition(" ")
            # --no-abbrev (necesario para casar los SHAs completos de los
            # blobs) también des-abrevia %h; se recorta aquí.
            commit = commit[:10]
        elif linea.startswith(":"):
            # :modo_viejo modo_nuevo sha_viejo sha_nuevo estado\truta
            partes = linea.split("\t")
            campos = partes[0].split()
            if len(campos) >= 5 and campos[3] in sucios:
                origen[campos[3]] = (commit, fecha, partes[-1])
    return origen


def _vivos_en_head(raiz: Path) -> set[str]:
    try:
        crudo = _git(raiz, "ls-tree", "-r", "HEAD")
    except subprocess.CalledProcessError:
        return set()
    vivos = set()
    for linea in crudo.decode("utf-8", "replace").splitlines():
        partes = linea.split()
        if len(partes) >= 3:
            vivos.add(partes[2])
    return vivos


def revisar_historial(
    raiz: Path,
    detectores: Iterable[Detector],
    exenciones: Iterable[Exencion] = (),
) -> ResultadoHistorial:
    dets = [d for d in detectores if d.activo]
    exen = list(exenciones)
    res = ResultadoHistorial()

    blobs = _blobs_del_historial(raiz)
    if not blobs:
        return res
    res.commits = int(
        _git(raiz, "rev-list", "--branches", "--tags", "--count") or b"0")

    tamanos = _tamanos(raiz, list(blobs))

    revisables: list[str] = []
    for sha, tam in tamanos.items():
        ruta = blobs[sha]
        ok, _motivo = ruta_revisable(Path(ruta))
        if not ok:
            res.blobs_omitidos += 1
            continue
        if tam > MAX_BYTES:
            res.blobs_omitidos += 1
            res.omitidos_grandes.append(
                (f"{ruta} ({sha[:8]})",
                 f"pesa {tam // 1_000_000} MB, más del tope de "
                 f"{MAX_BYTES // 1_000_000} MB"))
            continue
        revisables.append(sha)

    sucios: dict[str, list[Hallazgo]] = {}
    for sha, crudo in _contenidos(raiz, revisables):
        texto = descifrar(crudo)
        if texto is None:
            res.blobs_omitidos += 1
            continue
        res.blobs_revisados += 1
        ruta = blobs[sha]
        en_pruebas = es_de_prueba(ruta)
        registro_publico = Path(ruta).name in ARCHIVOS_DE_REGISTRO_PUBLICO
        for det in dets:
            cubierto = next((e for e in exen if e.cubre(ruta, det.nombre)), None)
            if cubierto is not None:
                res.exentos_aplicados[cubierto.patron] = (
                    res.exentos_aplicados.get(cubierto.patron, 0) + 1)
                continue
            for h in det.buscar(texto, ruta):
                if en_pruebas and h.detector in DETECTORES_RELAJADOS_EN_PRUEBAS:
                    continue
                if registro_publico and h.detector not in DETECTORES_RELAJADOS_EN_PRUEBAS:
                    continue
                sucios.setdefault(sha, []).append(h)

    if not sucios:
        return res

    origen = _origen_de(raiz, set(sucios))
    vivos = _vivos_en_head(raiz)
    grupos: dict[tuple, HallazgoHistorico] = {}
    for sha, hallazgos in sucios.items():
        commit, fecha, ruta_origen = origen.get(sha, ("?", "?", blobs[sha]))
        for h in hallazgos:
            # La ruta del reporte es la del commit que lo introdujo: es la
            # que quien va a limpiar tiene que buscar en el historial.
            nuevo = HallazgoHistorico(
                hallazgo=Hallazgo(**{**h.__dict__, "archivo": ruta_origen}),
                commit=commit, fecha=fecha, vivo=sha in vivos,
            )
            clave = (ruta_origen, h.detector, h.que)
            previo = grupos.get(clave)
            if previo is None:
                grupos[clave] = nuevo
            else:
                # Se reporta el commit MÁS VIEJO (ahí empezó la exposición)
                # y se cuenta cuántas versiones la cargaron. `vivo` es OR:
                # si CUALQUIER versión sigue en HEAD, el dato está vivo.
                base = nuevo if nuevo.fecha < previo.fecha else previo
                grupos[clave] = replace(
                    base, versiones=previo.versiones + 1,
                    vivo=previo.vivo or nuevo.vivo)
    res.hallazgos = sorted(
        grupos.values(), key=lambda x: (x.vivo, x.fecha, x.hallazgo.archivo))
    return res
