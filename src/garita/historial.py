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
    MAX_BYTES, Detector, Exencion, Hallazgo, descifrar, filtrar_por_ruta,
    ruta_revisable,
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


# Ramas, tags Y remotos: en un clon fresco las ramas de origin que nunca se
# mergearon sólo existen como refs remotas, y una auditoría que no las ve
# declara limpio un historial que no revisó.
_ALCANCE = ("--branches", "--tags", "--remotes")

# `git log --raw` calla en los commits de merge: un secreto nacido en la
# resolución de un conflicto (el «arreglo rápido» hecho al mergear) no
# aparecía en ninguna pasada y su origen caía al «?» — justo el dato que
# quien limpia necesita. Contra el primer padre, que es la historia que
# la rama cuenta; el commit original de una rama lateral es más viejo y
# gana igual en la sobreescritura.
_CON_MERGES = ("--diff-merges=first-parent",)


def _git(raiz: Path, *args: str) -> bytes:
    # core.quotepath=false: sin esto, git entrega «peña.pem» como
    # «"pe\303\261a.pem"» en --raw y la ruta se reporta mutilada (y ni
    # coincide con la misma ruta sin comillas que da rev-list).
    return subprocess.run(
        ["git", "-c", "core.quotepath=false", *args],
        cwd=raiz, capture_output=True, check=True,
    ).stdout


def _alcance(raiz: Path) -> tuple[str, ...]:
    """El alcance real de la auditoría: ramas, tags, remotos… y HEAD.

    HEAD no es redundante: un commit hecho con la HEAD suelta (checkout
    --detach, bisect, un rebase interrumpido) no es alcanzable desde
    ninguna ref, y sin él la auditoría aprobaba con 0 un historial que no
    revisó — el mismo agujero que la guardia de shallow cierra para los
    clones someros. Se añade sólo si resuelve: en un repo sin commits,
    HEAD pelón hace fallar a git."""
    try:
        _git(raiz, "rev-parse", "--verify", "-q", "HEAD^{commit}")
    except subprocess.CalledProcessError:
        return _ALCANCE
    return _ALCANCE + ("HEAD",)


def _descitar(ruta: str) -> str:
    """Des-cita una ruta C-quoted de `git log --raw`.

    `core.quotepath=false` sólo salva los bytes no ASCII: git SIEMPRE
    C-quota rutas con comillas, backslash o caracteres de control. Como
    `rev-list --objects` entrega la misma ruta cruda, el blob quedaba con
    una ruta real y una fantasma citada — que anulaba la relajación de
    pruebas, rompía exenciones y mutilaba el reporte y el SARIF."""
    if len(ruta) < 2 or ruta[0] != '"' or ruta[-1] != '"':
        return ruta
    cuerpo = ruta[1:-1]
    crudo = bytearray()
    # Los siete que emite quote.c de git, no sólo los cinco obvios: sin
    # \a \b \v \f la ruta quedaba con el backslash literal, distinta de la
    # cruda que da rev-list, y el blob recuperaba su ruta fantasma — el
    # bug que esta función existe para cerrar.
    simples = {'"': b'"', "\\": b"\\", "t": b"\t", "n": b"\n", "r": b"\r",
               "a": b"\a", "b": b"\b", "v": b"\v", "f": b"\f"}
    i = 0
    while i < len(cuerpo):
        c = cuerpo[i]
        if c == "\\" and i + 1 < len(cuerpo):
            s = cuerpo[i + 1]
            if s in simples:
                crudo += simples[s]
                i += 2
                continue
            octal = cuerpo[i + 1:i + 4]
            if len(octal) == 3 and all(ch in "01234567" for ch in octal):
                crudo.append(int(octal, 8))
                i += 4
                continue
        crudo += c.encode("utf-8")
        i += 1
    return crudo.decode("utf-8", "replace")


def es_somero(raiz: Path) -> bool:
    """¿El clon es shallow? Un clon somero no trae la historia, y auditar
    la parte visible para decir «limpio» es aprobar sin revisar."""
    salida = _git(raiz, "rev-parse", "--is-shallow-repository")
    return salida.decode("utf-8", "replace").strip() == "true"


def _blobs_del_historial(raiz: Path) -> dict[str, list[str]]:
    """Cada blob alcanzable desde ramas y tags, con TODAS sus rutas.

    Todas y no la primera, a propósito: el mismo contenido puede vivir en
    `src/secreto.pem` y en `fixtures/ejemplo.pem` (mismo blob, un solo
    SHA), y si la ruta única resultara ser la del fixture, la copia
    «inocente» absolvería a la original. La regla es la contraria: un blob
    se perdona sólo si TODAS sus rutas lo perdonan.

    `rev-list --objects` no basta: deduplica por OBJETO, así que el blob
    sale una sola vez con la primera ruta donde se le vio y las demás ni
    aparecen. Las rutas restantes se juntan de `git log --raw`, que lista
    cada cambio con su blob y su ruta — la copia a `fixtures/` es un
    cambio como cualquiera. Los commits y árboles se filtran después con
    `cat-file --batch-check`, que además trae el tamaño.
    """
    alcance = _alcance(raiz)
    crudo = _git(raiz, "rev-list", "--objects", *alcance)
    blobs: dict[str, list[str]] = {}
    for linea in crudo.decode("utf-8", "replace").splitlines():
        sha, _, ruta = linea.partition(" ")
        if ruta:  # los commits vienen sin ruta; los árboles se filtran luego
            blobs.setdefault(sha, [ruta])

    crudo = _git(raiz, "log", *alcance, *_CON_MERGES, "--raw", "--no-abbrev",
                 "--format=")
    for linea in crudo.decode("utf-8", "replace").splitlines():
        if not linea.startswith(":"):
            continue
        # :modo_viejo modo_nuevo sha_viejo sha_nuevo estado\truta
        partes = linea.split("\t")
        campos = partes[0].split()
        if len(campos) >= 5 and campos[3] in blobs:
            rutas = blobs[campos[3]]
            ruta = _descitar(partes[-1])
            if ruta not in rutas:
                rutas.append(ruta)
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
    cambio, recorrida en orden TOPOLÓGICO e invertido: de los ancestros
    hacia el presente. Así la primera aparición es la introducción de
    verdad, y se queda.

    El orden importa y no es un detalle: por omisión `git log` ordena por
    FECHA DE COMMITTER, que un reloj adelantado, un rebase que conserva
    fechas o un cherry-pick desordenan. Con ese orden, un secreto nacido
    en una rama lateral se le atribuía al merge que lo trajo —anterior en
    el reloj, posterior en la historia— y quien iba a limpiar buscaba en
    el commit equivocado. La topología no miente: el ancestro es el
    ancestro aunque su reloj diga otra cosa.
    """
    if not sucios:
        return {}
    crudo = _git(
        raiz, "log", *_alcance(raiz), *_CON_MERGES, "--topo-order",
        "--reverse", "--raw", "--no-abbrev",
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
                # setdefault y no asignación: en orden topológico invertido
                # la primera aparición ya es la introducción.
                origen.setdefault(
                    campos[3], (commit, fecha, _descitar(partes[-1])))
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
        _git(raiz, "rev-list", *_alcance(raiz), "--count") or b"0")

    tamanos = _tamanos(raiz, list(blobs))

    revisables: list[str] = []
    for sha, tam in tamanos.items():
        # Basta con que UNA ruta sea revisable: si el mismo contenido vivió
        # como `datos.csv` y como `datos.svg`, la extensión sin datos no
        # absuelve a la copia que sí se llama como un archivo de datos.
        if not any(ruta_revisable(Path(r))[0] for r in blobs[sha]):
            res.blobs_omitidos += 1
            continue
        if tam > MAX_BYTES:
            res.blobs_omitidos += 1
            res.omitidos_grandes.append(
                (f"{blobs[sha][0]} ({sha[:8]})",
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
        rutas = blobs[sha]
        for det in dets:
            # Exenciones y filtros de ruta se evalúan por CADA ruta del
            # blob, y el blob se perdona sólo si todas lo perdonan. El
            # contenido se busca una sola vez — es el mismo blob — y cada
            # hallazgo se queda con su versión más severa entre las rutas
            # que no lo suprimen.
            activas = []
            for ruta in rutas:
                cubierto = next(
                    (e for e in exen if e.cubre(ruta, det.nombre)), None)
                if cubierto is not None:
                    res.exentos_aplicados[cubierto.patron] = (
                        res.exentos_aplicados.get(cubierto.patron, 0) + 1)
                else:
                    activas.append(ruta)
            if not activas:
                continue
            for h in det.buscar(texto, activas[0]):
                mejor: Hallazgo | None = None
                for ruta in activas:
                    filtrado = filtrar_por_ruta(h, ruta)
                    if filtrado is None:
                        continue
                    if mejor is None or (filtrado.severidad == "error"
                                         and mejor.severidad != "error"):
                        mejor = filtrado
                if mejor is not None:
                    sucios.setdefault(sha, []).append(mejor)

    if not sucios:
        return res

    origen = _origen_de(raiz, set(sucios))
    vivos = _vivos_en_head(raiz)
    grupos: dict[tuple, HallazgoHistorico] = {}
    for sha, hallazgos in sucios.items():
        commit, fecha, ruta_origen = origen.get(sha, ("?", "?", blobs[sha][0]))
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
