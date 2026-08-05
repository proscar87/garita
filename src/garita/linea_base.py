#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
La línea base: cómo se enciende Garita en un repositorio que ya existe.

EL PROBLEMA QUE RESUELVE

Un guardián que sólo sirve en repositorios nuevos no sirve. Quien más lo
necesita es justamente quien ya lleva años acumulando: enciende Garita, le
salen cuarenta hallazgos, el build queda rojo y no puede arreglarlos hoy. Las
dos salidas que le quedan son escribir cuarenta exenciones a mano —cada una
mintiendo con un motivo inventado— o apagar la herramienta. Casi siempre
apaga la herramienta.

La línea base congela lo que ya estaba y deja que CI falle sólo con lo NUEVO.
La deuda vieja se ve, se documenta y se paga cuando se pueda; la sangría se
detiene hoy. Es la diferencia entre una herramienta que se adopta y una que
se admira de lejos.

QUÉ SE GUARDA, Y POR QUÉ NO EL VALOR

El archivo de línea base se commitea. Guardar ahí el valor encontrado sería
filtrar exactamente lo que esta herramienta existe para no filtrar, y en un
archivo que además nadie mira.

Guardar un *hash* tampoco alcanza. Para un secreto de alta entropía sería
seguro, pero para un identificador nacional no: un CURP tiene estructura
—iniciales, fecha de nacimiento, estado, sexo— y su espacio se recorre por
fuerza bruta en hardware modesto. Un hash de CURP es un CURP con un candado
de juguete.

Así que no se guarda ningún derivado del valor. Sólo **cuántos hallazgos de
cada detector había en cada archivo**. Eso alcanza para lo que la línea base
tiene que hacer —detectar que apareció algo nuevo— y no filtra absolutamente
nada.

LA LIMITACIÓN, DICHA EN VOZ ALTA

Contar tiene un hueco: si alguien SUSTITUYE un dato por otro en el mismo
archivo, el total no cambia y la línea base no lo nota. Reemplazar el CURP de
una persona por el de otra pasa silencioso.

Se acepta a conciencia. La alternativa era guardar hashes de datos
personales en un archivo commiteado, y ese remedio es peor que la
enfermedad. Quien necesite cubrir también la sustitución tiene el camino
correcto a la mano: pagar la deuda y borrar la línea base, que es lo que
debería pasar de todos modos.

Por eso el archivo lleva la fecha en que se creó. Una línea base es una
promesa de limpiar después, y las promesas sin fecha no se cumplen.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .nucleo import Hallazgo

NOMBRE_POR_OMISION = ".garita-base.json"
# 2: la clave del conteo incluye la severidad. Con la 1, un aviso congelado
# perdonaba un ERROR nuevo del mismo detector en el mismo archivo — y con
# `fallar_en_aviso` apagado, que es el default, el veredicto salía 0.
FORMATO = 2


class LineaBaseInvalida(Exception):
    """El archivo existe pero no se puede leer.

    Se trata como error de configuración, nunca como «no hay línea base»:
    seguir sin ella marcaría en rojo todo lo que el equipo ya había aceptado
    y el reporte sería inservible; seguir *con* la que se creyó leer, cuando
    no se leyó, aprobaría hallazgos nuevos. Ninguna de las dos se vale.
    """


@dataclass(frozen=True)
class LineaBase:
    creada: str
    """Fecha en que se generó. Una línea base vieja es deuda que envejece."""
    conteos: dict[str, int]
    """«archivo\\x00detector\\x00severidad» → cuántos hallazgos había."""
    total: int

    @staticmethod
    def _clave(archivo: str, detector: str, severidad: str) -> str:
        # La severidad va en la clave porque varios detectores emiten aviso
        # o error según el contexto (una CLABE dentro de una URL es aviso; a
        # pelo, error). Sin ella, congelar un aviso perdonaba un error nuevo
        # y el veredicto salía 0: deuda aceptada que absuelve lo que nunca
        # se aceptó.
        return f"{archivo}\x00{detector}\x00{severidad}"

    def filtrar(self, hallazgos: Iterable[Hallazgo]) -> tuple[list, list]:
        """Separa en (nuevos, ya_conocidos).

        Se agrupa por archivo, detector Y severidad, y se perdonan tantos
        hallazgos como había. El orden importa: se perdonan los de línea más
        baja primero, para que al agregar algo al final del archivo sea lo
        nuevo lo que aparece, y no un salto arbitrario.
        """
        por_grupo: dict[str, list[Hallazgo]] = {}
        for h in hallazgos:
            por_grupo.setdefault(
                self._clave(h.archivo, h.detector, h.severidad), []).append(h)

        nuevos, conocidos = [], []
        for clave, hs in por_grupo.items():
            perdonables = self.conteos.get(clave, 0)
            for h in sorted(hs, key=lambda x: x.linea):
                if perdonables > 0:
                    perdonables -= 1
                    conocidos.append(h)
                else:
                    nuevos.append(h)
        return nuevos, conocidos

    def obsoletas(self, hallazgos: Iterable[Hallazgo]) -> list[str]:
        """Entradas que ya no corresponden a ningún hallazgo.

        Deuda pagada. Decirlo es el único momento en que alguien se entera de
        que puede achicar el archivo — si no, la línea base sólo crece y
        termina perdonando cosas que nadie recuerda haber aceptado.
        """
        vivos = Counter(
            self._clave(h.archivo, h.detector, h.severidad) for h in hallazgos)
        return sorted(
            clave.replace("\x00", " · ")
            for clave, n in self.conteos.items()
            if vivos.get(clave, 0) < n
        )


def construir(hallazgos: Iterable[Hallazgo], fecha: str) -> LineaBase:
    conteos = Counter(
        LineaBase._clave(h.archivo, h.detector, h.severidad) for h in hallazgos
    )
    return LineaBase(creada=fecha, conteos=dict(conteos), total=sum(conteos.values()))


def guardar(lb: LineaBase, ruta: Path) -> None:
    # Ordenado y con sangría: este archivo se revisa en un pull request, y un
    # diff ilegible es un diff que se aprueba sin leer.
    datos = {
        "formato": FORMATO,
        "creada": lb.creada,
        "total": lb.total,
        "_nota": (
            "Hallazgos que ya existían cuando se encendió Garita. No se "
            "guarda ningún valor ni hash: sólo cuántos había por archivo, "
            "detector y severidad. Esto es deuda aceptada, no deuda "
            "perdonada — bórrala "
            "conforme la pagues. Regenerar: garita --linea-base"
        ),
        "conteos": {
            clave.replace("\x00", "::"): n
            for clave, n in sorted(lb.conteos.items())
        },
    }
    ruta.write_text(
        json.dumps(datos, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def cargar(ruta: Path) -> LineaBase | None:
    """Devuelve None si no existe; levanta si existe y está rota."""
    if not ruta.is_file():
        return None
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise LineaBaseInvalida(f"{ruta}: {e}") from e

    if not isinstance(datos, dict):
        raise LineaBaseInvalida(f"{ruta}: se esperaba un objeto JSON.")

    formato = datos.get("formato")
    if formato != FORMATO:
        raise LineaBaseInvalida(
            f"{ruta}: formato {formato!r}, esperado {FORMATO}. La escribió "
            f"otra versión de Garita; regenérala con «garita --linea-base»."
        )

    crudo = datos.get("conteos")
    if not isinstance(crudo, dict):
        raise LineaBaseInvalida(f"{ruta}: falta el mapa «conteos».")

    conteos: dict[str, int] = {}
    for clave, n in crudo.items():
        if not isinstance(n, int) or n < 0:
            raise LineaBaseInvalida(
                f"{ruta}: «{clave}» tiene un conteo inválido ({n!r})."
            )
        resto, _, severidad = clave.rpartition("::")
        archivo, _, detector = resto.rpartition("::")
        if not archivo or not detector or severidad not in ("error", "aviso"):
            raise LineaBaseInvalida(
                f"{ruta}: la clave «{clave}» no trae "
                f"«archivo::detector::severidad»."
            )
        conteos[LineaBase._clave(archivo, detector, severidad)] = n

    return LineaBase(
        creada=str(datos.get("creada", "?")),
        conteos=conteos,
        total=sum(conteos.values()),
    )
