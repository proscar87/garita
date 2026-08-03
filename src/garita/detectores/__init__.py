#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ensambla los detectores según la configuración.

El de nombres se construye aquí y no en su propio módulo porque es el único
que depende del proyecto revisado: necesita su lista. Los demás saben lo que
buscan sin preguntarle a nadie.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from ..config import Config
from ..fuentes import a_patron, cargar
from ..nucleo import Detector, Hallazgo
from . import secretos


def _detector_nombres(patron: "re.Pattern[str]", cuantos: int) -> Detector:
    def buscar(texto: str, archivo: str) -> Iterator[Hallazgo]:
        for i, linea in enumerate(texto.splitlines(), 1):
            m = patron.search(linea)
            if not m:
                continue
            yield Hallazgo(
                archivo=archivo, linea=i, detector="nombre", que=m.group(0),
                por_que=(
                    "Es el nombre de una persona real de este proyecto. Un "
                    "nombre junto a un dato —un adeudo, un domicilio, un "
                    "expediente— convierte un archivo técnico en un registro "
                    "personal, y el historial de git no olvida."
                ),
                como_arreglar=(
                    "Escríbelo por rol o por identificador: «la Administración» "
                    "en vez del nombre, «lote 47» en vez de quién vive ahí. Si "
                    "de verdad debe estar (un acta pública, un cargo oficial), "
                    "exenta ESE archivo en .garita.yml con su motivo."
                ),
            )
    return Detector(
        nombre="nombre",
        descripcion=f"nombres de personas del proyecto ({cuantos} en la lista)",
        buscar=buscar,
    )


def construir(cfg: Config, raiz: Path) -> list[Detector]:
    dets: list[Detector] = []

    if cfg.activo("nombre") and cfg.fuentes_nombres:
        nombres: list[str] = []
        for spec in cfg.fuentes_nombres:
            nombres.extend(cargar(spec, raiz))
        nombres = sorted(set(nombres))
        dets.append(_detector_nombres(a_patron(nombres), len(nombres)))

    if cfg.activo("secretos"):
        dets.append(Detector(
            nombre="secretos",
            descripcion="JWT, llaves privadas, tokens de proveedor, URLs con contraseña",
            buscar=secretos.buscar,
        ))
    if cfg.activo("asignacion_sospechosa"):
        dets.append(Detector(
            nombre="asignacion_sospechosa",
            descripcion="variables password/token/secret con valor literal",
            buscar=secretos.buscar_asignaciones,
        ))

    # Los identificadores oficiales viven en `paises/`, uno por país.
    from .paises import cargar as cargar_paises
    dets.extend(cargar_paises(cfg))

    return dets
