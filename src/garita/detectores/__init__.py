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
from ..fuentes import a_patron, cargar, existe
from ..nucleo import Detector, Hallazgo
from . import secretos


def _detector_de_lista(etiqueta: str, descripcion: str, por_que: str,
                       como_arreglar: str, patron: "re.Pattern[str]") -> Detector:
    """Los dos detectores de lista —personas y clientes— comparten motor.

    Lo único propio de cada uno es el mensaje, porque el daño es distinto:
    un nombre de persona filtra un dato personal; un nombre de cliente
    filtra una relación comercial que suele estar bajo confidencialidad."""
    def buscar(texto: str, archivo: str) -> Iterator[Hallazgo]:
        for i, linea in enumerate(texto.splitlines(), 1):
            m = patron.search(linea)
            if not m:
                continue
            yield Hallazgo(
                archivo=archivo, linea=i, detector=etiqueta, que=m.group(0),
                por_que=por_que, como_arreglar=como_arreglar,
            )
    return Detector(nombre=etiqueta, descripcion=descripcion, buscar=buscar)


def _lista(cfg_fuentes: list[str], raiz: Path,
           ausentes: list[str] | None = None) -> list[str]:
    """Junta las fuentes de una lista. El prefijo «?» marca una fuente
    OPCIONAL: si el archivo no está en esta máquina (una lista gitignoreada
    que sólo vive donde se necesita), se apunta en `ausentes` y se sigue —
    pero un archivo presente y roto truena igual que siempre. Opcional
    tolera la ausencia, jamás la corrupción."""
    valores: list[str] = []
    for spec in cfg_fuentes:
        if spec.startswith("?"):
            real = spec[1:].strip()
            if not existe(real, raiz):
                if ausentes is not None:
                    ausentes.append(real)
                continue
            valores.extend(cargar(real, raiz))
        else:
            valores.extend(cargar(spec, raiz))
    return sorted(set(valores))


def construir(cfg: Config, raiz: Path,
              listas_ausentes: list[str] | None = None) -> list[Detector]:
    dets: list[Detector] = []

    if cfg.activo("nombre") and cfg.fuentes_nombres:
        nombres = _lista(cfg.fuentes_nombres, raiz, listas_ausentes)
        if nombres:
            dets.append(_detector_de_lista(
                "nombre",
                f"nombres de personas del proyecto ({len(nombres)} en la lista)",
                "Es el nombre de una persona real de este proyecto. Un nombre "
                "junto a un dato —un adeudo, un domicilio, un expediente— "
                "convierte un archivo técnico en un registro personal, y el "
                "historial de git no olvida.",
                "Escríbelo por rol o por identificador: «la Administración» en "
                "vez del nombre, «lote 47» en vez de quién vive ahí. Si de "
                "verdad debe estar (un acta pública, un cargo oficial), exenta "
                "ESE archivo en .garita.yml con su motivo.",
                a_patron(nombres)))

    if cfg.activo("cliente") and cfg.fuentes_clientes:
        # La lista admite lo que identifique al cliente: su nombre, su
        # dominio (cliente.edu.mx), el serial de su appliance. Todo se casa
        # con fronteras de palabra y tolerancia de acentos, igual que los
        # nombres de personas.
        clientes = _lista(cfg.fuentes_clientes, raiz, listas_ausentes)
        if clientes:
            dets.append(_detector_de_lista(
                "cliente",
                f"nombres, dominios o seriales de clientes ({len(clientes)} en la lista)",
                "Identifica a un cliente de este proyecto. Nombrarlo liga al "
                "cliente con lo que este repositorio sabe de él —hallazgos, "
                "infraestructura, contratos— y ese vínculo suele estar bajo "
                "confidencialidad.",
                "Usa el alias convenido (sector + modelo: «transporte_ib1415») "
                "en vez del nombre. Si de verdad debe estar (una carta de "
                "autorización), exenta ESE archivo en .garita.yml con su motivo.",
                a_patron(clientes)))

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
