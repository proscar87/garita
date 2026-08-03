#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Identificadores oficiales, por país.

POR QUÉ PAQUETES Y NO RAMAS

La tentación al agregar un segundo país es abrir una rama. Es un error que se
paga tarde: cada rama deja de recibir los arreglos de las demás, y el bug que
alguien corrige en el motor —una evasión por codificación, un falso positivo—
sólo llega a la rama donde se corrigió. En seis meses hay cinco versiones
divergentes y ninguna es la buena.

Aquí cada país es un módulo de este paquete. Comparten el motor, las
exenciones, el reporte y las pruebas; lo único propio es su archivo. Un
arreglo del motor llega a todos el mismo día.

CÓMO SE ELIGE QUÉ SE REVISA

Por omisión se cargan TODOS los países disponibles. Suena agresivo y no lo es:
un detector con dígito verificador prácticamente no dispara fuera de su país
—un RFC mexicano no valida como CPF brasileño—, así que el costo de tenerlos
todos encendidos es casi nulo y el beneficio es que nadie se queda sin
protección por no haber leído la documentación.

Quien quiera acotarlo lo dice en la configuración:

    paises: mx, es

Agregar un país está documentado en `docs/AGREGAR_PAIS.md`. La regla que hace
que valga la pena: **sólo se acepta un identificador si su validación se puede
verificar contra una fuente oficial**. Un detector que sólo mira la forma
produce ruido, y el ruido es lo que enseña a la gente a ignorar al guardián.
"""
from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...config import Config
    from ...nucleo import Detector


def disponibles() -> list[str]:
    """Los códigos de país que hay, leídos del propio paquete.

    Se descubren en vez de listarse a mano: una lista escrita es una lista que
    alguien olvida actualizar al agregar un país, y entonces el módulo existe
    pero nunca se carga.
    """
    return sorted(
        m.name for m in pkgutil.iter_modules(__path__)
        if not m.name.startswith("_")
    )


def cargar(cfg: "Config") -> list["Detector"]:
    pedidos = cfg.paises or disponibles()
    fuera: list[Detector] = []
    for codigo in pedidos:
        if codigo not in disponibles():
            raise ValueError(
                f"no conozco el país «{codigo}». Disponibles: "
                f"{', '.join(disponibles())}. Si quieres agregarlo, "
                f"docs/AGREGAR_PAIS.md explica cómo."
            )
        mod = importlib.import_module(f"{__name__}.{codigo}")
        fuera.extend(mod.detectores(cfg))
    return fuera
