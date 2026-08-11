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

Por omisión se cargan TODOS los países disponibles, porque el costo de
tenerlos encendidos es bajo y el beneficio es que nadie se queda sin
protección por no haber leído la documentación.

«Bajo» no es «nulo», y conviene decir la verdad medida. Entre familias
distintas casi no hay cruce —un RFC mexicano no valida como CPF brasileño—,
pero entre identificadores del MISMO diseño el cruce es la regla, no la
excepción: el NIT guatemalteco y el RUC paraguayo son el mismo módulo 11
sobre la misma base, así que un número válido en uno lo es en el otro el
100 % de las veces; el CUIT argentino y el RUC peruano comparten los pesos
y cruzan el 82 %; y la cédula ecuatoriana satisface el refuerzo del NIT
colombiano el 8 % de las veces.

Eso NO se resuelve mirando el número, porque la información no está ahí. Se
resuelve diciéndolo: cuando dos países reclaman el mismo valor en la misma
línea, el motor emite UN hallazgo que los nombra a todos (ver
`nucleo.fusionar_ambiguos`). Y quien sepa en qué país vive su dato lo acota
con `paises:`, que es lo que vuelve el veredicto inequívoco.

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


NOMBRES = {
    "ar": "Argentina", "br": "Brasil", "ca": "Canadá", "cl": "Chile",
    "co": "Colombia", "do": "República Dominicana", "ec": "Ecuador",
    "es": "España", "gt": "Guatemala", "mx": "México", "pe": "Perú",
    "pt": "Portugal", "py": "Paraguay", "us": "Estados Unidos",
    "uy": "Uruguay", "ve": "Venezuela",
}
"""El país con todas sus letras, para el texto que lee una persona.

El código de dos letras sirve para `paises:` en la configuración; en un
mensaje —«también valida como el ruc_py de py»— no se lee. Vive aquí y no
en cada módulo porque es una sola línea por país y así no se olvida al
agregar el diecisiete: `disponibles()` y este mapa se comparan en las
pruebas.
"""

PAIS_DE_DETECTOR: dict[str, str] = {}
"""De qué país es cada detector de identificadores, llenado al cargar.

Existe para poder FUSIONAR los hallazgos ambiguos. Dos países pueden usar
el mismo algoritmo sobre la misma base —Guatemala y Paraguay son módulo 11
sobre cinco a ocho dígitos, y comparten «factura» y «contribuyente» como
palabra de contexto—, así que el mismo número dispara los dos detectores y
el reporte afirmaba dos cosas incompatibles sobre él. Saber el país permite
decirlo una vez y con los candidatos nombrados.
"""


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
        propios = mod.detectores(cfg)
        for d in propios:
            PAIS_DE_DETECTOR[d.nombre] = codigo
        fuera.extend(propios)
    return fuera
