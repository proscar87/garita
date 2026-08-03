#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
La configuración: `.garita.yml` en la raíz del repositorio.

TRES DECISIONES QUE VALE LA PENA EXPLICAR

**La lista de nombres admite tres orígenes, no uno.** El diseño nació leyendo
la constante del generador de datos sintéticos por AST, que es lo más
elegante: una sola lista, imposible de desincronizar. Pero atarse a eso
excluye a quien tenga su generador en otro lenguaje o no tenga generador.
Por eso también se acepta un JSON y un archivo de texto plano. El AST es la
recomendación, no el requisito.

**No se lee YAML con una librería externa.** Un guardián que exige instalar
dependencias antes de correr es un guardián que la gente pospone. El
subconjunto de YAML que necesita esta configuración —listas y mapas de un
nivel— cabe en cien líneas y se lee sin `pip install`.

**Sin archivo de configuración, hay valores por omisión útiles.** Que alguien
pueda agregar la acción y ver resultados el mismo minuto importa más que la
pureza: los detectores de secretos y de identificadores no necesitan
configurarse. Sólo el de nombres la requiere, porque sólo esa lista es
específica del proyecto.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .nucleo import Exencion


NOMBRE_ARCHIVO = ".garita.yml"


@dataclass
class Config:
    fuentes_nombres: list[str] = field(default_factory=list)
    """Dónde vive la lista de nombres a proteger. Ver `fuentes.cargar`."""

    detectores: dict[str, bool] = field(default_factory=dict)
    """Cuáles activar. Ausente = activo."""

    exenciones: list[Exencion] = field(default_factory=list)

    paises: list[str] = field(default_factory=list)
    """Qué paquetes de identificadores cargar. Vacío = todos los disponibles.

    Tenerlos todos encendidos por omisión casi no cuesta: un identificador con
    dígito verificador no valida fuera de su país, así que no dispara. Y
    evita que alguien se quede sin protección por no haber leído la
    documentación."""

    fallar_en_aviso: bool = False
    """Por omisión los avisos no rompen el build. Quien quiera tolerancia
    cero lo enciende, pero no se le impone: un guardián que rompe el build
    por algo dudoso enseña a la gente a saltárselo."""

    def activo(self, detector: str) -> bool:
        return self.detectores.get(detector, True)


# ── Lector de YAML mínimo ──────────────────────────────────────────────────
#
# Admite exactamente lo que la configuración necesita:
#
#   clave: valor
#   clave:
#     - elemento
#     - clave_interna: valor
#       otra: valor
#
# Cualquier cosa fuera de eso se rechaza con un mensaje que dice qué línea y
# qué se esperaba. Fallar claro es mejor que interpretar de más.

_COMENTARIO = re.compile(r"(?<!\S)#.*$")


class ConfigInvalida(Exception):
    pass


def _valor(bruto: str):
    v = bruto.strip().strip('"').strip("'")
    if v.lower() in ("true", "sí", "si", "yes"):
        return True
    if v.lower() in ("false", "no"):
        return False
    return v


def _leer_yaml(texto: str) -> dict:
    raiz: dict = {}
    pila: list[tuple[int, object]] = [(-1, raiz)]

    for n, cruda in enumerate(texto.splitlines(), 1):
        linea = _COMENTARIO.sub("", cruda).rstrip()
        if not linea.strip():
            continue
        sangria = len(linea) - len(linea.lstrip())
        cuerpo = linea.strip()

        while len(pila) > 1 and sangria <= pila[-1][0]:
            pila.pop()
        contenedor = pila[-1][1]

        if cuerpo.startswith("- "):
            item = cuerpo[2:].strip()
            if not isinstance(contenedor, list):
                raise ConfigInvalida(
                    f"línea {n}: hay un elemento de lista donde se esperaba un "
                    f"mapa. Revisa la sangría."
                )
            # Un elemento de lista es un MAPA sólo si lleva «clave: valor»
            # con espacio tras los dos puntos, que es la regla de YAML. Sin
            # ella, «scripts/gen.py:PROHIBIDOS» se partía en una clave
            # «scripts/gen.py» y perdía la fuente en silencio — justo el tipo
            # de falla que hace que un guardián revise menos de lo que cree.
            if re.match(r"^[^:\s]+:\s", item) and not item.startswith(("http", '"', "'")):
                k, _, v = item.partition(":")
                d = {k.strip(): _valor(v)}
                contenedor.append(d)
                pila.append((sangria, d))
            else:
                contenedor.append(_valor(item))
            continue

        if ":" not in cuerpo:
            raise ConfigInvalida(
                f"línea {n}: «{cuerpo}» no es «clave: valor» ni «- elemento»."
            )

        if not re.match(r"^[^:]+:(\s|$)", cuerpo):
            raise ConfigInvalida(
                f"línea {n}: «{cuerpo}» — falta el espacio tras los dos puntos."
            )
        clave, _, resto = cuerpo.partition(":")
        clave = clave.strip()
        if not isinstance(contenedor, dict):
            raise ConfigInvalida(f"línea {n}: clave dentro de una lista sin «- ».")

        if resto.strip():
            contenedor[clave] = _valor(resto)
        else:
            hijo: list = []
            contenedor[clave] = hijo
            pila.append((sangria, hijo))

    return raiz


def _a_mapa(valor):
    """Una lista de mapas de una llave se colapsa a un solo mapa.

    `detectores:` con elementos `- curp: false` llega como lista de
    diccionarios; para consultarla conviene un mapa.
    """
    if isinstance(valor, dict):
        return valor
    fuera = {}
    if isinstance(valor, list):
        for x in valor:
            if isinstance(x, dict):
                fuera.update(x)
    return fuera


def cargar(raiz: Path) -> Config:
    ruta = raiz / NOMBRE_ARCHIVO
    if not ruta.is_file():
        # Sin configuración se revisa lo que no requiere saber nada del
        # proyecto. El detector de nombres queda apagado porque sin lista no
        # tiene nada contra qué comparar, y se dice en el reporte.
        return Config(detectores={"nombre": False})

    try:
        datos = _leer_yaml(ruta.read_text(encoding="utf-8"))
    except ConfigInvalida as e:
        raise ConfigInvalida(f"{NOMBRE_ARCHIVO}: {e}") from e

    fuentes = datos.get("nombres", [])
    if isinstance(fuentes, str):
        fuentes = [fuentes]
    fuentes = [f for f in fuentes if isinstance(f, str)]

    exenciones = []
    for e in datos.get("exenciones", []) or []:
        if not isinstance(e, dict):
            raise ConfigInvalida(
                "cada exención necesita al menos «archivo» y «motivo»."
            )
        archivo = e.get("archivo")
        motivo = e.get("motivo")
        if not archivo or not motivo:
            raise ConfigInvalida(
                f"la exención de «{archivo or '?'}» no tiene motivo. El motivo "
                f"es obligatorio: una lista de exenciones sin razones se "
                f"convierte, en pocos meses, en la lista de archivos que "
                f"nadie se atreve a tocar porque nadie sabe por qué están ahí."
            )
        dets = e.get("detectores", "")
        detectores = tuple(d.strip() for d in str(dets).split(",") if d.strip())
        exenciones.append(Exencion(str(archivo), str(motivo), detectores))

    paises = datos.get("paises", "")
    if isinstance(paises, str):
        paises = [p.strip() for p in paises.split(",") if p.strip()]
    paises = [str(p).strip() for p in paises if str(p).strip()]

    return Config(
        fuentes_nombres=fuentes,
        paises=paises,
        detectores={k: bool(v) for k, v in _a_mapa(datos.get("detectores", [])).items()},
        exenciones=exenciones,
        fallar_en_aviso=bool(datos.get("fallar_en_aviso", False)),
    )
