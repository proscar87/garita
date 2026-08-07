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
    fuentes_clientes: list[str] = field(default_factory=list)
    """Dónde vive la lista de clientes (nombres, dominios, seriales). Mismo
    mecanismo que los nombres: la lista ya existe en algún lado del proyecto
    —el CRM, el generador de alias— y se lee de ahí, no se duplica aquí."""

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
    # Las colecciones vacías en línea. Sin esto, «exenciones: []» quedaba como
    # la CADENA "[]" y el validador la rechazaba con «cada exención necesita
    # archivo y motivo» — sobre una lista que no tiene exenciones. Un repo que
    # declara explícitamente «aquí no hay exenciones» es justo el caso que hay
    # que premiar, y era el único que no compilaba.
    if v in ("[]", "{}"):
        return [] if v == "[]" else {}
    # Los mismos booleanos que acepta YAML 1.1, ni más ni menos. Con la
    # lista corta, «fallar_en_aviso: off» quedaba como la cadena «off» —
    # que es verdadera— y reprobaba el build justo cuando se pedía lo
    # contrario: la clase de sorpresa que enseña a desactivar el paso.
    if v.lower() in ("true", "sí", "si", "yes", "y", "on", "1"):
        return True
    if v.lower() in ("false", "no", "n", "off", "0"):
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

        # Una clave repetida se DICE. Dos bloques «nombres:» —lo que sale de
        # fusionar dos configuraciones o de un merge mal resuelto— dejaban
        # viva sólo la última fuente, y dos «detectores:» revivían lo que el
        # primero apagó: sin mensaje y sin rastro. Todo lo demás de este
        # archivo falla ruidoso; esto también.
        if clave in contenedor:
            raise ConfigInvalida(
                f"línea {n}: «{clave}» ya se definió antes. El segundo "
                f"bloque borraría al primero en silencio: únelos."
            )

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


def _fuentes(clave: str, valor) -> list[str]:
    """Las fuentes de una lista, o error ruidoso.

    El filtro mudo de antes (`isinstance(f, str)`) tiraba en silencio lo que
    no fuera cadena, y basta el espacio tras los dos puntos —lo que la
    ortografía YAML pide— para que `- gen.py: PROHIBIDOS` se lea como mapa,
    se borre, y el detector de nombres deje de correr con código 0. Es la
    degradación que `fuentes.py` declara inaceptable en tres docstrings: ahí
    una fuente rota es código 2, y aquí una mal escrita se tragaba entera.
    """
    if isinstance(valor, str):
        valor = [valor]
    fuera = []
    for f in valor or []:
        if isinstance(f, str):
            fuera.append(f)
            continue
        if isinstance(f, dict) and len(f) == 1:
            k, v = next(iter(f.items()))
            raise ConfigInvalida(
                f"«{clave}» tiene una fuente que se leyó como mapa: "
                f"«{k}: {v}». Quita el espacio tras los dos puntos "
                f"(«{k}:{v}») para que sea la ruta y el símbolo."
            )
        raise ConfigInvalida(
            f"«{clave}» tiene una fuente que no es una cadena: {f!r}."
        )
    return fuera


def cargar(raiz: Path, nombre: str = NOMBRE_ARCHIVO) -> Config:
    ruta = raiz / nombre
    if not ruta.is_file():
        # Sin configuración se revisa lo que no requiere saber nada del
        # proyecto. El detector de nombres queda apagado porque sin lista no
        # tiene nada contra qué comparar, y se dice en el reporte.
        return Config(detectores={"nombre": False})

    try:
        # utf-8-sig y no utf-8: el BOM sobrevivía dentro del texto y volvía
        # la PRIMERA clave del archivo en «﻿nombres», que ningún
        # `datos.get` encuentra. Con `nombres:` arriba —el orden del
        # ejemplo del README— la lista desaparecía y el detector se apagaba
        # sin decir nada. Es el default de Notepad, del «UTF-8 with BOM» de
        # VS Code y de PowerShell; y utf-8-sig lee igual de bien lo que no
        # trae marca.
        datos = _leer_yaml(ruta.read_text(encoding="utf-8-sig"))
    except ConfigInvalida as e:
        raise ConfigInvalida(f"{NOMBRE_ARCHIVO}: {e}") from e
    except (UnicodeDecodeError, OSError) as e:
        # Una configuración ilegible es error de entorno, no un hallazgo:
        # antes salía por traceback con código 1, el reservado a «hay algo
        # que arreglar en el repo».
        raise ConfigInvalida(
            f"{NOMBRE_ARCHIVO}: no se pudo leer ({e}). Guárdalo en UTF-8."
        ) from e

    fuentes = _fuentes("nombres", datos.get("nombres", []))
    fuentes_cli = _fuentes("clientes", datos.get("clientes", []))

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
        # La forma de lista YAML («detectores:» y guiones debajo) llegaba
        # como list, y str() la volvía «['clabe']»: la exención no casaba
        # ningún detector y dejaba de exentar EN SILENCIO — el patrón sí
        # coincidía, así que tampoco salía como exención muerta.
        dets = e.get("detectores", "")
        if isinstance(dets, (list, tuple)):
            dets = ",".join(str(d) for d in dets)
        elif not isinstance(dets, str):
            raise ConfigInvalida(
                f"la exención de «{archivo}» tiene «detectores: {dets!r}», "
                f"que no es una lista ni una lista separada por comas."
            )
        detectores = tuple(d.strip() for d in dets.split(",") if d.strip())
        exenciones.append(Exencion(str(archivo), str(motivo), detectores))

    paises = datos.get("paises", "")
    if isinstance(paises, str):
        paises = [p.strip() for p in paises.split(",") if p.strip()]
    paises = [str(p).strip() for p in paises if str(p).strip()]

    return Config(
        fuentes_nombres=fuentes,
        fuentes_clientes=fuentes_cli,
        paises=paises,
        detectores={k: bool(v) for k, v in _a_mapa(datos.get("detectores", [])).items()},
        exenciones=exenciones,
        fallar_en_aviso=bool(datos.get("fallar_en_aviso", False)),
    )
