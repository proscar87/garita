#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regenera src/garita/detectores/paises/_mx_ladas.py desde el IFT.

El guion bajo del nombre importa: los módulos de `paises/` sin él se
autodescubren como países y se les exige una función `detectores()`.

Baja la descarga pública del Plan Nacional de Numeración (sns.ift.org.mx),
extrae las claves lada asignadas y reescribe el módulo completo. Correr a
mano cuando el IFT asigne ladas nuevas — pasa poco; una vez al año alcanza.

Sin dependencias, como todo el proyecto. El portal es JSF (PrimeFaces):
hay que pedir la página, quedarse con la cookie y el ViewState, y hacer el
POST del botón. Si el portal cambia, lo que se rompe es este script, nunca
la herramienta: la lista versionada sigue siendo la última buena.

Nota de red: el servidor no responde bien por IPv6 en algunas redes. Si el
GET se cuelga, fuerza IPv4 (en macOS: NODE_OPTIONS no aplica aquí; usa una
red que resuelva IPv4 o un `--dns-result-order` equivalente del sistema).
"""
from __future__ import annotations

import csv
import io
import re
import sys
import urllib.parse
import urllib.request
import zipfile
from datetime import date
from http.cookiejar import CookieJar
from pathlib import Path

URL = "https://sns.ift.org.mx/sns-frontend/planes-numeracion/descarga-publica.xhtml"
DESTINO = Path(__file__).resolve().parent.parent / (
    "src/garita/detectores/paises/_mx_ladas.py")
DOS_DIGITOS = ("55", "56", "33", "81")


def bajar_csv() -> tuple[str, str]:
    """Devuelve (nombre_del_csv, contenido)."""
    jar = CookieJar()
    ab = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    ab.addheaders = [("User-Agent", "garita/actualizar-ladas")]

    pagina = ab.open(URL, timeout=60).read().decode("utf-8", "replace")
    m = re.search(r'name="javax\.faces\.ViewState"[^>]*value="([^"]+)"', pagina)
    if not m:
        sys.exit("No encontré el ViewState: el portal del IFT cambió.")

    datos = urllib.parse.urlencode({
        "FORM_planes": "FORM_planes",
        "FORM_planes:BTN_planPublico1": "",
        "javax.faces.ViewState": m.group(1),
    }).encode()
    respuesta = ab.open(urllib.request.Request(URL, data=datos), timeout=300)
    zf = zipfile.ZipFile(io.BytesIO(respuesta.read()))
    nombre = zf.namelist()[0]
    return nombre, zf.read(nombre).decode("utf-8", "replace")


def extraer_ladas(contenido: str) -> list[str]:
    ladas = set()
    filas = csv.reader(io.StringIO(contenido))
    next(filas)  # encabezado
    for fila in filas:
        if len(fila) < 3:
            continue
        num = fila[1].strip()
        if len(num) != 10 or not num.isdigit():
            continue
        ladas.add(num[:2] if num[:2] in DOS_DIGITOS else num[:3])
    return sorted(ladas, key=lambda x: (len(x), x))


PLANTILLA = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Las claves lada asignadas en el Plan Nacional de Numeración del IFT.

POR QUE EXISTE ESTE ARCHIVO

El plan de numeracion mexicano y el estadounidense comparten el formato
3-3-4: sin esta lista, un 555, un 212 de Manhattan o un 202 de Washington
pasan por telefonos mexicanos y hacen ruido exactamente en los proyectos
que mas documentan telefonos (faker genera miles). Con ella, un numero
cuya lada no esta asignada en Mexico simplemente no es un telefono
mexicano y no se reporta.

La lista NO se invento ni se aproximo: viene de la descarga publica del
PNN en sns.ift.org.mx. Para actualizarla: scripts/actualizar_ladas.py
(reescribe este archivo completo; no lo edites a mano).

Corte de los datos: {nombre_csv} ({fecha}).
{n} ladas: 33, 55, 56 y 81 de dos digitos, el resto de tres.
"""

_CRUDAS = """
{cuerpo}
"""

LADAS = frozenset(_CRUDAS.split())
'''


def main() -> None:
    nombre, contenido = bajar_csv()
    ladas = extraer_ladas(contenido)
    if len(ladas) < 350:
        # Un corte con muchas menos ladas de las conocidas es una descarga
        # rota, no una desasignación masiva. Mejor no escribir nada.
        sys.exit(f"Sólo salieron {len(ladas)} ladas; esperaba ~400. "
                 f"No reescribo el módulo.")
    lineas, fila = [], []
    for l in ladas:
        fila.append(l)
        if len(fila) == 12:
            lineas.append(" ".join(fila))
            fila = []
    if fila:
        lineas.append(" ".join(fila))
    DESTINO.write_text(PLANTILLA.format(
        nombre_csv=nombre, fecha=date.today().isoformat(),
        n=len(ladas), cuerpo="\n".join(lineas)), encoding="utf-8")
    print(f"{DESTINO.name}: {len(ladas)} ladas, corte {nombre}")


if __name__ == "__main__":
    main()
