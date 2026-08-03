# Agregar un país

Garita empezó con México porque ahí nació el problema. La arquitectura está
hecha para que agregar otro país sea un archivo, no una rama.

**Si tu país no está, esta es la contribución más útil que puedes hacer.**

---

## Por qué paquetes y no ramas

La tentación es abrir una rama `colombia`. Se paga tarde: cada rama deja de
recibir los arreglos de las demás, y el bug que alguien corrige en el motor
—una evasión por codificación, un falso positivo que ahogaba el reporte— sólo
llega a la rama donde se corrigió. En seis meses hay cinco versiones
divergentes y ninguna es la buena.

Cada país es un módulo en `src/garita/detectores/paises/`. Comparten el motor,
las exenciones, el reporte y la infraestructura de pruebas. Un arreglo del
motor llega a todos el mismo día.

---

## La regla que no se negocia

> **Sólo se acepta un identificador si su validación se puede verificar contra
> una fuente oficial.**

No basta el patrón. Un detector que sólo mira la forma marca cualquier cadena
que se le parezca, y el ruido es lo que enseña a la gente a ignorar al
guardián — ese día deja pasar el dato de verdad.

En la práctica esto significa que un identificador entra si tiene **dígito
verificador, letra de control o suma de comprobación** documentada. Si no lo
tiene, puede entrar igual, pero **exigiendo contexto léxico en la misma
línea**, como hace el NSS mexicano.

Si no encuentras el algoritmo en fuente oficial, dilo en el pull request en
vez de aproximarlo. Un detector aproximado es peor que ninguno.

---

## Qué escribir

Un archivo `src/garita/detectores/paises/<código ISO>.py`. Tómalo de `mx.py`,
que es el ejemplo trabajado.

```python
"""
Colombia: NIT, cédula.

Fuentes en docs/IDENTIFICADORES.md.
"""
from __future__ import annotations

import re
from typing import Iterator

from ...config import Config
from ...nucleo import Detector, Hallazgo


_NIT = re.compile(r"\b\d{9}-?\d\b")


def nit_valido(nit: str) -> bool:
    """Dígito de verificación del NIT, según la DIAN."""
    ...


def _buscar_nit(texto: str, archivo: str) -> Iterator[Hallazgo]:
    for i, linea in enumerate(texto.splitlines(), 1):
        for m in _NIT.finditer(linea):
            v = m.group(0)
            if v in GENERICOS or not nit_valido(v):
                continue
            yield Hallazgo(
                archivo=archivo, linea=i, detector="nit",
                que=v[:4] + "…" + v[-2:],          # NUNCA el valor completo
                por_que="Es un NIT con dígito de verificación válido. …",
                como_arreglar="…",
            )


def detectores(cfg: Config) -> list[Detector]:
    return [
        Detector(nombre="nit", descripcion="NIT con dígito válido",
                 buscar=_buscar_nit)
    ] if cfg.activo("nit") else []
```

Sólo eso. El registro descubre el módulo solo: no hay ninguna lista que
actualizar.

### Los nombres de los detectores son globales

`curp`, `rfc`, `nit`, `cpf`… viven en el mismo espacio de nombres, porque así
un usuario los apaga o los exenta sin saber de qué país vienen. Si tu país
tiene un identificador que se llama igual que uno existente pero es otra cosa,
antepón el código: `br_rg`.

---

## Qué más incluir

**1. Pruebas, con tantos casos negativos como positivos.** En
`tests/test_garita.py`, junto a las de México. La falla por exceso mata más
guardianes que la falla por omisión, así que cada falso positivo que se te
ocurra merece su prueba:

- Los vectores oficiales de tu fuente, válidos
- El mismo con el dígito mutado, inválido
- Los identificadores **genéricos o de prueba** que la autoridad publique
  (México tiene dos RFC genéricos que no identifican a nadie) — deben quedar
  exentos
- Ruido plausible: ids de la misma longitud, fechas, marcas de tiempo, folios

**2. Una sección en `docs/IDENTIFICADORES.md`** con la estructura del
identificador, el algoritmo en código, los vectores y **la fuente oficial**.

**3. Nada de datos reales.** Ni en el código, ni en las pruebas, ni en la
documentación. Usa los ejemplos que publique la autoridad o construye
sintéticos calculando el dígito con tu propia función. Si un sitio muestra el
identificador de una persona real, no lo copies.

---

## Cómo se usa una vez agregado

Por omisión se cargan **todos** los países disponibles. No es agresivo: un
identificador con dígito verificador prácticamente no dispara fuera de su país
—un RFC mexicano no valida como CPF brasileño—, así que tenerlos todos
encendidos casi no cuesta y evita que alguien se quede sin protección por no
haber leído esto.

Quien quiera acotarlo:

```yaml
# .garita.yml
paises: mx, co
```

---

## Lo que se agradece especialmente

Países donde el identificador nacional aparece seguido en repositorios de
trabajo: facturación, nómina, salud, trámites. Ahí es donde un dato personal
entra a git sin que nadie lo note, porque el archivo parece técnico.

Y si tu país **no tiene** dígito verificador en su identificador principal,
dilo en un issue antes de escribir código: probablemente la respuesta correcta
sea exigir contexto léxico, y conviene decidirlo juntos antes de que exista un
detector ruidoso.
