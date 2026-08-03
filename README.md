# Garita

**Impide que datos personales y credenciales entren a tu repositorio.**
Nombres de tu propio padrón, CURP, RFC, CLABE, NSS, teléfonos mexicanos y
secretos — como hook de `pre-commit` y como GitHub Action.

[English below](#english) · MIT · Sin dependencias · Python ≥ 3.9

---

## Por qué existe

Nació de un problema común: un proyecto donde los datos financieros TIENEN
que estar versionados —hay que auditarlos— y el padrón de personas NO puede
estar. La **LFPDPPP** lo regula, y el historial de git no olvida.

La regla que salió de ahí resume la herramienta:

> **La línea es el lote, no el nombre.**
> Se puede versionar el número de lote y su adeudo. Jamás la liga entre ese
> lote y la persona que vive en él.

Buscamos con qué hacerla cumplir y no encontramos nada. Presidio de Microsoft
cubre más de veinte países y **México no está**. GitGuardian **rechaza
explícitamente** patrones de PII. GitHub cobra los patrones personalizados, y
aun así son de secretos, no listas de nombres. `git-secrets`, lo único que
podía vetar cadenas arbitrarias, está sin mantenimiento desde 2019.

Garita es eso que faltaba.

---

## Lo que revisa

| Detector | Qué busca | Cómo evita gritar en falso |
|---|---|---|
| `nombre` | Nombres de personas de **tu** proyecto | Fronteras de palabra, tolerante a acentos |
| `curp` | CURP | **Dígito verificador** + fecha + catálogo de entidades |
| `rfc` | RFC | **Dígito verificador** (módulo 11) + fecha |
| `clabe` | CLABE interbancaria | **Dígito de control** (3-7-1, módulo 10) |
| `nss` | NSS del IMSS | **Luhn** + exige contexto léxico en la línea |
| `telefono` | Teléfono mexicano de 10 dígitos | Prefijo, separadores o contexto |
| `secretos` | JWT, llaves privadas, tokens, URLs con contraseña | Estructura completa, no fragmentos |
| `asignacion_sospechosa` | `password = "algo largo"` | Ignora lecturas del entorno |

**Validar el dígito verificador no es un detalle.** Un detector que marca
cualquier cadena de 18 caracteres como CURP grita todo el tiempo, y un
guardián que grita se acaba ignorando — ese día deja pasar el dato de verdad.
Con el dígito, los falsos positivos caen entre 90 y 5,000 veces según el
identificador.

---

## La idea central: una sola lista

Un guardián que compara contra una lista escrita en su configuración tiene un
defecto fatal: **la lista es un dato personal más**. Para impedir que el
padrón entre al repositorio, tendrías que escribir el padrón en el
repositorio. El remedio filtra lo que cura.

La salida: casi todo proyecto que maneja datos reales ya tiene un **generador
de datos sintéticos** para sus pruebas y su *seed*. Ese generador necesita
saber qué nombres reales NO debe producir por accidente, así que **ya
contiene la lista**.

```yaml
# .garita.yml
nombres:
  - scripts/generar_datos_sinteticos.py:PROHIBIDOS
```

Garita la lee de ahí **por AST, sin ejecutar el archivo**. Una sola lista,
imposible de desincronizar: cuando alguien agrega una persona al generador, el
guardián se entera solo.

> Si tu generador está en otro lenguaje o no tienes uno, también se acepta un
> JSON (`datos.json:padron.nombres`) o un archivo de texto, uno por línea. El
> AST es la recomendación, no el requisito.

---

## Instalación

### Como hook de pre-commit — **empieza por aquí**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/proscar87/garita
    rev: v0.1.0
    hooks:
      - id: garita
```

```bash
pre-commit install
```

**Por qué primero el hook:** si tu único control está en CI, cuando falle el
dato personal **ya vive en un commit** — y el arreglo pasa de «borra la línea»
a «reescribe el historial y avisa a quien haya clonado». El hook es donde el
arreglo todavía es barato.

### Como GitHub Action — el respaldo

```yaml
# .github/workflows/garita.yml
name: Garita
on: [push, pull_request]

jobs:
  revisar:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: proscar87/garita@v0.1.0
```

Es lo que nadie puede saltarse con `--no-verify`. Las dos capas se
complementan; ninguna sustituye a la otra.

### Como comando

```bash
pip install garita
garita              # revisa el repositorio
garita --explicar   # dice qué va a revisar y con qué configuración
```

---

## Configuración

Todo es opcional salvo la lista de nombres. Sin `.garita.yml`, Garita revisa
identificadores y secretos —que no necesitan saber nada de tu proyecto— y
apaga el detector de nombres avisándolo.

```yaml
# .garita.yml

nombres:
  - scripts/generar_datos_sinteticos.py:PROHIBIDOS

detectores:
  - nss: false          # apágalo si tu proyecto no toca IMSS

exenciones:
  - archivo: scripts/generar_datos_sinteticos.py
    motivo: es la fuente de la lista; por definición la contiene
    detectores: nombre

  - archivo: docs/EJEMPLOS.md
    motivo: documenta los formatos con los identificadores genéricos oficiales
    detectores: curp, rfc

fallar_en_aviso: false
```

**El motivo es obligatorio.** Una lista de exenciones sin razones se convierte,
en pocos meses, en la lista de archivos que nadie se atreve a tocar porque
nadie recuerda por qué están ahí. Con el motivo escrito, cualquiera puede
evaluar si sigue siendo válido.

Las exenciones se acotan por detector: exentar un archivo de `curp` no debería
exentarlo también de `llave_privada`.

---

## Cómo se ve un hallazgo

```
padron.py
  ✗ línea 12  nombre  Juanito
      Es el nombre de una persona real de este proyecto. Un nombre junto a un
      dato —un adeudo, un domicilio, un expediente— convierte un archivo
      técnico en un registro personal, y el historial de git no olvida.
      → Escríbelo por rol o por identificador: «la Administración» en vez del
        nombre, «lote 47» en vez de quién vive ahí. Si de verdad debe estar
        (un acta pública, un cargo oficial), exenta ESE archivo con su motivo.
```

Cada hallazgo trae **qué**, **por qué importa** y **cómo se arregla**. Un
mensaje que solo dice «patrón prohibido en la línea 47» obliga a investigar
las tres cosas; al tercero, alguien propone desactivar el paso «mientras
tanto».

**Nunca se imprime el valor completo de un secreto.** La salida de una
ejecución de CI suele verla más gente que el propio repositorio y se conserva
más tiempo: volcar ahí la credencial la filtra otra vez, en un lugar donde
nadie la busca.

---

## Qué NO hace, a propósito

- **No arregla automáticamente.** Borrar un dato personal sin que un humano
  vea el contexto es cómo se pierde información legítima. Y el dato ya está en
  el historial: el arreglo real casi nunca es editar la línea.
- **No revisa archivos ignorados por git.** El daño empieza al publicar.
- **No compite con `gitleaks` ni `trufflehog`.** Ellos hacen secretos mejor y
  con más catálogo. Úsalos, y usa Garita para lo que ellos no ven: los nombres
  de *tu* padrón y los identificadores mexicanos.
- **No manda nada a ningún servidor.** Todo corre local.
- **No detecta identificación por agregación.** Garita busca lo que le
  declaras y lo que tiene forma reconocible. No ve que «un condominio de 58
  unidades en tal municipio» identifica un lugar concreto aunque no aparezca
  ningún nombre. Eso lo tiene que ver una persona — y conviene revisar con
  ese lente los README y los comentarios, que es donde el contexto se cuela.
  *(Lo aprendimos publicando este mismo repositorio.)*

---

## Documentación

- [`docs/IDENTIFICADORES.md`](docs/IDENTIFICADORES.md) — los algoritmos, sus
  fuentes oficiales y los vectores de prueba
- [`docs/DISENO.md`](docs/DISENO.md) — por qué cada decisión, incluidas las que
  parecen raras

---

## Créditos

Construido con [Claude Code](https://claude.com/claude-code) (Anthropic) sobre
un problema real. Los algoritmos de CURP, RFC, CLABE y NSS se verificaron
reproduciendo identificadores de muestra publicados por RENAPO, el SAT y el
IMSS; las fuentes están en `docs/IDENTIFICADORES.md`.

MIT. Úsalo, cámbialo, véndelo.

---
---

<a name="english"></a>

# Garita (English)

**Keeps personal data and credentials out of your repository.** Names from
your own records, Mexican national IDs (CURP, RFC, CLABE, NSS), phone numbers
and secrets — as a `pre-commit` hook and as a GitHub Action.

## Why it exists

It came out of administering a condominium. The financial records had to be versioned — it's neighbours' money and someone will audit
it. The resident roster could not be: Mexican privacy law regulates it and git
history doesn't forget.

The rule that emerged sums up the tool:

> **The line is the unit, not the name.**
> You may version unit 47 and what it owes. Never the link between that unit
> and the person living in it.

Nothing existed to enforce it. Microsoft Presidio covers 20+ countries and
**Mexico isn't one**. GitGuardian **explicitly rejects** PII patterns.
GitHub charges for custom patterns, and they're secret patterns anyway — not
name lists. `git-secrets`, the only tool that could ban arbitrary strings, has
been unmaintained since 2019.

## The core idea

A guard that compares against a list written in its own config has a fatal
flaw: **the list is itself personal data**. To keep the roster out of the
repo, you'd have to write the roster into the repo.

The way out: most projects handling real data already have a **synthetic data
generator** for tests and seeds — and it already knows which real names it
must never produce by accident.

```yaml
nombres:
  - scripts/generate_fake_data.py:FORBIDDEN
```

Garita reads it from there **via AST, without executing the file**. One list,
impossible to desynchronise.

## What makes it different

**Mexican national IDs with checksum validation.** A detector that flags any
18-character string as a CURP cries wolf constantly — and a guard that cries
wolf gets ignored. With checksum validation, false positives drop by 90× to
5,000× depending on the identifier.

## Install

```yaml
# .pre-commit-config.yaml — start here
repos:
  - repo: https://github.com/proscar87/garita
    rev: v0.1.0
    hooks:
      - id: garita
```

```yaml
# .github/workflows/garita.yml — the backstop
- uses: actions/checkout@v4
- uses: proscar87/garita@v0.1.0
```

Hook first: if your only check is in CI, by the time it fails the data already
lives in a commit — and the fix goes from "delete a line" to "rewrite history
and notify everyone who cloned".

Config, findings format and design rationale: see the Spanish sections above
and [`docs/DISENO.md`](docs/DISENO.md). Built with
[Claude Code](https://claude.com/claude-code). MIT.
