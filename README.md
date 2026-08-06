# Garita

**Impide que datos personales y credenciales entren a tu repositorio.**
Nombres de tu propio padrón, CURP, RFC, CLABE, NSS, teléfonos mexicanos y
secretos — como hook de `pre-commit` y como GitHub Action.

[![CI](https://github.com/proscar87/garita/actions/workflows/ci.yml/badge.svg)](https://github.com/proscar87/garita/actions/workflows/ci.yml)
[![MIT](https://img.shields.io/badge/licencia-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-%E2%89%A53.9-blue)
![Sin dependencias](https://img.shields.io/badge/dependencias-0-green)

[English below](#english)

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
| `cliente` | Nombres, dominios o seriales de **tus clientes** | Misma mecánica de lista única que `nombre` |
| `curp` | CURP | **Dígito verificador** + fecha + catálogo de entidades |
| `rfc` | RFC | **Dígito verificador** (módulo 11) + fecha |
| `clabe` | CLABE interbancaria | **Dígito de control** (3-7-1, módulo 10) |
| `nss` | NSS del IMSS | **Luhn** + exige contexto léxico en la línea |
| `telefono` | Teléfono mexicano de 10 dígitos | **Lada asignada en el PNN del IFT** + prefijo, separadores o contexto |
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

**La misma idea aplica a clientes.** Un repo de consultoría —casos de
estudio, análisis, entregables— tiene la regla inversa del padrón: el
*sector* se documenta, el *cliente* jamás. La lista `clientes:` acepta lo
que lo identifique (nombre, dominio, serial de su appliance) y el detector
`cliente` lo bloquea donde aparezca, con su mensaje: usa el alias por
sector. Nació de un caso real: un case study que nombraba al cliente en un
repo cuya propia convención era el alias.

El prefijo **`?`** marca la fuente como **opcional**: si el archivo no está
en la máquina, Garita avisa por stderr y sigue sin ese detector, en vez de
tronar. Existe para la lista que debe vivir **gitignoreada**: escribir los
nombres de tus clientes en el propio repo re-filtraría exactamente lo que
quieres bloquear. Opcional tolera la ausencia, jamás la corrupción: un
archivo presente y roto truena igual que siempre.

---

## ¿Tu país no está?

Los identificadores oficiales viven en `detectores/paises/`, **un archivo por
país**. Hoy son dieciséis:

| País | Identificadores | Validación |
|---|---|---|
| 🇲🇽 México | CURP, RFC, CLABE, NSS, teléfono | dígito verificador + lada del PNN |
| 🇦🇷 Argentina | CUIT/CUIL (contiene el DNI) | módulo 11 |
| 🇧🇷 Brasil | CPF, CNPJ (alfanumérico 2026) | doble dígito verificador |
| 🇨🇱 Chile | RUT/RUN | módulo 11 |
| 🇨🇴 Colombia | NIT | dígito de la DIAN |
| 🇪🇸 España | DNI, NIE, CIF, IBAN | letra de control / módulo 97 |
| 🇵🇪 Perú | RUC | dígito verificador |
| 🇺🇸 EE.UU. | SSN | estructura SSA + contexto obligatorio |
| 🇨🇦 Canadá | SIN | Luhn + contexto |
| 🇵🇹 Portugal | NIF | módulo 11 + contexto |
| 🇺🇾 Uruguay | Cédula de identidad | dígito verificador |
| 🇪🇨 Ecuador | Cédula de identidad | módulo 10 del Registro Civil + contexto |
| 🇩🇴 Rep. Dominicana | Cédula (JCE) | Luhn + contexto |
| 🇻🇪 Venezuela | RIF (contiene la cédula) | módulo 11 |
| 🇵🇾 Paraguay | RUC (es la cédula + dígito) | módulo 11 de la SET + contexto |
| 🇬🇹 Guatemala | NIT | módulo 11 de la SAT (FEL) + contexto |

Agregar otro es un archivo, no una rama — comparten motor, exenciones y
pruebas, así que un arreglo llega a todos el mismo día.

```yaml
paises: mx, co     # por omisión: todos los disponibles
```

Tenerlos todos encendidos casi no cuesta: un identificador con dígito
verificador no valida fuera de su país, así que no dispara.

**[`docs/AGREGAR_PAIS.md`](docs/AGREGAR_PAIS.md) explica cómo agregar el
tuyo.** La única regla dura: sólo se acepta un identificador si su validación
se puede verificar contra una fuente oficial. Un detector que sólo mira la
forma produce ruido, y el ruido es lo que enseña a la gente a ignorar al
guardián.

---

## Instalación

### Como hook de pre-commit — **empieza por aquí**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/proscar87/garita
    rev: v0.21.0
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
      - uses: proscar87/garita@v0
```

Es lo que nadie puede saltarse con `--no-verify`. Las dos capas se
complementan; ninguna sustituye a la otra.

| Entrada | Por omisión | Qué hace |
|---|---|---|
| `config` | `.garita.yml` | Ruta del archivo de configuración |
| `solo-cambios` | `false` | Revisar sólo los archivos del pull request. Más rápido, **pero ciego a lo que ya estaba**: úsalo junto a una revisión completa programada, no en su lugar |

| Salida | Qué trae |
|---|---|
| `hallazgos` | Número de hallazgos |

Probada en `ubuntu-latest` y `macos-latest`. En runners de Windows agrega
`actions/setup-python@v5` antes: `python3` no siempre existe ahí.

#### Con alertas en la pestaña Security (SARIF)

Un hallazgo impreso en el registro de la corrida muere ahí: casi nadie abre
los registros. Con `--formato sarif`, GitHub lo convierte en una alerta de
code scanning — con historial y estado propio por hallazgo:

```yaml
jobs:
  revisar:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - run: |
          pip install garita
          garita --formato sarif --salida garita.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: garita.sarif
```

El documento SARIF respeta las mismas dos reglas que todo lo demás: ningún
valor completo en los mensajes, y nada derivado del valor en las huellas que
GitHub usa para seguir un hallazgo entre corridas. La deuda aceptada por la
línea base aparece como `note`, no como error.

## El reporte gráfico (`--formato html`)

```bash
garita --formato html --salida reporte.html              # revisión normal
garita --historial --formato html --salida auditoria.html  # el entregable
```

Un HTML **autocontenido** — cifras, gráficas por detector y tabla de
hallazgos — para el tercero que también existe: el cliente, el auditor, el
consejo. Se abre con doble clic, se imprime y se anexa a un informe.

- **Cero peticiones externas**: ni fuentes, ni scripts, ni CSS de un CDN. Un
  reporte de seguridad que llama a terceros al abrirse les filtra cuándo y
  dónde se lee. Las gráficas son CSS puro.
- **Ningún valor completo**, igual que la consola y el SARIF.
- La severidad nunca es sólo color: cada error lleva su ✗ y cada aviso su
  `!` — el color no le habla al daltonismo ni a la impresora.
- En la auditoría de historial separa lo vivo de lo que está sólo en el
  pasado, con su guía de rotación en orden.

---

## El historial también cuenta

```bash
garita --historial
```

Revisa **todas las versiones de todos los archivos** que han pasado por el
repositorio — no sólo las actuales. El caso que duele: el secreto commiteado
hace tres meses y «borrado» al día siguiente. La revisión normal no lo ve;
el historial sí, porque git no olvida: el dato vive en cada clon y cada fork.

El reporte separa lo que **sigue en el árbol** (se arregla como siempre) de
lo que está **sólo en el historial** — ahí borrar el archivo no borró nada:
si es una credencial se rota HOY, y limpiar el historial (`git-filter-repo`)
es una decisión humana que Garita no toma ni automatiza jamás.

Detalles a saber:

- Recorre **blobs únicos**, no commits: cada versión de cada archivo se
  revisa una sola vez, y la misma cadena a través de N versiones se reporta
  como UN hallazgo con su commit de origen. En un repo mediano (~6,000
  commits) tarda uno o dos minutos.
- Aplica **las mismas reglas** que la revisión normal: mismos detectores,
  mismas exenciones (a la ruta histórica), mismos filtros. Dos motores con
  reglas distintas darían dos verdades distintas.
- **La línea base no aplica**: congela el presente, y una auditoría del
  pasado que perdona no es una auditoría.

Y como capa permanente, la **auditoría mensual con alertas en Security**:

```yaml
# .github/workflows/garita-historial.yml
name: Garita — auditoría de historial
on:
  schedule:
    - cron: "0 8 1 * *"   # día 1 de cada mes
  workflow_dispatch:

jobs:
  auditar:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # sin historia completa no hay auditoría
      - run: |
          pip install garita
          garita --historial --formato sarif --salida historial.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: historial.sarif
```

Las alertas del historial apuntan a la ruta del commit que introdujo el
dato — que puede ya no existir en el árbol, y está bien: el mensaje carga
el commit, la fecha y si el archivo «se borró» (el dato no). La huella es
`commit + ruta + regla`: el historial es inmutable, así que identifica al
hallazgo para siempre sin derivar nada del valor.

---

### Como comando

```bash
pip install garita
garita              # revisa el repositorio
garita --explicar   # dice qué va a revisar y con qué configuración
```

---

## ¿Tienes un repositorio con hallazgos previos? Así lo enciendes hoy

El caso más común no es el repositorio nuevo: es el que lleva años acumulando.
Enciendes Garita, salen cuarenta hallazgos, el build queda rojo y no puedes
arreglarlos hoy. Sin ayuda, las salidas son escribir cuarenta exenciones a
mano o apagar la herramienta — y casi siempre se apaga la herramienta.

Para eso existe la línea base:

```bash
garita --linea-base   # congela lo que ya estaba; escribe .garita-base.json
git add .garita-base.json && git commit -m "Enciende Garita con línea base"
```

A partir de ahí **CI falla sólo con lo nuevo**. La deuda vieja no desaparece
del reporte: se imprime aparte, en gris, como deuda aceptada — con la fecha en
que la aceptaste, porque una línea base es una promesa de limpiar después y
las promesas sin fecha no se cumplen.

Tres cosas que conviene saber:

- **El archivo no contiene ningún dato.** Sólo cuántos hallazgos había por
  archivo y detector. Ni valores ni hashes: un hash de CURP se revienta por
  fuerza bruta, así que no se guarda ningún derivado del valor. Puedes
  commitearlo tranquilo.
- **La deuda se paga borrando.** Cuando limpies un archivo, Garita te avisa
  que esa entrada quedó obsoleta; regenera con `garita --linea-base` para
  achicar el archivo. La meta es que un día puedas borrarlo completo.
- **Para auditar de verdad**, `garita --sin-linea-base` ignora el archivo y
  reporta todo, incluido lo aceptado.

---

## Configuración

Todo es opcional salvo la lista de nombres. Sin `.garita.yml`, Garita revisa
identificadores y secretos —que no necesitan saber nada de tu proyecto— y
apaga el detector de nombres avisándolo.

```yaml
# .garita.yml

nombres:
  - scripts/generar_datos_sinteticos.py:PROHIBIDOS

clientes:
  - '?clientes.txt'     # nombres, dominios o seriales — uno por línea

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

**El `archivo` casa como en `.gitignore`.** Un patrón **sin barra** casa el
nombre a cualquier profundidad (`*.test.ts` cubre
`src/lib/ids.test.ts`); uno **con barra** casa la ruta por segmentos, donde
`*` no cruza las barras y `**` sí. Para una carpeta entera se escribe
`tests/**` — `tests*` no casa nada y sale reportado como exención que no
aplicó, en vez de tragarse en silencio `tests_reales/` y todo lo que empiece
igual.

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

MIT © 2026 Oscar Pacheco ([proscar87](https://github.com/proscar87)).
Úsalo, cámbialo, véndelo.

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
    rev: v0.21.0
    hooks:
      - id: garita
```

```yaml
# .github/workflows/garita.yml — the backstop
- uses: actions/checkout@v4
- uses: proscar87/garita@v0
```

Hook first: if your only check is in CI, by the time it fails the data already
lives in a commit — and the fix goes from "delete a line" to "rewrite history
and notify everyone who cloned".

**Existing repo with prior findings?** Run `garita --linea-base` to freeze
them as accepted debt: CI then fails only on *new* findings, while old ones
stay visible in the report. The baseline file stores only counts per file and
detector — no values, no hashes — so it's safe to commit.

**And the past counts too:** `garita --historial` audits every version of
every file that ever passed through the repo — the secret committed three
months ago and "deleted" the next day is invisible to a normal scan, but git
never forgets. The report separates what's still in the tree from what lives
only in history, where the fix is rotating the credential — never a silent
history rewrite.

Config, findings format and design rationale: see the Spanish sections above
and [`docs/DISENO.md`](docs/DISENO.md). Built with
[Claude Code](https://claude.com/claude-code). MIT.
