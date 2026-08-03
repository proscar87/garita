# Los identificadores mexicanos

Cómo se validan, de dónde salió cada algoritmo y con qué se comprobó.

Este documento existe porque un detector de datos personales que no puede
justificar sus reglas no es auditable — y una herramienta de seguridad que no
se puede auditar se usa por fe, que es lo contrario de lo que promete.

**Ningún identificador de este documento pertenece a una persona real.** Todos
son claves de muestra publicadas por la autoridad en sus propios instructivos,
o construidos sintéticamente para las pruebas.

---

## CURP

18 caracteres. Identifica de forma única a una persona en México y contiene su
fecha de nacimiento, su sexo y su entidad de nacimiento.

### Estructura

| Posición | Contenido |
|---|---|
| 1 | Inicial del primer apellido |
| 2 | Primera vocal **interna** del primer apellido |
| 3 | Inicial del segundo apellido (`X` si no hay) |
| 4 | Inicial del nombre |
| 5–10 | Fecha de nacimiento `AAMMDD` |
| 11 | Sexo: `H` / `M` |
| 12–13 | Entidad de nacimiento (catálogo de 2 letras) |
| 14–16 | Primera consonante interna de apellido 1, apellido 2 y nombre |
| 17 | Diferenciador de homonimia: **dígito** si nació ≤ 1999, **letra** si ≥ 2000 |
| 18 | **Dígito verificador** |

### Dígito verificador

```python
ALFABETO = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"   # la Ñ vale 24

def digito(curp17: str) -> str:
    suma = sum(ALFABETO.index(c) * (18 - i) for i, c in enumerate(curp17))
    return str((10 - suma % 10) % 10)
```

El alfabeto **no es corrido**: incluye la `Ñ` en la posición 24, entre la `N`
y la `O`. Usar el alfabeto latino normal produce dígitos incorrectos para
cualquier clave que contenga letras posteriores a la N.

### Vectores

| Clave | Válida | Nota |
|---|---|---|
| `HEGG560427MVZRRL04` | sí | Muestra histórica de RENAPO |
| `SASO750909HDFNNS05` | sí | Constancia modelo del instructivo vigente |
| `ZUNA540308MNELTN05` | sí | Constancia modelo, nacido en el extranjero |
| `HEGG560427MVZRRL03` | no | Dígito mutado |
| `SABC560626MDFLRN09` | **no** | Diagrama ilustrativo del DOF: su dígito es **decorativo** |
| `ABCD123456HDFEFG00` | no | Marcador de la constancia temporal |

Las tres válidas están en `CURP_DE_MUESTRA` y no se marcan: aparecen en
documentación pública y marcarlas produciría falsos positivos en cualquier
manual que las cite.

### Dos cosas que confunden

**La `X` en la posición 2 es legítima.** Cuando las primeras cuatro letras
forman una de las 81 palabras inconvenientes del Anexo 2 (`BUEI`, `KACA`,
`PUTO`…), RENAPO sustituye la segunda letra por `X`. No es un error ni un dato
anonimizado.

**`DF` sigue vigente** para quien nació en la Ciudad de México antes del
cambio de nombre. El catálogo no se actualizó retroactivamente.

### Falsos positivos

Sobre cadenas de 18 caracteres alfanuméricos que pasan la forma general:
fecha válida deja pasar ~3.7%, catálogo de entidad ~4.9%, dígito ~10%.
Combinado, sobrevive **~1 de cada 5,500**.

---

## RFC

12 caracteres para persona moral, 13 para persona física.

### Dígito verificador (módulo 11)

```python
VALOR = {c: v for v, c in enumerate("0123456789ABCDEFGHIJKLMN&OPQRSTUVWXYZ")}
VALOR[" "] = 37
VALOR["Ñ"] = 38

def digito(rfc_sin_dv: str) -> str:
    s = rfc_sin_dv.rjust(12)          # persona moral: espacio al frente
    suma = sum(VALOR[c] * (13 - i) for i, c in enumerate(s))
    d = 11 - (suma % 11)
    return "0" if d == 11 else "A" if d == 10 else str(d)
```

Tres detalles que se equivocan seguido:

1. **El `&` vale 24 y va entre la `N` y la `O`.** No es alfabeto corrido.
2. **A las personas morales se les antepone un espacio**, que vale 37 y entra
   a la suma con peso 13. Omitirlo da un dígito incorrecto para todas.
3. **`11 → "0"` y `10 → "A"`**, en ese orden. Hay documentación secundaria que
   lo invierte.

### Vectores

| RFC | Válido | Nota |
|---|---|---|
| `GODE561231GR8` | sí | Ejemplo canónico del SAT |
| `CACX7605101P8` | sí | RFC de pruebas del SAT, común en documentación de CFDI |
| `XEXX010101000` | **sí** | Genérico de extranjeros — **pasa el módulo 11** |
| `XAXX010101000` | **no** | Genérico nacional — **no pasa** |
| `GODE561231GR7` | no | Dígito mutado |

Los dos genéricos y el de pruebas están en `RFC_GENERICOS`. `XEXX010101000`
**necesita la lista blanca** porque valida; `XAXX010101000` se descartaría
solo, pero se incluye para que el comportamiento no dependa de esa casualidad.

---

## CLABE

18 dígitos: banco (3) + plaza (3) + cuenta (11) + control (1).

```python
def digito(clabe17: str) -> str:
    pesos = [3, 7, 1] * 6
    suma = sum((int(d) * pesos[i]) % 10 for i, d in enumerate(clabe17))
    return str((10 - suma % 10) % 10)
```

El `% 10` va sobre **cada producto**, tal como está en la norma. (El resultado
final coincide si se omite, pero la implementación literal evita discusiones
al compararla con otra.)

| CLABE | Válida |
|---|---|
| `032180000118359719` | sí — ejemplo publicado |
| `032180000118359710` | no — dígito mutado |

Se exentan las cuentas con los 11 dígitos en ceros o nueves: son marcadores de
documentación, no cuentas.

### Por qué importa el catálogo de bancos

Los identificadores tipo *snowflake* de Discord y X tienen 18–19 dígitos y
matchean la forma. Rara vez empiezan con un código de banco válido, así que
validar los primeros tres dígitos contra el catálogo de la ABM corta casi todo
lo que el dígito deja pasar. *(Pendiente: incrustar el catálogo.)*

---

## NSS

11 dígitos: subdelegación (2) + año de alta (2) + año de nacimiento (2) +
folio (4) + verificador (1). El dígito se calcula con **Luhn**.

```python
def digito(nss10: str) -> str:
    suma = 0
    for i, d in enumerate(nss10):
        n = int(d) * (1 if i % 2 == 0 else 2)
        suma += n - 9 if n > 9 else n
    return str((10 - suma % 10) % 10)
```

| NSS | Válido |
|---|---|
| `92988084494` | sí — ejemplo documentado |
| `92988084495` | no — dígito mutado |
| `29988084494` | no — transposición de los dos primeros |

**Es el único detector que exige contexto.** Luhn corta el 90%, y once dígitos
también son un folio, un teléfono con lada internacional o una CLABE truncada.
Sin exigir que la línea mencione `NSS`, `IMSS`, `seguro social` o `afiliación`,
este detector solo sería ruido — y el ruido es lo que enseña a la gente a
ignorar al guardián.

---

## Teléfono

Sin dígito verificador. Desde el **3 de agosto de 2019** todos los números
nacionales son de diez dígitos y los prefijos `01`, `044` y `045`
desaparecieron.

- Ladas de **2 dígitos**: `55`, `56` (Valle de México), `33` (Guadalajara),
  `81` (Monterrey), seguidas de 8 dígitos.
- El resto del país usa lada de **3 dígitos** + 7. Ninguna empieza con `0`
  ni `1`.
- **El prefijo `521` sigue vivo** aunque ya no se marque: los exports de
  WhatsApp lo usan en los identificadores de contacto. Y un chat exportado es
  justo el tipo de archivo que alguien versiona sin pensarlo.

Se marca como **error** si hay prefijo internacional o contexto léxico
(`tel`, `cel`, `WhatsApp`, `contacto`); como **aviso** si sólo hay
separadores; y **no se marca** si son diez dígitos pegados sin nada más,
porque a esa altura es indistinguible de una marca de tiempo Unix o un folio.

---

## Fuentes

- Instructivo Normativo para la Asignación de la CURP — SEGOB/RENAPO,
  DOF 18-jun-2018, última reforma DOF 18-oct-2021. Anexo 2 (palabras
  inconvenientes) y Anexo 4 (catálogo de entidades).
- Tabla de valores para la generación del código verificador del RFC — Anexo
  del SAT, reproducido por integradores autorizados de facturación.
- Estructura y dígito de control de la CLABE — norma de Banxico/ABM.
- Conformación del NSS y su dígito verificador — documentación del IMSS.
- Marcación a 10 dígitos — IFT, Plan Técnico Fundamental de Numeración,
  DOF 17-jul-2019.

Cada algoritmo se comprobó **reproduciendo** el dígito de los identificadores
de muestra listados arriba. El del CURP merece una nota: el instructivo
vigente dice que la posición 18 se calcula «mediante algoritmo» pero **no
publica la fórmula**; la que se usa aquí es el estándar de la industria y
reproduce correctamente las tres claves de muestra oficiales.
