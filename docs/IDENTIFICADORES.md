# Los identificadores

Cómo se valida cada identificador de los dieciséis países, de dónde salió cada
algoritmo y con qué se comprobó.

Este documento existe porque un detector de datos personales que no puede
justificar sus reglas no es auditable — y una herramienta de seguridad que no
se puede auditar se usa por fe, que es lo contrario de lo que promete.

**Ningún identificador de este documento pertenece a una persona real.** Todos
son claves de muestra publicadas por la autoridad en sus propios instructivos,
o construidos sintéticamente para las pruebas.

La primera parte cubre México — el país de origen, con el detalle completo de
cada algoritmo. La segunda, los otros quince países, cada uno con su estructura,
su validación y su política de refuerzo. Las dos políticas que se repiten
vienen de `_comun.py`: un identificador con UN solo carácter de control exige
**refuerzo** (separadores o la palabra que lo nombre en la línea); uno que
valide únicamente por Luhn o que no tenga verificador exige **contexto
siempre**.

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
lo que el dígito deja pasar.

El catálogo está incrustado en `mx.py` (`_BANCOS`), cotejado contra el
catálogo de instituciones de Banxico (agosto 2026): los códigos vigentes —
incluidas las IFPEs como Mercado Pago (722), Cuenca (723) y Spin (728), que
emiten buena parte de las CLABEs modernas — más los históricos de bancos
fusionados, porque una CLABE vieja en un respaldo viejo sigue siendo la
cuenta de alguien.

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

## Argentina — CUIT/CUIL

11 dígitos: prefijo (2) + base (8) + verificador módulo 11 con pesos
`5-4-3-2-7-6-5-4-3-2`. Un verificador de 10 no se emite: la AFIP reasigna el
prefijo a 23, así que aquí se rechaza.

El DNI argentino no tiene dígito verificador —siete u ocho dígitos
consecutivos— y por eso no hay detector propio. El atajo es mejor: **el CUIT
de una persona física (prefijos 20, 23, 24, 25, 26, 27) CONTIENE su DNI en
las posiciones 3 a 10**, y ése sí valida. Los prefijos 30, 33 y 34 son de
personas jurídicas. Refuerzo: separadores o contexto (`cuit`, `cuil`,
`afip`, `arca`, `dni`…).

## Brasil — CPF y CNPJ

**CPF**: 11 dígitos con doble verificador módulo 11. La trampa clásica: los
once CPF de dígito repetido (`000.000.000-00` a `999.999.999-99`) **pasan el
algoritmo** — van en lista negra, junto con los secuenciales
(`123.456.789-09`, `012.345.678-90`) que son el marcador de medio mundo.
Refuerzo a pesar del doble dígito: ~1 de cada 100 números de once dígitos lo
pasa por azar.

**CNPJ**: alfanumérico desde julio de 2026 (Nota Técnica Conjunta 2025.001
de la Receita Federal): doce posiciones que admiten letras + dos dígitos
verificadores; cada carácter vale su ASCII menos 48. Si trae letras se exige
la puntuación oficial — catorce alfanuméricos sueltos son un trozo de hash.
El ejemplo oficial del manual (`12.ABC.345/01DE-35`) está exento.

## Canadá — SIN

9 dígitos que validan por Luhn. El primer dígito codifica la región: 0 y 8
no se asignan (se rechazan); el 9 es de residentes temporales y es válido.

Contexto **siempre**, y las siglas son sensibles a mayúsculas: «sin» es la
preposición más común del español, así que `SIN`/`NAS` cuentan solo en
mayúsculas (o las formas largas «social insurance»/«assurance sociale»).
Exento `123 456 782`, el número de prueba de la documentación; el ejemplo de
la CRA (`046 454 286`) ni exención necesita — empieza en 0 y el validador ya
lo rechaza, que es justo por lo que la CRA lo eligió.

## Chile — RUT/RUN

7 u 8 dígitos + verificador módulo 11 (residuo 10 → `K`). Mismo tropiezo que
el CPF: **todo RUT de dígito repetido valida** (`11.111.111-1` …
`99.999.999-9`) — lista negra, junto con los genéricos del SII para
extranjeros sin domicilio (`44.444.446-0`, `44.444.447-9`). Refuerzo.

## Colombia — NIT

La cédula de ciudadanía **no tiene** dígito verificador (es un consecutivo
de la Registraduría), así que no hay detector de cédula: sería puro ruido.
El «DV» que a veces la acompaña es el de la DIAN, de cuando la cédula opera
como NIT.

El NIT valida con el dígito de la DIAN: pesos primos `3,7,13,17,19,23,29,37…`
sobre la base invertida, módulo 11. Base de 8 **o** 9 dígitos — las cédulas
antiguas, hoy NIT de persona natural, tienen ocho. Refuerzo: en Colombia los
celulares y las cédulas nuevas también son de diez dígitos.

## Ecuador — cédula de identidad

10 dígitos: provincia (01–24, y 30 para inscripciones en el exterior) +
tercer dígito menor a 6 (personas naturales) + verificador módulo 10 del
Registro Civil (coeficientes `2-1-2-1…`, restando 9 a los productos de dos
cifras). Contexto **siempre**: diez dígitos pelones también son un teléfono.
Las repetidas que pasan el módulo están exentas.

## España — DNI, NIE, CIF e IBAN

**DNI**: 8 dígitos + letra de control — el número módulo 23 indexa la tabla
`TRWAGMYFPDXBNJZSQVHLCKE`. **NIE**: igual, con prefijo X/Y/Z que vale 0/1/2
antepuesto. Una sola letra (1/23) → ambos exigen refuerzo. Exentos los
ejemplos oficiales `12345678Z`, `00000000T` y `99999999R` (el NIF de los
certificados de prueba de la FNMT).

**CIF**: letra de organización + 7 dígitos + control. La suma es tipo Luhn
sobre los siete dígitos; la Orden EHA/451/2008 fija que `K P Q R S N W`
exigen control alfabético (`JABCDEFGHI`), `A B E H` numérico, y el resto
admite ambos — esa doble puerta deja pasar ~7%, por eso refuerzo. Admite
separadores («B-12345678» es la forma común por escrito).

**IBAN**: el detector más limpio de la herramienta — valida el módulo 97 del
IBAN **y** los dos dígitos de control internos del CCC que envuelve. Tasa de
falsos positivos 0.0095%; es el único que no necesita refuerzo ni contexto.

## Estados Unidos — SSN e ITIN

El único identificador **sin dígito verificador**: desde 2011 la SSA asigna
las áreas al azar y no hay geografía que validar. Lo verificable es la
estructura que la propia SSA documenta como inválida: área `000`/`666`,
grupo `00`, serie `0000`. El área `9xx` no es un SSN pero **sí puede ser un
ITIN** — el IRS los asigna con el grupo en rangos fijos (50–65, 70–88,
90–92, 94–99); fuera de ellos no es nada.

Sin verificador → contexto **siempre** (`ssn`, `social security`, `itin`):
tres-dos-cuatro con guiones también es un número de parte. Exentos los dos
SSN más publicados de la historia — `078-05-1120` (la cartera de Woolworth,
1938) y `219-09-9999` (el anuncio de la SSA) — más los rellenos de siempre.

## Guatemala — NIT

Base de hasta 8 dígitos + control: pesos descendentes desde la izquierda
(n+1 … 2), módulo 11, y el residuo 10 se escribe **K**. Es el algoritmo que
la SAT documenta para la factura electrónica (FEL); el vector de todo
instructivo (`3602978-5`) reproduce. Contexto **siempre**: la forma también
es un rango o un folio. Y «sat» no cuenta como contexto — en un repositorio
es sábado o el SAT mexicano; `nit`, `fel`, `factura` sí.

El CUI del DPI queda fuera **a propósito**: el RENAP no publica el algoritmo
de su verificador y la regla de la casa exige fuente.

## Paraguay — RUC

El RUC de una persona física ES su cédula más el dígito verificador
(`1946520-3`); el de una jurídica arranca en 80 (`80009735-1`). El algoritmo
lo distribuye la propia SET (hoy DNIT) como código fuente: pesos 2, 3, 4…
de derecha a izquierda, módulo 11; residuo 0 o 1 → verificador 0. Los dos
ejemplos de la documentación oficial reproducen y están exentos.

Contexto **siempre** («dígitos-guion-dígito» también es un rango de páginas)
y la sigla vieja de la autoridad no cuenta: «set» es palabra común del
inglés — la lección de «SIN» y de «ci». La cédula pelona, sin verificador a
la vista, no tiene detector propio: el RUC la cubre.

## Perú — RUC

El DNI peruano queda fuera **a propósito**: RENIEC confirma que el carácter
verificador de la tarjeta es módulo 11 pero no publica el algoritmo, y en
texto el DNI casi siempre aparece como ocho dígitos pelados, sin nada que
validar. El atajo es el argentino: **un RUC de tipo 10 contiene el DNI** de
la persona en las posiciones 3 a 10, y el RUC sí valida.

RUC: 11 dígitos, prefijos `10/15/16/17/20`, módulo 11 con pesos
`5-4-3-2-7-6-5-4-3-2` y ajuste final módulo 10. Refuerzo.

## Portugal — NIF

9 dígitos, módulo 11 sobre los primeros ocho. El primer dígito dice qué es:
1, 2 y 3 personas singulares; 5, 6, 8 y 9 entidades; 0 y 4 no se asignan.
Contexto **siempre**: su formato por grupos de tres es idéntico a media
plantilla de HTML — un «slice» de tres centenas en una plantilla de hugo
validaba completo. Exento `123 456 789`, que pasa el módulo y es el marcador
de todos los formularios portugueses.

## República Dominicana — cédula

11 dígitos que validan por el Luhn de la JCE; se escribe `001-1234567-8`.
Luhn solo → contexto **siempre**, la misma regla que el NSS mexicano y el
SIN canadiense. Las repetidas que pasan Luhn están exentas.

## Uruguay — cédula de identidad

7 dígitos + verificador módulo 10 con coeficientes `2-9-8-7-6-3-4`; se
escribe `1.234.567-8`. Un solo dígito → refuerzo. Y una lección de
repositorio: «ci» pelona **no** cuenta como contexto — en software, CI es
integración continua y una fecha `AAAAMMDD` pasa el módulo una de cada diez
veces; «c.i.» con puntos sí, porque así la abrevian los documentos. Exentos
`1.234.567-2` (el ejemplo de los instructivos) y los repetidos que validan.

## Venezuela — RIF

Letra + 8 dígitos + verificador. La letra vale V=1, E=2, J=3, P=4, G=5 y se
multiplica por 4; los dígitos, por `3-2-7-6-5-4-3-2`; módulo 11, y si 11
menos el residuo pasa de 9, el verificador es 0. El SENIAT no publica la
fórmula — la misma situación que el CURP — así que se usa el estándar de la
industria comprobado contra RIF públicos de entidades: el del propio SENIAT
(`G-20000303-0`) y el de PDVSA (`J-00123072-6`) reproducen.

**El RIF de V o E contiene la cédula** de la persona en sus ocho dígitos —
el mismo atajo que el CUIT argentino y el RUC peruano, porque la cédula
venezolana no tiene verificador propio. Refuerzo; los repetidos que validan
(`J-00000000-0`) están exentos.

## Los que quedan fuera, y por qué

- **Bolivia**: el NIT no tiene un algoritmo de verificación publicado de
  forma verificable; la cédula no trae verificador.
- **Costa Rica**: ni la cédula física ni la jurídica llevan dígito
  verificador — no hay nada que validar, solo forma, y la forma sola es
  ruido.
- **Panamá**: la cédula no trae verificador; el RUC sí, pero el algoritmo de
  la DGI es una rutina heredada sin especificación publicada que se pueda
  reproducir contra vectores oficiales.

Los tres seguirán fuera hasta que exista fuente verificable: un detector
aproximado es peor que ninguno.

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
- CUIT/CUIL y su verificador — AFIP/ARCA (Argentina).
- CPF (módulo 11 doble) — Receita Federal; CNPJ alfanumérico — Nota Técnica
  Conjunta COCAD/SUARA/RFB 2025.001 (Brasil).
- SIN y su validación Luhn — ESDC/CRA (Canadá).
- RUT y dígito verificador — SII (Chile); genéricos de la Resolución sobre
  RUT de extranjeros sin domicilio.
- Dígito de verificación del NIT — DIAN, Orden administrativa de RUT
  (Colombia).
- Cédula de identidad y su módulo 10 — Registro Civil (Ecuador).
- DNI/NIE (letra módulo 23) — Ministerio del Interior; CIF — Orden
  EHA/451/2008; IBAN/CCC — Banco de España.
- Estructura del SSN (áreas/grupos/series inválidos) — SSA; rangos de grupo
  del ITIN — IRS (Estados Unidos).
- RUC y su verificador — SUNAT (Perú). El DNI queda fuera porque RENIEC no
  publica su algoritmo.
- NIF y su módulo 11 — Autoridade Tributária e Aduaneira (Portugal).
- Cédula de identidad y electoral (Luhn) — JCE (República Dominicana).
- Cédula de identidad y su verificador — DNIC (Uruguay).
- Dígito verificador del NIT — SAT, especificación de la factura
  electrónica FEL (Guatemala).
- Dígito verificador del RUC — código fuente distribuido por la SET/DNIT
  (Paraguay); reproducido contra los ejemplos de su documentación.
- RIF — estándar de la industria (el SENIAT no publica la fórmula),
  comprobado reproduciendo los RIF públicos del SENIAT y de PDVSA
  (Venezuela).

Cada algoritmo se comprobó **reproduciendo** el dígito de los identificadores
de muestra listados arriba. El del CURP merece una nota: el instructivo
vigente dice que la posición 18 se calcula «mediante algoritmo» pero **no
publica la fórmula**; la que se usa aquí es el estándar de la industria y
reproduce correctamente las tres claves de muestra oficiales.
