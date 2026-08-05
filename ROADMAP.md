# Hoja de ruta

Este documento sale de la **tercera oleada** de agentes sobre el propio código
(2026-08-05, después de cerrar las dos anteriores). Los frentes fueron: los
arreglos del mismo día (v0.13.0–v0.16.0, *que el remedio no sea peor*), y las
superficies que ninguna oleada había mirado con adversario — SARIF y HTML, la
línea base y las exenciones, el núcleo, y la Action con los detectores
veteranos.

Cada hallazgo de la primera sección fue **reproducido de punta a punta** por un
verificador adversarial independiente, con instrucciones de refutar también lo
que resultara ser compromiso deliberado. De diez verificados, diez
sobrevivieron y uno lo hizo a medias (ver `spec/`). Los de la segunda sección
quedaron fuera del cupo: traen receta, pero nadie los ha reproducido con
adversario; **verificar antes de arreglar**.

La regla para priorizar es la de siempre: *un guardián que aprueba todo es peor
que ninguno*. Primero los falsos negativos silenciosos, después los veredictos
que mienten, después la calibración, al final lo cosmético.

Las dos oleadas anteriores quedaron saldadas: la primera en v0.8.0–v0.12.0
(16 países), la segunda en v0.13.0–v0.16.0 (20 de 20 hallazgos reales).

---

## 1. Confirmado y reproducido

### Lo que el motor no leyó

- [x] **UTF-16 sin BOM se descarta como binario: secretos aprobados en
  silencio** — `src/garita/nucleo.py:238`. `descifrar()` solo reconoce UTF-16
  por BOM; sin marca, el archivo está lleno de bytes nulos, cae en `if b"\0"
  in crudo: return None` y se cuenta como «omitido (binarios o muy grandes)»
  sin nombrarse. Una AKIA y una cadena `postgres://` en ese archivo salen con
  0; el mismo contenido con BOM da dos errores. Lo escriben `iconv -t
  UTF-16LE`, `java.io` con ese charset, `.NET UnicodeEncoding(false,…)` y
  `bcp -w` de SQL Server — el exportador de padrones, o sea el escenario
  nuclear de la herramienta. Arreglo verificado: antes de descartar por byte
  nulo, detectar nulos alternados (>70 % en impares y <10 % en pares → utf-16-le,
  y el espejo) y decodificar; rechaza tanto bytes aleatorios como un bloque
  todo-nulos.

- [x] **Latin-1/CP1252 con acentos mata las palabras de contexto** —
  `src/garita/nucleo.py:240`. Todo lo no-BOM se decodifica como UTF-8 con
  `replace`, así que en un archivo Latin-1 «Cédula» se vuelve «C�dula» y
  ningún `_CONTEXTO` con `c[eé]dula` casa. Cada detector `exige_contexto`
  (cedula_ec, cedula_do, NIT gt, RUC py, SSN, SIN ca) queda ciego, y el
  archivo **cuenta como revisado** — peor que omitirlo, porque el resumen
  jura que se miró. Es el default histórico de Excel y de los editores
  Windows en español. Arreglo verificado: UTF-8 estricto y reintento con
  cp1252 solo si falla (idéntico a hoy para UTF-8 válido).

- [x] **`dentro_de_un_numero` silencia todo identificador en una fila CSV** —
  `src/garita/detectores/paises/_comun.py:41,43,46`. Las guardas de borde
  tratan la coma del CSV como prueba de literal numérico: en
  `Juan Perez,55,<CLABE>,1234.50` el hallazgo se descarta con `continue` antes
  de toda otra lógica, y lo mismo le pasa a rut, cpf, cuit y las cédulas —
  todo lo que pasa por `buscador()`. El CSV es *el* formato donde vive el
  padrón. La calibración declarada era para notación científica y tablas de
  constantes, no para separadores de campo. Ojo: arreglar solo los bordes no
  basta — la ventana de la línea 46 cuenta los puntos internos del propio
  identificador (`12.345.678` aporta dos pares) y lo silencia por segunda vía.
  Arreglo verificado (201/201 en verde): coma fuera de los dos bordes, y la
  ventana contada **excluyendo el span de la coincidencia**.

- [x] **`spec|specs` en `RUTAS_DE_PRUEBA` suprime credenciales de contratos
  OpenAPI** — `src/garita/nucleo.py:81`. El directorio `spec/` de un contrato
  OpenAPI o JSON-Schema es un documento que se **escribe**, no un fixture que
  se genera: una URL de conexión real en `spec/openapi.yaml` se suprime a
  `None` —ni aviso— y el repo sale 0. Es el mismo argumento con que v0.8.0
  sacó `examples/` de la supresión. *(Refutado a medias: el verificador
  refutó el otro extremo del hallazgo —que suprimir secretos en `tests/` sea
  un defecto— porque el comentario de `nucleo.py:71-78` y el commit de v0.8.0
  lo documentan como decisión, «un fixture se genera; un ejemplo se
  ESCRIBE».)* Arreglo: quitar `spec|specs` de `RUTAS_DE_PRUEBA` —
  `ARCHIVOS_DE_PRUEBA` ya cubre `foo_spec.rb` y `foo.spec.ts`, y
  `spec/fixtures/` sigue casando por `fixtures?` — o degradarlo a aviso.

### Las vías de callar

- [x] **La línea base perdona por conteo sin mirar la severidad: un aviso
  congelado absuelve un ERROR nuevo** — `src/garita/linea_base.py:104`.
  `filtrar()` perdona hasta N hallazgos por clave `archivo::detector`, sin
  severidad y empezando por la línea más baja. Varios detectores emiten aviso
  o error según contexto (la CLABE dentro de una URL es aviso, a pelo error):
  si la base congeló un aviso y alguien agrega una CLABE desnuda en una línea
  anterior, el **error nuevo** se perdona como deuda aceptada, el aviso viejo
  sale como «nuevo» y con `fallar_en_aviso` apagado —el default— el exit es 0.
  No es el hueco de sustitución que el docstring acepta: ahí el total no
  cambia; aquí pasó de 1 a 2. Arreglo: severidad en la clave del conteo
  (subiendo `FORMATO` a 2, que ya trae mensaje de regenerar); paliativo sin
  romper formato: consumir los perdones ordenando los avisos primero, que
  sesga hacia falso positivo y nunca hacia falso negativo.

- [x] **El `*` de fnmatch cruza «/»: la exención «tests\*» exenta también
  `tests_reales/`** — `src/garita/nucleo.py:271`. `Exencion.cubre` usa
  `fnmatch`, donde `*` casa las barras: un patrón escrito pensando en la
  carpeta `tests/` absorbe `tests_reales/`, `tests_viejos.tar` y todo lo que
  empiece igual — y `tests_reales/` **no** es ruta de prueba para
  `RUTAS_DE_PRUEBA`, así que ahí los hallazgos eran de verdad. La absorción es
  silenciosa: el patrón coincidió, no sale en `exenciones_muertas`, y el
  reporte solo dice «N revisiones omitidas» sin decir de qué archivos.
  Arreglo: casar por segmentos (`PurePath.full_match`, donde «tests\*» ya no
  casa nada y el patrón cae en `exenciones_muertas` — falla ruidosa en vez de
  absorción silenciosa) y listar qué archivos absorbió cada exención. Es
  cambio de semántica: anunciarlo.

- [x] **`solo-cambios` omite los typechange: un symlink reemplazado por
  archivo con secreto pasa con 0** — `scripts/ejecutar.py:31`. El
  `--diff-filter=ACMR` excluye el estado `T`. Si el PR trae además cualquier
  otro cambio (la lista no queda vacía y no cae al escaneo completo), el
  archivo nuevo no se revisa: «nada que reportar», exit 0. El docstring
  justifica la `R` y la exclusión de la `D`, pero nunca menciona la `T`.
  Arreglo verificado: `--diff-filter=ACMRT`, con su línea de porqué y una
  prueba que fije el filtro.

### Los detectores veteranos

- [ ] **El teléfono mexicano no admite la lada entre paréntesis** —
  `src/garita/detectores/paises/mx.py:255`. Ninguna rama de `_TELEFONO`
  acepta `(` o `)`, así que la forma impresa más común del país —la lada entre
  paréntesis, con o sin el +52 delante— no produce ni un aviso, mientras la
  misma línea con guiones sí es error. Es el formato de directorios, firmas de
  correo y volcados de CRM, y ninguna prueba lo cubría. Arreglo verificado:
  `\(?` … `\)?` alrededor de la lada en las dos ramas; el resto del pipeline
  no cambia (los grupos nombrados se conservan y el chequeo `separado` se
  satisface con el espacio tras el paréntesis).

### La regresión de hoy

- [ ] **La frontera camelCase absuelve contraseñas reales
  «MiClave…»/«MiSecreto…»** — `src/garita/detectores/secretos.py:173`. La
  frontera minúscula→Mayúscula que v0.13.0 introdujo para los placeholders
  camelCase, combinada con el marcador `mi[_-]?(clave|llave|secreto)`,
  convierte «MiClave»/«MiSecreto»/«MiLlave» en **prefijo absolutorio**: el
  patrón de contraseña humana más común en español. Una URL de conexión con
  «MiClaveSegura2024» daba error en v0.12.0 y sale limpia en v0.16.0
  (verificado contra worktree). El marcador estaba pensado para valores que
  SON el placeholder entero. Arreglo verificado (201/201 en verde): quitar
  esa alternativa de `MARCADORES` y añadir «llave» a los sustantivos de
  `_ES_TODO_MARCADOR` — los valores-completos legítimos (miClave, mi_secreto,
  MiClave, myPassword) siguen absueltos por el prefijo `(m[iy][\W_]?)?` que
  esa constante ya tiene, y los camel deliberados no se mueven.

---

## 2. Plausible, sin verificar aún

*(Trae receta del buscador; nadie lo ha reproducido con adversario. Ordenado
por severidad alegada.)*

### Veredictos que podrían mentir

- [ ] **`recortar()` vuelca el valor COMPLETO de identificadores de ≤8
  caracteres** — `_comun.py:73`. Su docstring dice «Nunca el valor completo» y
  hace lo contrario: una cédula uruguaya pelona o un RUT chileno de 8 dígitos
  llegan íntegros al `message.text` del SARIF (que la pestaña Security muestra
  a más gente que el repo) y a la tabla del HTML — cuyo pie **jura** que
  ningún valor completo aparece. Arreglo: truncar siempre, como
  `nucleo.recortar()`. El mismo patrón duplicado en `mx.py:285` es rama
  muerta (los ID mexicanos miden ≥10).

- [ ] **`artifactLocation.uri` sin percent-encoding: SARIF inválido** —
  `sarif.py:76` y `:148`. El esquema 2.1.0 define ese campo como
  `uri-reference`: un espacio, comillas o `<>` producen un documento que no
  valida, y un `#` es peor —RFC 3986 lo parte en fragmento y la alerta apunta
  a un artefacto que no existe. «mi archivo.txt» es cotidiano, no
  adversarial. Arreglo: `quote(h.archivo, safe='/')`.

- [x] **`solo-cambios` no des-quota las rutas C-quoted de git: un archivo con
  ñ tumba el PR con exit 2** — `scripts/ejecutar.py:34`. `git diff
  --name-only` cita los nombres no ASCII, la cadena literal llega a la CLI y
  responde «no existe el archivo» con código 2: un PR legítimo de un repo en
  español —el público de la herramienta— falla como error de configuración y
  **ningún** archivo del PR se revisa. La misma clase de bug que v0.15.0 cerró
  en `historial.py`. Arreglo: `git diff -z --name-only` con split por NUL.

- [ ] **La guardia de variable vacía cubre `--salida` pero no `--config` ni
  `--linea-base-ruta`** — `cli.py:111`. `--config ""` (el `$VAR` sin definir de
  CI) cae en `if args.config:` y Garita corre con la configuración por
  omisión, aprobando con 0 — justo lo que la guardia de `--config` inexistente
  declara inaceptable: «correr con otra configuración de la que se pidió es
  peor que no correr».

- [x] **`dentro_de_url` no corta en coma: un ID en campo CSV posterior a una
  URL baja a aviso** — `_comun.py:61`. El token se recorta en espacio, tab y
  comillas, pero no en coma: en `Juan,https://…/juan,<CLABE>` la CLABE es un
  campo propio y el token retrocede hasta incluir la URL, así que el error se
  degrada a aviso y el veredicto es 0. La degradación se justificó para IDs
  *dentro* de la ruta de una URL; en datos raspados —el caso de uso
  declarado— convierte un error real en luz verde.

### Calibración

- [ ] **`_POSESIVO_ES_TODO` con lista de sustantivos marca «TuClaveAqui» como
  error** — `secretos.py:143`. La lista cerrada exige que el valor termine
  justo tras el sustantivo, así que los placeholders con sufijo y sin
  separador («TuClaveAqui», «tuPasswordAqui», el estilo de las plantillas) ya
  no se absuelven, y `MARCADORES` tampoco los salva porque ahí `tu` exige
  separador. Falso positivo en documentación, que es lo que desinstala
  guardianes. Es el reverso de la regresión de la sección 1: cualquier
  arreglo debe cerrar los dos.

- [x] **`detectores:` en forma de lista YAML se convierte con `str()` y la
  exención deja de exentar, en silencio** — `config.py:213`. `str(dets).split(",")`
  asume el escalar; con la forma de lista anidada llega una `list` y la tupla
  queda `("['clabe']",)`, que no casa ningún detector: el archivo exento
  sigue reportándose y tampoco sale en `exenciones_muertas`. Igual con
  `detectores: no` (bool). Arreglo: unir la lista, o rechazar con
  `ConfigInvalida`.

- [ ] **El NSS no exenta rellenos: el todo-ceros pasa Luhn y dispara error** —
  `mx.py:339`. `nss_valido("0"*11)` es True y `_buscar_nss` no tiene lista de
  exentos, a diferencia de sus tres hermanos del mismo archivo (que incluyen
  un `_clabe_es_relleno` hecho justo para ceros y nueves). La lección de
  v0.16.0 sin aplicar al detector veterano.

- [ ] **`_descitar` ignora los escapes `\a \b \v \f` de git** —
  `historial.py:145`. El diccionario conoce `\" \\ \t \n \r`, pero el
  C-quoting de git también emite esos cuatro: la ruta queda con backslash
  literal, distinta de la cruda que da `rev-list`, y el blob recupera su ruta
  fantasma — el bug que `_descitar` dice cerrar. Arreglo: cuatro entradas más.

- [ ] **Un punto final de oración apaga el detector de teléfono** —
  `mx.py:258`. El lookahead `(?![\d.])` protege de decimales pero también
  rechaza el punto que cierra una frase: «Llama al tel 55 1234 5678.» no
  produce nada. Arreglo: `(?!\.?\d)`.

### Cosmético

- [ ] **`first-parent` atribuye el origen al merge cuando el commit lateral
  tiene fecha posterior** — `historial.py:278`. La sobreescritura confía en
  que el commit original es más viejo, pero `git log` ordena por fecha de
  committer: con un reloj adelantado o un rebase que conserva fechas, el merge
  se emite después y gana. El reporte manda a quien limpia al commit
  equivocado. Arreglo: quedarse con la fecha mínima, o `--topo-order`.

- [ ] **La sección «Deuda pagada» del HTML corta en 10 sin decirlo** —
  `reporte_html.py:252`. Sus dos hermanas sí avisan «…y N más»; ésta
  desaparece las entradas 11 en adelante, y quien regenera la línea base
  guiándose por el HTML cree que la lista está completa.

---

## Versiones propuestas

| Versión | Tema | Contenido |
|---------|------|-----------|
| v0.17.0 ✓ | Lo que el motor no leyó | UTF-16 sin BOM, Latin-1, el CSV de `dentro_de_un_numero`, `spec/`; y los plausibles de `dentro_de_url` que sobrevivan |
| v0.18.0 ✓ | Las vías de callar | Severidad en la línea base, fnmatch por segmentos, la `T` del diff y las rutas C-quoted de la Action, `detectores:` en lista |
| v0.19.0 | La regresión y los veteranos | «MiClave…» y «TuClaveAqui» (las dos caras), el teléfono con paréntesis y con punto final, los rellenos del NSS, los escapes de `_descitar` |
| v0.20.0 | Los documentos no mienten | `recortar()` sin valores completos, el `uri` del SARIF, el truncamiento del HTML, `--config ""` |
