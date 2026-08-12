# Hoja de ruta

Este documento sale de la **séptima oleada** de agentes sobre el propio
código (2026-08-09, versión auditada **v0.27.0**). Cinco frentes: los
arreglos de la víspera, lo que el motor dice haber leído y no leyó, el
repositorio hostil, los dieciséis países y la coherencia entre los cuatro
canales de salida.

Treinta y cinco hallazgos crudos, nueve verificados con adversario: **siete
sobrevivieron y dos se refutaron**. Los veintiséis restantes traen receta
pero nadie los ha reproducido con adversario; **verificar antes de
arreglar**.

Lo que esta oleada vuelve a demostrar: **cinco oleadas seguidas han
encontrado una regresión publicada el mismo día**. Tres de los siete
confirmados nacieron en v0.26.1 y v0.27.0 —ayer—, y uno de ellos abre un
agujero que aprueba un repositorio entero. Auditar el arreglo propio sigue
siendo el frente más rentable que existe.

La regla para priorizar es la de siempre: *un guardián que aprueba todo es
peor que ninguno*. Primero los falsos negativos silenciosos, después los
veredictos que mienten, después la calibración, al final lo cosmético.

Las seis oleadas anteriores quedaron saldadas: v0.8.0–v0.12.0 (16 países),
v0.13.0–v0.16.0 (20 de 20), v0.17.0–v0.20.1 (23 de 23), v0.20.2–v0.23.0
(18 arreglados, 3 refutados por doctrina), v0.23.1–v0.24.1 (todos) y
v0.25.0–v0.27.0 (los diez de la sexta).

---

## 1. Confirmado y reproducido por dos agentes independientes

Los siete quedaron saldados: seis en **v0.28.0** y el del anclaje en
**v0.29.0**, aparte porque cambia la semántica de `casa_ruta` y eso se mide
contra los consumidores antes de mover el tag `v0`.

### Las regresiones de la víspera

- [x] **La llave de cuenta de servicio de Google dejó de detectarse** —
  `secretos.py:328`, *alta*. El filtro nuevo de v0.27.0 cuenta **tokens
  separados por espacio**, no palabras de prosa: un JSON de cuenta de
  servicio minificado en una línea llega a ocho tokens antes de
  `-----BEGIN` y se descarta como documentación. La misma llave indentada
  sí suena. Ningún otro detector la recoge: el archivo sale con **código
  0**. Cae cualquier asignación precedida de seis tokens, no sólo GCP.
  *Arreglo: saltar la comprobación de frase cuando el prefijo termina en
  delimitador de asignación **seguido de comilla** (`_ASIGNACION =
  re.compile(r'''[:=]\s*["'`]\s*$''')`). La comilla es obligatoria: sin
  ella vuelve el ruido de la prosa que termina en dos puntos.*

- [x] **«detectores: []» pasó de no exentar nada a exentar TODOS los
  detectores** — `config.py:96`, *alta*. La rama de colecciones vacías de
  v0.26.1 se pensó para `exenciones: []` de nivel superior, pero también
  toca la clave `detectores` de una exención: antes daba `('[]',)` —no
  casaba nada y salía como exención muerta—, ahora da `()`, que
  `Exencion.cubre` lee como **todos**. La escritura se lee como «ningún
  detector» y hace lo contrario: silencia el archivo completo, sin aviso y
  sin exención muerta. *Arreglo: distinguir la clave ausente de la lista
  vacía escrita a propósito y rechazar ésta con `ConfigInvalida`.*

- [x] **La propuesta de `--proponer-exenciones` sale más ancha que su
  hallazgo** — `cli.py:544`, *media*. Para un archivo de la raíz el patrón
  no lleva «/», y `casa_ruta` lo interpreta con semántica gitignore: casa
  el **nombre a cualquier profundidad**. Quien pega el bloque creyendo
  exentar `vectores.json` de la raíz exenta también `vendor/vectores.json`.
  Y no hay escape: ni `./x` ni `/x` casan hoy. *Arreglo en dos piezas:
  `casa_ruta` aprende el anclaje de gitignore (una barra inicial ancla a la
  raíz —hoy es código muerto, así que es estrictamente aditivo), y la
  propuesta emite `/archivo` cuando no hay directorio.*

### Lo que el motor dice haber revisado y no leyó

- [x] **Un archivo rastreado y ausente del árbol de trabajo se omite en
  silencio bajo la etiqueta «binario o muy grande»** — `nucleo.py:495`,
  *alta*. `revisar()` enumera desde el **índice** (`git ls-files`) y decide
  con el **disco** (`ruta.is_file()`). Con `git sparse-checkout set src`
  —configuración soportada por `actions/checkout`— el archivo sigue en el
  índice y en HEAD, o sea que `git push` lo publica, y Garita sale con «✓
  nada que reportar, 1 omitidos (binarios o muy grandes)» y **código 0**
  sobre un repo que publica una llave AWS. La etiqueta es literalmente
  falsa y el archivo nunca se nombra. Tres caminos reales: sparse-checkout,
  `rm` sin `git rm`, y los submódulos. *Arreglo: leer del índice
  (`git cat-file blob :<ruta>`) en vez de rendirse. Mínimo honesto: lista
  propia `ausentes_del_arbol`, nombrada, y que decida el veredicto.*

- [x] **La rama del BOM no usa el respaldo cp1252 por byte** —
  `nucleo.py:298`, *media*. Las tres ramas de BOM decodifican con
  `errors="replace"`; sólo la rama sin marca usa el manejador por byte. Y
  el «CSV UTF-8» de Excel **siempre** escribe BOM, que es justo donde
  aparece el archivo mezclado: un byte Latin-1 vuelve «Cédula» en
  «C�dula», el contexto `c[eé]dula` de EC/DO/UY/CO deja de casar, y el
  detector con `exige_contexto` queda ciego sobre un archivo que el resumen
  cuenta como revisado. `git log -L` confirma que el `replace` viene del
  commit inicial y que nadie lo revisitó al introducir `garita_cp1252`.
  *Arreglo: `garita_cp1252` para la marca UTF-8; `replace` se queda en
  UTF-16/32, donde un byte suelto no es cp1252.*

### Formas de llave que nunca han sonado

- [x] **`ENCRYPTED PRIVATE KEY`, `DSA PRIVATE KEY` y el `PGP` que el patrón
  anuncia** — `secretos.py:57`, *alta*. El patrón enumera
  `(?:RSA |EC |OPENSSH |PGP )?` y deja fuera PKCS#8 cifrado —lo que emiten
  `openssl genpkey -aes256`, `openssl genrsa -aes256` y `openssl pkcs8
  -topk8`, verificado con OpenSSL 3.6.3, o sea la forma más común hoy de
  una llave con contraseña—. Y la alternativa `PGP ` es letra muerta: gpg
  emite `-----BEGIN PGP PRIVATE KEY BLOCK-----`, que exige ` BLOCK` antes
  de los guiones. *Arreglo: `-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?:
  BLOCK)?-----`. El filtro `_pem_con_cuerpo` sigue actuando después, así
  que no vuelve el ruido de twilio-python.*

- [x] **Los tokens de prefijo punteado no se detectan en un `.env`** —
  `secretos.py:427`, *alta*. `_ES_REFERENCIA` descarta cualquier valor sin
  comillas que empiece con palabra+punto, por parecer `config.get`. Pero
  los tokens de Vault (`hvs.`), Doppler (`dp.st.`) y Stripe (`cs.live.`)
  tienen esa forma exacta, y en un `.env` van **sin comillas** por
  convención — y el `.env` es justo la rama que existe para eso. El arreglo
  de v0.24.0 restauró la rama entrecomillada y dejó viva la fuga en la
  pelona; el propio comentario declara que esas credenciales deben sonar.
  *Arreglo: exigir que la referencia sea una cadena completa de
  identificadores cortos (`\w{1,24}(\.\w{1,24})+$`, anclado) en vez de
  descartar todo lo que lleve un punto.*

---

## 2. Refutado por adversario

- **UTF-32 sin BOM se descarta como binario.** El mecanismo se reproduce,
  pero ningún exportador real produce UTF-32 sin marca: Excel no lo ofrece,
  `bcp -w` es UTF-16LE, e `iconv` y `str.encode` escriben BOM —y con BOM
  Garita sí lo lee—. Llegar al agujero exige elegir a mano `utf-32-le`.

- **El propio PR puede escribir la línea base que lo perdona.** El código 0
  es el contrato documentado de la línea base, no un falso negativo, y la
  premisa de «tampoco hay señal» es falsa en los cuatro canales: terminal,
  anotación sobre la línea exacta, resumen del job y SARIF nombran la
  credencial como deuda aceptada.

---

## 3. Plausible, con receta, sin verificar

Quedan **tres**, y dos son nuevos: salieron de correr Garita sobre los
repositorios que la consumen, no de una oleada. Los ocho de «los cuatro
canales» se saldaron en **v0.30.0**, los seis del «repositorio hostil» en
**v0.31.0**, ocho de calibración en **v0.32.0** —con dos refutados— y las
tres colisiones entre países en **v0.33.0**.

### Lo que encontró el uso, no la auditoría (2026-08-12)

- [ ] **`self.x = x` se reporta como credencial** — `secretos.py:427`,
  *falso positivo*, **medido: 20 de los 20 avisos del consumidor más
  grande**. `_ES_REFERENCIA` reconoce la referencia con punto
  (`config.token`) y la indexada (`os.environ[...]`), pero no la
  **desnuda**: en `self.azure_client_secret = azure_client_secret` el
  valor es el parámetro del constructor, o sea el patrón más común de
  Python. La política ya está escrita en el comentario de la función —«no
  parecer una referencia, que es lo que pone ahí quien hizo las cosas
  bien»—; falta el caso más frecuente de todos.

  *Receta:* añadir `\w{1,40}$` a `_ES_REFERENCIA`, o sea un identificador
  entero sin comillas. Un secreto de verdad no es un identificador válido
  —tiene guiones, puntos, mayúsculas mezcladas o largo mayor—, y la rama
  sólo aplica al valor SIN comillas. **Verificar el contrapeso**: que
  `token = supersecreto123` (sin comillas, un valor plausible) siga
  sonando, y medir contra los cuatro consumidores antes de mover `v0`.

- [ ] **Un motivo repetido palabra por palabra no es un motivo** —
  *nuevo, sin detector*. En un repositorio real, treinta exenciones
  compartían un motivo de línea base copiado en bloque; una de ellas
  cubría un archivo que ligaba propietarios a sus lotes, justo lo que la
  regla del proyecto prohíbe. El motivo boilerplate **silenció lo que no
  debía y nadie lo notó** hasta una revisión a mano.

  Garita ya exige que el motivo exista y rechaza el vacío (v0.31.0), pero
  no mira si es el mismo texto en N exenciones. *Receta:* avisar —no
  bloquear— cuando un mismo motivo literal cubre más de un puñado de
  archivos: «N exenciones comparten motivo; un motivo copiado en bloque es
  un motivo que no se pensó por archivo». Es el mismo argumento que ya
  sostiene las exenciones muertas y los recortes de configuración.

### El repositorio hostil — saldado en v0.31.0

Los seis reproducidos antes de tocarlos.

- [x] Una exención con patrón `*` o `**` apagaba el repositorio entero y el
  reporte no la nombraba: sólo una línea gris con el total de revisiones
  omitidas. No se bloquea —hay repos que legítimamente revisan una sola
  carpeta— pero ahora se NOMBRA el patrón en los cuatro canales, y en el
  SARIF con nivel de error: no es una reserva sobre el veredicto, es la
  ausencia del veredicto.
- [x] Un motivo hecho sólo de espacios pasaba la validación que toda la
  herramienta promete obligatoria — incluido `--proponer-exenciones`, que
  se apoya en que el motivo en blanco es código 2.
- [x] El hook de pre-commit pasaba los nombres sin `--`: `garita --version
  datos.txt` imprimía la versión y salía con **0**, o sea que el hook
  aprobaba el commit entero. La Action ya cerraba este ataque; la otra
  superficie con `pass_filenames` se había quedado abierta.
- [x] Un nombre de archivo hecho sólo de espacio en blanco —legal en git y
  en POSIX— se caía de la lista en modo solo-cambios.
- [x] `leer()` seguía los enlaces simbólicos. Lo que git publica de un
  symlink es la CADENA de su destino, así que la revisión normal reprobaba
  por contenido que **no está en el repositorio** mientras `--historial`,
  que sí lee el blob, decía «limpio» sobre el mismo commit.
- [x] `--linea-base` borraba la línea base commiteada cuando faltaba una
  fuente opcional y lo declaraba «deuda ya pagada». Cero hallazgos ahí no
  es deuda pagada: es revisión incompleta. Ahora sale con 2 sin tocarla.

### Los cuatro canales no dicen lo mismo — saldado en v0.30.0

Los ocho se reprodujeron construyendo un repositorio que ejercita cada
señal a la vez y diferenciando los cuatro canales sobre él.

- [x] El SARIF de `--historial` no emitía `sin_revisar`: «cero alertas»
  sobre un blob que nunca se leyó, en el modo cuyo propósito entero es no
  dar nada por revisado.
- [x] El HTML no mencionaba los archivos ilegibles, ni los recortes de
  configuración, ni las exenciones muertas — y es el canal que su propio
  docstring describe como el entregable para el auditor. Ahora hay una
  sección «Reservas sobre este veredicto» en los dos reportes HTML.
- [x] El SARIF callaba los recortes de configuración: cero alertas sobre un
  repositorio con la mitad del guardián apagado.
- [x] `--historial` nunca escribía `GITHUB_STEP_SUMMARY`, así que el panel
  de la auditoría programada salía vacío.
- [x] Las exenciones muertas sólo existían en la terminal. *(Al medir el
  arreglo apareció una real en coto-orquideas.)*
- [x] Un `|` en el nombre del archivo partía la fila de la tabla del
  resumen — y la parte aunque esté dentro de un span de código.
- [x] La tabla del resumen no llevaba severidad: el error y el aviso se
  veían idénticos.
- [x] `recortar` sobre `llave_privada` imprimía `----…----`: los dos
  extremos de un PEM son guiones. Ahora se nombra por su etiqueta
  (`ENCRYPTED PRIVATE KEY`), que no es el secreto — el secreto es el
  cuerpo, y el cuerpo no se imprime nunca.

- [ ] El bloque de `--proponer-exenciones` no es YAML válido para el propio
  lector si la ruta lleva `#` — `cli.py:544`. (Falla cerrada.)

### Los dieciséis países: colisiones — saldado en v0.33.0

Medido antes de tocar nada: **GT/PY 100 %**, **AR/PE 82.2 %**, **EC→CO
8.3 %**. La afirmación del README —«un identificador con dígito verificador
no valida fuera de su país, así que no dispara»— era **falsa** dentro de una
misma familia de diseño, y quedó corregida en los tres lugares donde se
repetía.

- [x] La información para desambiguar NO está en el número: no hay arreglo
  que la deduzca. Lo que sí se podía era dejar de fingir que la hay. Cuando
  dos países reclaman el mismo valor en la misma línea, `fusionar_ambiguos`
  emite **un** hallazgo que los nombra a todos y ofrece el camino para
  volverlo inequívoco (`paises:`), en vez de dos veredictos que se
  contradicen con la misma seguridad.
- [x] Corregido también el docstring de `paises/__init__.py` y el de
  `config.Config.paises`, que repetían la promesa falsa.

### Los dieciséis países: contexto y rellenos — saldado en v0.32.0

- [x] **El plural del sustantivo de contexto no casaba.** Toda regex cerraba
  con `\b` pegado al singular, y la clave de un YAML o de un JSON va casi
  siempre en plural: los detectores con contexto obligatorio quedaban ciegos
  sobre la forma en que se exporta un padrón. Trece países corregidos. Los
  acrónimos que en plural chocan con una palabra común del inglés
  —«run»→«runs», «sii»— se quedaron sin la «s» **a propósito**: una palabra
  de contexto envenenada es peor que la forma que deja de casar.
- [x] Los rellenos de dígito repetido, que pasan el módulo 10 y el 11 con
  frecuencia: los ocho DNI españoles, los CIF (`A00000000`, `U-00000000`),
  el RUT chileno de ceros —de siete Y de ocho dígitos—, cinco SSN, y el NIT
  colombiano, cuya lista estaba literalmente vacía. Se **generan** con el
  validador de cada país, no se copian, para que no envejezcan.
- [x] El rango 987-65-432X que la SSA reserva para publicidad, añadido con
  su fuente a la lista de publicados de EE.UU.

**Dos se refutaron al reproducirlos:**

- **El NIT guatemalteco secuencial** (el ascendente de ocho dígitos con
  su verificador). Exentar las secuencias
  ascendentes rompió tres pruebas del propio proyecto —un CIF y un NIT
  colombiano legítimos usan justo esos cuerpos— porque un identificador
  secuencial REAL existe, a diferencia de uno de ocho dígitos repetidos.
  Callarlo sería cambiar un falso positivo por un falso negativo, que pesa
  más. Sólo se exentan secuenciales con reserva oficial verificable.
- **El punto del teléfono mexicano.** No se pudo producir un falso positivo
  real: el detector no dispara dentro de un número ni dentro de una URL, y
  el punto ahí es *refuerzo* —evidencia de que alguien lo escribió como
  teléfono—, no el separador que `_comun.py` discute. Quitarlo perdería los
  teléfonos escritos con puntos, o sea un falso negativo a cambio de nada.

### Lo que sigue abierto de los países

- [ ] Un padrón exportado pelado no lo ve ningún detector, contra lo que
  promete `DISENO.md:88-93` — `_comun.py:193`. El plural NO lo arregla: el
  encabezado de un CSV va en la línea de arriba y `exige_contexto` pide la
  palabra en la MISMA línea.

---

## 4. Decisión pendiente del usuario

- [ ] **`permitidos:` por valor.** Hoy la exención más fina es por archivo,
  que en el caso del padrón de coto-orquideas es demasiado gruesa en la
  dirección peligrosa: exenta el archivo entero, incluido lo que llegue
  mañana. La propuesta es una lista de valores permitidos leída por el
  mismo mecanismo que `nombres:`; es doctrinalmente sostenible porque un
  nombre que legítimamente vive en el repositorio no añade exposición
  nueva. Cambia la semántica pública de la herramienta.

  **Evidencia de campo a favor (2026-08-12):** ese mismo repositorio acabó
  con más de treinta exenciones por archivo, y una de ellas —con motivo
  copiado en bloque— tapó un archivo que ligaba propietarios a sus lotes.
  Es exactamente la falla que la exención por archivo permite: el motivo
  habla de un caso y el alcance cubre otro. Una lista por VALOR no tiene
  esa holgura.

---

## 5. Estado de los consumidores (2026-08-12)

Los cuatro salen con código 0, y dos pendientes viejos quedaron cerrados
por su lado:

| Repo | Estado |
|---|---|
| `velador` | limpio |
| `mifo` | limpio; su línea base ya está en **formato 2** con 53 hallazgos |
| `coto-orquideas` | 1 aviso; triaje humano hecho, exención muerta retirada |
| `cinaba-platform` | 20 avisos, **los 20 del mismo falso positivo** de arriba |
