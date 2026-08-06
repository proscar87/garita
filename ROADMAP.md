# Hoja de ruta

Este documento sale de la **quinta oleada** de agentes sobre el propio código
(2026-08-06, versión auditada v0.23.0). Frentes nuevos: **el paquete
instalado desde PyPI** —nadie había comprobado que lo publicado funcione
fuera del repo—, **la propia suite de pruebas** con ejercicio de mutación, y
**evasión**: cómo entra un dato sin que nadie quiera evadir nada. Más los
arreglos de la víspera y la coherencia de los documentos.

De diez hallazgos verificados, **los diez sobrevivieron y ninguno se
refutó** — la cosecha más dura de las cinco oleadas, y los diez son falsos
negativos. Los de la segunda sección traen receta pero nadie los ha
reproducido con adversario; **verificar antes de arreglar**.

La regla para priorizar es la de siempre: *un guardián que aprueba todo es
peor que ninguno*. Primero los falsos negativos silenciosos, después los
veredictos que mienten, después la calibración, al final lo cosmético.

Cinco quedaron saldados el mismo día en **v0.23.1**, por urgentes: tres eran
regresiones propias de las últimas horas. Van marcados abajo.

Las cuatro oleadas anteriores quedaron saldadas: v0.8.0–v0.12.0 (16 países),
v0.13.0–v0.16.0 (20 de 20), v0.17.0–v0.20.1 (23 de 23) y v0.20.2–v0.23.0
(18 arreglados, 3 refutados por doctrina).

---

## 1. Confirmado y reproducido

### Las regresiones de la víspera

- [x] **El remedio de cp1252 invirtió la ceguera: un carácter UTF-8 dentro
  de un archivo Latin-1 borra TODOS sus acentos** — `nucleo.py:289`. Tercera
  versión de esta función y segunda ceguera: v0.17.0 leía el archivo entero
  como cp1252, así que un byte Latin-1 arruinaba los acentos del UTF-8
  mayoritario; v0.20.2 lo invirtió y bastaba **un** carácter UTF-8 para
  arruinar los del padrón Latin-1 —la población que v0.17.0 existía para
  leer— en cuanto alguien le pega una línea desde un editor moderno.
  *(Saldado en v0.23.1: la codificación se decide POR BYTE, con un manejador
  de errores que lee como cp1252 sólo la secuencia inválida. Las dos
  direcciones se sirven a la vez; no había que elegir.)*

- [x] **`Ilegible` sólo cubre `read_bytes`: un DIRECTORIO sin permiso deja
  el archivo en «binarios o muy grandes» y aprueba con 0** —
  `nucleo.py:428`. `is_file()` se traga el `OSError`, así que el arreglo de
  v0.22.0 funcionaba para `chmod 000 archivo` y no para `chmod 000
  directorio`, que es la forma en que aparece en un contenedor de CI con
  otro UID. Y `es_revisable` ya calculaba el motivo «ilegible» al fallar el
  `stat`: `revisar` lo tiraba porque sólo miraba «tope». *(Saldado en
  v0.23.1, las tres vías.)*

- [x] **`os.geteuid()` dentro del decorador tumba el MÓDULO ENTERO en
  Windows** — `tests/test_garita.py:690`. Esa función no existe en Windows y
  el decorador se evalúa al construir la clase, así que desde v0.22.0 el job
  de `windows-latest` **no corría ni una de las 248 pruebas**: reventaba al
  importar. «Cero pruebas» y «todo verde» se parecen demasiado en un tablero.
  *(Saldado en v0.23.1 con `getattr`.)*

### El paquete y las listas

- [x] **Un BOM en la lista de nombres borra el PRIMER nombre y el repo sale
  verde** — `fuentes.py:97`. Es el defecto que v0.21.0 cerró en `config.py`
  y que no se llevó a `fuentes.py`; aquí es peor, porque lo que desaparece
  no es una clave sino **una persona del padrón**, sin mensaje y sin código
  2. Con una lista de un solo nombre el veredicto pasa de 1 a 0. *(Saldado
  en v0.23.1 en las tres lecturas: AST, JSON y texto.)*

### Evasión: por dónde entra un dato sin que nadie quiera evadir

- [ ] **NFD (acento combinante) ciega a TODO detector con contexto y al de
  nombres** — `nucleo.py:252`. `descifrar()` no normaliza Unicode y ningún
  detector lo hace después: en un archivo NFD —lo que produce macOS al
  copiar nombres de archivo, y varios exportadores— «Cédula» y «José» son
  otras cadenas. Se caen los `_CONTEXTO` de EC, DO, PT, UY, CO, CL, VE y el
  del NSS, más el patrón de nombres. Los detectores con `exige_contexto`
  quedan **completamente** ciegos y el archivo cuenta como revisado. Arreglo:
  normalizar a NFC en `descifrar()`, un `unicodedata.normalize`.

- [ ] **`nombre`/`cliente` usan `search`: un padrón de una sola línea reporta
  UN nombre** — `detectores/__init__.py:31`. Un JSON de una línea (`jq -c`,
  una respuesta de API guardada) con cuatrocientos nombres produce **un**
  hallazgo. `secretos` y todos los países usan `finditer` con el comentario
  explícito de por qué; el detector de nombres nunca recibió esa lección. Y
  no es sólo un conteo bajo: la línea base congela ese `1` y a partir de ahí
  se pueden agregar cientos de nombres sin que el veredicto cambie.

- [ ] **Un secreto sin comillas (.env, .properties, docker-compose) no lo ve
  ningún detector** — `secretos.py:351`. `NOMBRES_SOSPECHOSOS` exige que el
  valor sea un literal entrecomillado, y el razonamiento escrito arriba es
  sobre CÓDIGO. Pero los formatos donde de verdad se filtra una credencial
  por descuido no usan comillas por convención: `.env`, `.properties`,
  `.ini`, el bloque `environment:` de un docker-compose, un `Secret` de
  Kubernetes en YAML plano. Ahí `DB_PASSWORD=<20 aleatorios>` no lo ve
  nadie, salvo que además case un prefijo de proveedor conocido — y es
  justo el hueco bajo el consejo que la propia herramienta imprime
  («guárdala en un .env ignorado por git»).

- [ ] **Tres decimales cerca borran la CLABE de un CSV de banco** —
  `_comun.py:59`. La ventana antirruido descarta la coincidencia con tres
  pares `dígito[.,]dígito` en 24 caracteres a cada lado: una fila de export
  bancario —cuenta, monto, comisión, IVA— llega a tres sin esfuerzo y la
  CLABE válida se descarta antes de validar nada. El arreglo del CSV de
  v0.17.0 quedó a medias: quitó la coma de los bordes y la ventana sigue
  matando el mismo layout.

### La suite

- [ ] **«Sin revisar por tamaño» sólo tiene prueba en `--historial`** —
  `tests/test_garita.py:1709`. Mutación que sobrevive: borrar la línea de
  `nucleo.py` que NOMBRA el archivo omitido por tamaño deja las 248 pruebas
  en verde. Con esa línea muerta, un volcado de 2 MB con un padrón dentro
  desaparece en el conteo agregado y el repo sale con «✓ nada que reportar».

### Los documentos

- [ ] **«Es el único detector con esa regla» — hoy son nueve** —
  `docs/DISENO.md:85` y `docs/IDENTIFICADORES.md:192`, que lo repite en
  negritas. Además del NSS mexicano exigen contexto ec, pt, gt, us, do, co
  (el NIT de base 8), py y ca. No es cosmético: `_comun` exige la palabra en
  **la misma línea**, así que la forma canónica de un padrón exportado
  —encabezado con el nombre de la columna y las filas debajo— pasa limpia, y
  el documento hace creer lo contrario.

---

## 2. Plausible, sin verificar aún

*(Traen receta del buscador; nadie los ha reproducido con adversario.)*

### Veredictos que podrían mentir

- [ ] **v0.23.0 nunca llegó a PyPI** — `.github/workflows/publicar.yml:13`.
  `pip install garita` entregaba 0.22.0. Confirmado a mano: la publicación
  quedó en cola durante la caída de GitHub del 6 de agosto. **Verificar si
  ya entró**; si el workflow no reintenta, hace falta una comprobación
  posterior al release, porque un tag publicado sin paquete es una promesa
  a medias.

- [ ] **Los ilegibles sólo llegaron a la terminal**: el resumen del job, el
  HTML y el SARIF siguen diciendo «✅ Nada que reportar» mientras el código
  de salida es 2 — `reporte.py:278`. El arreglo de v0.22.0 tocó un canal de
  los cuatro.

- [ ] **El SARIF y el HTML publican el NOMBRE COMPLETO** mientras juran que
  no hay valores completos — `detectores/__init__.py:35`. El detector de
  nombres no pasa por `recortar`. Hay defensa parcial (la lista suele vivir
  en el repo), pero **no** para las fuentes opcionales, que están
  gitignoreadas justo para que los nombres de clientes no vivan ahí. O se
  recorta, o los documentos dejan de prometerlo.

- [ ] **Con stdout en cp1252 (Windows por omisión) un repo LIMPIO sale con
  código 1** — `reporte.py:124`. El `✓` y las viñetas revientan al
  imprimirse.

- [ ] **La exención por etiqueta impresa vale en la revisión normal y NO en
  `--historial`** — `historial.py:370`. El mismo `.garita.yml` da 0 en una y
  1 en la otra: dos verdades, que es justo lo que el docstring del historial
  dice evitar. Lo reportaron tres frentes distintos.

- [ ] **`--linea-base` borra la base pagada aunque el escaneo saliera vacío
  por otro motivo** — `cli.py:472`. Si salió vacío porque la configuración
  estaba mal, el borrado de v0.21.0 destruye deuda aceptada legítima.

### Calibración y pruebas

- [ ] **Diez detectores de país sin un solo vector negativo** —
  `tests/test_garita.py:42`. Mutación que sobrevive: quitar la comprobación
  del dígito verificador y las pruebas siguen verdes. Cada país necesita su
  caso «esto NO valida».

- [ ] **GT y PY son el mismo módulo 11: 91 % de cruce** — `README.md:135`.
  Cada país denuncia el vector oficial del otro. Verificar si el contexto
  obligatorio de ambos lo vuelve irrelevante en la práctica.

### Cosmético

- [ ] Un padrón en Latin-1 se reporta por el manejador de «país inexistente»:
  mensaje sin archivo ni remedio — `cli.py:177`.
- [ ] El error de país manda a `docs/AGREGAR_PAIS.md`, que el paquete
  instalado no trae — `detectores/paises/__init__.py:67`.
- [ ] La descripción del Marketplace y la del hook siguen siendo sólo
  mexicanas: 15 de los 16 países no aparecen — `action.yml:2`.
- [ ] La sección inglesa reexpone el origen que la española generalizó —
  `README.md:478`.

---

## Versiones propuestas

| Versión | Tema | Contenido |
|---------|------|-----------|
| v0.23.1 ✓ | Lo urgente | Codificación por byte, el `Ilegible` del directorio, Windows corriendo pruebas otra vez, el BOM de las listas |
| v0.24.0 | Por dónde entra el dato | NFD, `finditer` en nombres, el secreto sin comillas, la ventana del CSV |
| v0.25.0 | Un solo canal, una sola verdad | Ilegibles en los cuatro canales, exenciones por etiqueta en el historial, los nombres del SARIF y el HTML |
| v0.26.0 | Que las pruebas no mientan | Vectores negativos por país, la mutación del tamaño, cp1252 en stdout |
| continuo | Documentos | «El único detector», el Marketplace, la sección inglesa |
