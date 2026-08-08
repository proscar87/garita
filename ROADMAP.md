# Hoja de ruta

Este documento sale de la **sexta oleada** de agentes sobre el propio código
(2026-08-07, versión auditada v0.24.0). Frentes nuevos: **el ruido en repos
reales** —hasta ahora sólo se había medido la ceguera, nunca los gritos—,
**Garita como blanco** de un repositorio hostil, y **los dieciséis países
como conjunto**, con sus colisiones. Más los arreglos de la víspera y la
coherencia entre los cuatro canales de salida.

De diez hallazgos verificados, **los diez sobrevivieron y ninguno se
refutó**, igual que en la quinta. Los diez quedaron saldados en **v0.25.0**.
Los de la segunda sección traen receta pero nadie los ha reproducido con
adversario; **verificar antes de arreglar**.

La regla para priorizar es la de siempre: *un guardián que aprueba todo es
peor que ninguno*. Primero los falsos negativos silenciosos, después los
veredictos que mienten, después la calibración, al final lo cosmético.

Las cinco oleadas anteriores quedaron saldadas: v0.8.0–v0.12.0 (16 países),
v0.13.0–v0.16.0 (20 de 20), v0.17.0–v0.20.1 (23 de 23), v0.20.2–v0.23.0
(18 arreglados, 3 refutados por doctrina) y v0.23.1–v0.24.1 (todos).

---

## 1. Confirmado, reproducido y saldado en v0.25.0

### Las regresiones de la víspera

- [x] **El filtro de «referencia» se aplicaba también al valor
  ENTRECOMILLADO** — `secretos.py:403`. `_ES_REFERENCIA` se escribió para el
  valor sin comillas, pero el `continue` quedó en el bucle común: mataba las
  credenciales de prefijo punteado —`hvs.` de Vault, `dp.st.` de Doppler,
  `cs.live.`— que v0.23.0 **sí** reportaba. Con `fallar_en_aviso: true` el
  veredicto pasaba de 1 a 0. *(El generador marca de qué rama viene cada par
  y el filtro sólo aplica a la pelona.)*

- [x] **La normalización NFC no cubría la rama del BOM ni la del UTF-16** —
  `nucleo.py:283`. El `normalize` estaba sólo en el `return` final, y el
  «CSV UTF-8» de Excel **siempre** escribe BOM: un padrón exportado de Excel
  en NFD seguía completamente ciego después del arreglo de la víspera.
  *(Un solo punto de salida normalizado, `_nfc()`, en las tres ramas.)*

- [x] **El tabulador de `_SEPARA_CAMPO` era código muerto** —
  `_comun.py:42`. `rstrip()` sin argumentos lo borraba antes de mirarlo, así
  que la salvaguarda de v0.24.0 nunca aplicaba a un TSV y la ventana
  antirruido volvía a matar el hallazgo. *(Se recortan sólo espacios.)*

### Garita como blanco

- [x] **Un archivo del PR llamado «--version» hacía salir con 0 sin revisar
  nada** — `scripts/ejecutar.py:83`. Los nombres del diff se concatenaban a
  `argv` sin separador, y argparse lee como BANDERA todo lo que empiece por
  guion: el PR se aprobaba solo. Con `-h` igual; con `--sin-linea-base` o
  `--formato=sarif` se alteraba el modo. El nombre del archivo lo elige
  quien manda el PR. *(`--` antes de los nombres.)*

- [x] **Un `.garita.yml` del propio PR apagaba TODOS los detectores en
  silencio** — `reporte.py:124`. Todo lo demás de la herramienta se grita
  —las exenciones muertas, las listas ausentes, lo omitido por tamaño— y el
  interruptor general era el único mudo: tres líneas de configuración junto
  al secreto y la salida era «✓ nada que reportar» con código 0. *(Los
  recortes de configuración se anuncian en la terminal y en el resumen del
  job; lo que se apaga solo por no haber lista no cuenta, para no hacer
  ruido en todo repo sin configuración.)*

- [x] **Un patrón de exención con varios comodines dobles colgaba el
  guardián** — `nucleo.py:377`. Sin memoización el costo era combinatorio y
  se pagaba POR ARCHIVO: doce `**` sobre una ruta de veinte segmentos
  tardaban 222 segundos, y el patrón vive en el `.garita.yml` del
  repositorio revisado. *(Memoizado: 0.02 ms.)*

- [x] **La guardia contra `..` comparaba PREFIJOS de cadena** —
  `fuentes.py:159`. Con la raíz `/w/trav`, un directorio HERMANO llamado
  `/w/trav-secretos/` quedaba «dentro» y Garita leía fuera del repositorio —
  y esa lista se vuelve el patrón del detector `nombre`, que imprime lo que
  casa. *(Comparación por árbol, no por texto.)*

### Los países

- [x] **El DNI y el NIE escritos con separador de millares eran invisibles**
  — `es.py:24`. «12.345.678-Z» es como se escribe un DNI en una carta, una
  factura o una hoja de cálculo españolas. *(Se admite la forma punteada; el
  punto no cuenta como refuerzo, así que no afloja nada.)*

### Los canales

- [x] **«Sin revisar por tamaño» no llegaba al SARIF ni al resumen del job**
  — `sarif.py:186`. El SARIF es el ÚNICO canal de la auditoría mensual
  documentada: la pestaña Security decía «cero alertas» sobre un padrón de
  2 MB que nadie leyó. *(Los ilegibles y los omitidos por tamaño entran como
  alertas propias con su regla `sin_revisar`, y el resumen del job pasa de
  ✅ a ⚠️.)*

- [x] **`otras_rutas` sólo existía en la terminal** — `sarif.py:152`. El
  SARIF y el HTML del historial nombraban la ruta de origen —que puede ser
  el fixture inocente— y ocultaban la copia viva en producción.

---

## 2. Plausible, sin verificar aún

*(Traen receta del buscador; nadie los ha reproducido con adversario.)*

### Veredictos que podrían mentir

- [ ] **Un symlink rastreado hace que Garita lea archivos arbitrarios fuera
  del repositorio y publique fragmentos en el SARIF** — `nucleo.py:340`.
  Hermano del que se cerró en `fuentes.py`, por otra puerta.
- [ ] **`--historial` nunca escribe `GITHUB_STEP_SUMMARY`** — `cli.py:205`.
  El panel del job queda en blanco aunque la auditoría encuentre errores.
- [ ] **La tabla del resumen del job no lleva severidad** — `reporte.py:290`.
  El error que reprueba y el aviso degradado de `examples/` salen como dos
  filas idénticas.
- [ ] **Las exenciones muertas sólo se dicen en la terminal**, y en
  `--historial` no se calculan en ningún canal — `reporte.py:99`.

### Calibración

- [x] **`llave_privada` casa la CABECERA PEM sin exigir cuerpo** —
  `secretos.py:57`. Medido en un repo real: 48 de 48 hallazgos eran una
  línea de docstring. El más rentable de esta lista.
- [ ] **El prefijo repetible marca constantes de enumeración** —
  `secretos.py:347`.
- [ ] **`_ES_REFERENCIA` no reconoce el identificador pelón** —
  `secretos.py:368`: `mqtt_password = decrypted_result` sale como aviso.
- [ ] **El CIF no tiene lista de rellenos** — `es.py:42`: `U-00000000`
  valida.
- [ ] **`range(1, 10)` deja el RUT de todo ceros fuera de la lista negra**
  que su propio docstring promete — `cl.py:23`.
- [ ] **El teléfono mexicano acepta el PUNTO como separador** —
  `mx.py:370`, cuando `_comun` ya había prohibido esa misma señal.
- [ ] **AR y PE comparten pesos idénticos**: 82–90 % de los CUIT/RUC de
  prefijo 20 los denuncian los dos países — `pe.py:33`.
- [ ] **Cinco países reclaman «ocho dígitos con guion o puntos» sin exigir
  contexto, y el reporte no deduplica** — `uy.py:21`.
- [ ] **El contexto obligatorio de la cédula ecuatoriana satisface por
  construcción el refuerzo del NIT colombiano** — `co.py:40`.

### Cosmético

- [ ] **El `finditer` de nombres emite duplicados idénticos** —
  `detectores/__init__.py:37`: 20 000 resultados SARIF de los que sólo 400
  son distintos. Consecuencia del arreglo de v0.24.0.
- [ ] **`recortar` sobre `llave_privada` imprime `----…----`** —
  `secretos.py:319`: se censura la única parte que NO es secreta, y quien
  tría cuarenta y ocho hallazgos idénticos no puede distinguirlos.

---

## Versiones propuestas

| Versión | Tema | Contenido |
|---------|------|-----------|
| v0.25.0 ✓ | El repo revisado no manda | Los diez confirmados de la sexta oleada |
| v0.27.0 ✓ | El ruido que sí importa | La cabecera PEM sin cuerpo, los rellenos del CIF y del RUT, el punto del teléfono, los duplicados de nombres |
| v0.27.0 | Un solo canal, una sola verdad (II) | El summary del historial, la severidad en la tabla, las exenciones muertas en los cuatro canales |
| continuo | Colisiones entre países | AR/PE, los cinco de ocho dígitos, EC/CO — medir antes de tocar |
