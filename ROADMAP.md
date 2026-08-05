# Hoja de ruta

Este documento sale de una auditoría de agentes sobre el propio código
(agosto 2026): cada hallazgo de la primera sección fue **reproducido de punta
a punta** por un verificador adversarial independiente antes de entrar aquí.
Los de la segunda sección son plausibles pero nadie los ha reproducido
todavía: verificar antes de arreglar. El orden dentro de cada sección es el
orden sugerido de trabajo.

La regla para priorizar es la del proyecto: *un guardián que aprueba todo es
peor que ninguno*. Primero va todo lo que hace que Garita apruebe en silencio
algo que no revisó (falsos negativos estructurales), después la calibración,
al final lo cosmético.

---

## 1. Confirmado y reproducido

### El veredicto no debe mentir

- [x] **Archivos inexistentes se omiten en silencio y Garita aprueba con
  exit 0** — `src/garita/nucleo.py:281`, `src/garita/cli.py:192`. Un nombre
  mal tecleado en la config del hook, o correr `garita archivo.py` desde un
  subdirectorio, produce «✓ nada que reportar … 1 omitidos (binarios o muy
  grandes)» y sale con 0. Peor: una ruta absoluta sí se revisa pero escapa a
  exenciones y línea base. Arreglo: normalizar `args.archivos` contra la raíz
  del repo; ruta inexistente o fuera del repo → exit 2 con mensaje claro.

- [x] **En clones shallow, `--historial` declara limpio un historial que no
  pudo ver** — `src/garita/historial.py:106`. Con `--depth 1` (el default de
  `actions/checkout`, el entorno más probable de la auditoría) `rev-list`
  solo ve el corte: un secreto borrado hace meses es invisible y Garita sale
  con 0. Arreglo: `git rev-parse --is-shallow-repository` antes de auditar;
  si es shallow → exit 2 pidiendo `fetch-depth: 0` / `--unshallow`.

- [x] **Una sola ruta por blob: una copia en `fixtures/` absuelve al secreto
  en `src/`** — `src/garita/historial.py:111`. `blobs.setdefault(sha, ruta)`
  conserva la primera ruta que `rev-list` entrega (orden alfabético), y esa
  ruta única decide relajación y exenciones. Una llave privada en
  `src/secreto.pem` copiada a `fixtures/ejemplo.pem` deja de reportarse.
  Arreglo: guardar todas las rutas por blob; omitir solo si **todas** lo
  omiten, reportar con la más severa. *(Nota del arreglo: `rev-list
  --objects` deduplica por objeto y las rutas extra ni aparecen; hubo que
  juntarlas de `git log --raw`.)*

- [x] **`examples/` relaja `llave_proveedor` y `credencial_en_url`, el
  escenario que el propio código declara como la fuga típica** —
  `src/garita/nucleo.py:80,90`. Una llave AKIA real en `examples/config.yml`
  se suprime sin dejar rastro, contradiciendo el comentario («sólo se relaja
  lo criptográfico») y el docstring de `secretos.py` («la mitad de las fugas
  reales son el archivo de ejemplo con valores verdaderos»). Arreglo: reducir
  el frozenset a lo criptográfico de fixtures y sacar `examples?|ejemplos?`
  de la relajación de credenciales — o degradar a aviso en vez de suprimir.

### Calibración de secretos

- [x] **`MARCADORES` descarta secretos reales que contengan «tu» como
  subcadena** — `src/garita/detectores/secretos.py:112,144`. El `.search`
  sin anclar hace que «VirtualPass2024» (contiene «tu» en «Virtual»), o
  cualquier token largo cuya base64 incluya «tu»/«ejemplo»/«fake», se
  descarte en silencio como placeholder. *(Arreglo final: un marcador cuenta
  si no está incrustado entre letras — así «7EXAMPLE» de la llave de AWS
  sigue contando — y «tu…»/«your…» sólo absuelve siendo el valor completo.)*

- [x] **Los formatos vigentes de OpenAI y Stripe no casan con
  `llave_proveedor`** — `src/garita/detectores/secretos.py:67`.
  `sk-[A-Za-z0-9]{20,}` no admite guiones ni guiones bajos: `sk-proj-…`,
  `sk-svcacct-…`, `sk_live_…`, `rk_live_…` pasan limpios (el formato legado
  sí se detecta). *(Arreglo final: prefijos explícitos `sk-proj-/svcacct-/
  admin-`, `[sr]k_live_`, `gh[opsur]_` y `npm_`; el `sk-` pelón se queda
  alfanumérico puro a propósito — admitirle guiones casaría clases CSS de
  esqueleto.)*

- [x] **`credencial_en_url` exige usuario no vacío: `redis://:pass@host`
  pasa limpio** — `src/garita/detectores/secretos.py:87`. Verificado y
  reproducido al arrancar v0.9.0 (venía de la sección 2). Es la forma normal
  de redis y memcached.

- [x] **`buscar_asignaciones` corta en la primera credencial de la línea**
  — `src/garita/detectores/secretos.py:248`. Verificado y reproducido al
  arrancar v0.9.0 (venía de la sección 2): si la primera era un marcador, el
  `continue` se tragaba la línea entera. Ahora `finditer`, la misma lección
  que `buscar` ya documentaba.

### Detectores de país

- [x] **UY: «ci» como palabra de contexto choca con la integración
  continua** — `src/garita/detectores/paises/uy.py:22`. «CI corrio el
  20250801» produce un ERROR: la fecha pasa el módulo 10 y el contexto
  insensible a mayúsculas la refuerza. Es la misma lección que `ca.py` ya
  documenta con «SIN». Arreglo: quitar «ci» pelona; aceptar solo
  `c\.i\.` con puntos.

- [x] **ES: la regex del CIF rechaza «B-12345678», la forma más común por
  escrito** — `src/garita/detectores/paises/es.py:26`. DNI y NIE aceptan
  separadores; el CIF no, así que la rama de separadores de
  `exige_refuerzo` queda muerta y la forma habitual nunca casa. Arreglo:
  replicar el patrón de separadores del NIE.

### La Action

- [x] **La salida `hallazgos` de `action.yml` está documentada pero nunca se
  escribe** — `action.yml:20`, `scripts/ejecutar.py`. Nada escribe a
  `$GITHUB_OUTPUT`; todo workflow que la use recibe cadena vacía. Arreglo:
  escribir `hallazgos=N` desde `ejecutar.py` y cubrirlo con una prueba —
  o eliminar la salida del `action.yml` y del README.

---

## 2. Plausible, sin verificar aún

*(Vacía desde v0.10.0: los quince se verificaron uno por uno — cada uno se
reprodujo antes de tocarse — y los quince resultaron reales. Los dos de
secretos entraron en v0.9.0; país, CLI, reportes, historial y la deuda de
pruebas, en v0.10.0: ITIN detectable, NIT de base 8, NIE con refuerzo,
`redis://:pass@host`, asignaciones con `finditer`, `--salida` con código 2,
`--linea-base`/`--explicar` rechazan banderas que ignorarían, anotaciones
escapadas, `--sin-color` operativo, `--remotes` en la auditoría, rutas no
ASCII enteras, y pruebas para `fallar_en_aviso` y `--explicar`.)*

---

## 3. Estratégico

- [ ] **Catálogo ABM para la CLABE** — la única promesa explícita de las
  docs (`docs/IDENTIFICADORES.md:152`): validar los tres primeros dígitos
  contra el catálogo de bancos corta casi todo lo que el dígito verificador
  deja pasar.

- [ ] **`docs/IDENTIFICADORES.md` cubre solo México** aunque el README lo
  enlaza como la referencia de los 13 países y `AGREGAR_PAIS.md` exige una
  sección por país. O se agregan las 12 secciones que faltan (los datos ya
  viven en los docstrings), o README y AGREGAR_PAIS pasan a señalar los
  módulos como fuente de verdad.

- [ ] **Más países**, en el orden en que se consigan reglas verificables
  contra fuente oficial (la doctrina de `AGREGAR_PAIS.md`: un detector
  aproximado es peor que ninguno). Candidatos naturales: Venezuela, Bolivia,
  Paraguay, Guatemala, Costa Rica, Panamá.

---

## Versiones propuestas

| Versión | Tema | Contenido |
|---------|------|-----------|
| v0.8.0 ✓ | El veredicto no miente | Los cuatro de «el veredicto no debe mentir» + la salida de la Action |
| v0.9.0 ✓ | Calibración de secretos | MARCADORES anclado, formatos vigentes de proveedor, y los plausibles de secretos que sobrevivan verificación |
| v0.10.0 ✓ | Países al día + el CLI no sorprende | UY, ES, y los plausibles de país que sobrevivan; catálogo ABM |
| continuo | Deuda de pruebas | `fallar_en_aviso`, `--explicar`, `--sin-color`, salida de la Action |
