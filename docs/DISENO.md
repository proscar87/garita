# Decisiones de diseño

Por qué Garita es como es. Están aquí las que parecen raras, porque las obvias
no necesitan defensa y las raras son justo las que alguien va a querer
cambiar sin saber qué se rompe.

---

## Falla ruidosa, nunca silenciosa

Si Garita no puede cargar la lista de nombres —el archivo no existe, la
constante desapareció, la lista quedó vacía— **no continúa**. Sale con código
2 y dice exactamente qué pasó.

La alternativa tentadora es «si no hay lista, revisa lo demás y sigue». Es
peor que no tener guardián: produce una marca verde que nadie va a cuestionar
mientras el detector más importante está apagado. Un guardián ciego que dice
«OK» genera confianza sin respaldo, y esa confianza es exactamente lo que
hace que alguien deje de revisar a mano.

Lo mismo aplica a las listas degeneradas. Una lista vacía, o con entradas de
dos letras que casarían con medio repositorio, se rechaza en vez de aceptarse:
las dos formas de romper un detector son no encontrar nada y encontrarlo todo.

---

## Se lee por AST, no se importa

La lista de nombres se extrae del generador de datos sintéticos con `ast`,
que lee el archivo como texto.

Importarlo sería más simple y más flexible —admitiría listas calculadas— pero
significaría **ejecutar código del repositorio revisado dentro del proceso del
guardián**, en CI, normalmente con permisos de escritura sobre el propio
repositorio. Un repositorio que se revisa a sí mismo no debería poder ejecutar
nada durante su revisión.

El costo es real y se acepta: la constante tiene que ser un literal. Si
alguien la construye en tiempo de ejecución, Garita falla con un mensaje que
explica por qué no puede leerla.

---

## Sólo lo que git rastrea

Los archivos ignorados no se revisan. El daño de un dato personal empieza
cuando se publica, y aquí publicar es `git push`. Un borrador en el disco de
alguien no es problema de esta herramienta.

Además, escanear el árbol completo produce ruido con `node_modules`, `.venv`
y descargas de trabajo — y el ruido es lo que enseña a la gente a ignorar al
guardián.

---

## El motivo de cada exención es obligatorio

No se puede exentar un archivo sin escribir por qué.

Una lista de exenciones sin razones se convierte, en pocos meses, en la lista
de archivos que nadie se atreve a tocar porque nadie recuerda por qué están
ahí. Deja de ser una decisión y pasa a ser sedimento. Con el motivo escrito,
cualquiera puede evaluar si sigue siendo válido — y si el motivo suena mal al
escribirlo, probablemente la exención esté mal.

Las exenciones se acotan por detector por la misma razón: exentar un archivo
de `curp` porque documenta el formato no debería exentarlo también de
`llave_privada`.

---

## Se valida el dígito verificador, no sólo la forma

Un detector que marca cualquier cadena de 18 caracteres como CURP grita en
falso constantemente. Y un guardián que grita en falso se acaba ignorando:
alguien propone desactivarlo «mientras tanto», y a partir de ahí no detecta
nada. La falla por exceso mata más guardianes que la falla por omisión.

La validación cambia el orden de magnitud: entre 90 y 5,000 veces menos falsos
positivos según el identificador. Ver [`IDENTIFICADORES.md`](IDENTIFICADORES.md).

El NSS lleva esto más lejos y **exige contexto léxico en la línea**, porque
Luhn solo corta el 90% y once dígitos también son un folio. Es el único
detector con esa regla, y está documentado para que nadie lo tome por
descuido.

---

## Nunca se imprime un valor completo

Los secretos y los identificadores se recortan (`eyJh…lIn0`) en toda la
salida.

La salida de una ejecución de CI suele ser visible para más gente que el
propio repositorio, y a menudo se conserva más tiempo. Volcar ahí la
credencial completa la filtra otra vez, ahora en un lugar donde nadie la
busca. El recorte deja lo justo para localizarla en el archivo.

---

## No hay modo «arreglar automáticamente»

Borrar un dato personal de un archivo sin que un humano vea el contexto es
cómo se pierde información legítima. Y más importante: **el dato ya está en el
historial de git**, así que editar la línea da sensación de limpieza sin
quitar el riesgo.

Por eso cada hallazgo dice qué hacer en el orden correcto: si es una
credencial, **rotar primero** —eso invalida la copia filtrada— y limpiar
después. Rotar es la acción que reduce el riesgo; reescribir el historial es
higiene.

---

## Cero dependencias

Incluido el lector de YAML, que son cien líneas.

Un guardián que exige `pip install` antes de correr es un guardián que la
gente pospone, y el que se pospone no protege. El subconjunto de YAML que
necesita la configuración —listas y mapas de un nivel— no justifica una
dependencia que además habría que auditar: una herramienta de seguridad que
arrastra árboles de dependencias amplía justo la superficie que dice cuidar.

El lector rechaza lo que no entiende en vez de adivinar. Un detalle que costó
un bug: en YAML un mapa exige **espacio** tras los dos puntos, así que
`scripts/gen.py:PROHIBIDOS` es una cadena y no una clave. Sin esa regla, la
fuente de nombres se perdía en silencio — el peor modo de falla posible,
porque el guardián revisaba menos de lo que creía y no lo decía.

---

## El hook primero, la Action después

Ambos, y en ese orden.

Si el único control está en CI, cuando falla el dato personal **ya vive en un
commit**. El arreglo pasa de «borra la línea» a «reescribe el historial y
avisa a quien haya clonado». El hook de `pre-commit` es el momento en que el
arreglo todavía es barato.

Pero el hook se salta con `--no-verify`, así que la Action es el respaldo que
nadie evade. Ninguna capa sustituye a la otra.

---

## Cada hallazgo trae su porqué y su arreglo

Un mensaje que dice «patrón prohibido en la línea 47» obliga a quien lo lee a
averiguar qué patrón, por qué importa y qué se supone que haga. Al tercer
mensaje así, alguien propone desactivar el paso.

Escribir el porqué una vez cuesta más y ahorra la conversación cada vez. Es la
misma economía que un buen mensaje de error de compilador.

---

## Garita se revisa a sí misma

El CI de este repositorio ejecuta la acción de este repositorio.

Una herramienta de seguridad que no se aplica sus propias reglas pide una
confianza que no está dispuesta a dar. Y es la prueba de humo más honesta que
hay: si las exenciones de `.garita.yml` empezaran a crecer, sería la señal de
que los detectores están mal calibrados — no de que este proyecto es especial.
