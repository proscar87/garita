# Nota de seguridad

Garita es una herramienta de seguridad. Estas son sus propias reglas, y su
propia superficie de riesgo.

## Lo que Garita hace con tus datos

**Nada sale de tu máquina.** No hay telemetría, no hay servicio, no hay
llamadas de red. Todo el análisis es local, en el proceso que la invoca.

**Cero dependencias.** Ni siquiera para leer YAML. Una herramienta de
seguridad que arrastra un árbol de dependencias amplía justo la superficie que
dice cuidar, y cada dependencia es una cadena de suministro que alguien tiene
que auditar.

**No ejecuta el código que revisa.** La lista de nombres se extrae del
generador de datos sintéticos con `ast`, que lee el archivo como texto.
Importarlo sería más flexible, pero significaría ejecutar código del
repositorio revisado dentro del proceso del guardián, en CI, normalmente con
permisos de escritura sobre el propio repositorio.

**No imprime valores completos.** Secretos e identificadores se recortan en
toda la salida. El registro de una ejecución de CI suele ser visible para más
gente que el propio repositorio y se conserva más tiempo: volcar ahí la
credencial la filtra otra vez, en un lugar donde nadie la busca.

## Lo que Garita NO puede hacer

**No detecta identificación por agregación.** Busca lo que le declaras y lo
que tiene forma reconocible. No ve que «una empresa de N empleados en tal
municipio» señala un lugar concreto aunque no aparezca ningún nombre. Eso lo
tiene que ver una persona, y conviene revisar con ese lente los README y los
comentarios, que es donde el contexto se cuela.

*(Lo aprendimos publicando este mismo repositorio: la primera versión del
README describía su caso de origen con suficiente detalle para identificarlo.
Ninguna regla de Garita lo habría atrapado.)*

**No limpia el historial.** Cuando marca algo, el dato ya está en el archivo;
si además ya se commiteó, está en el historial y en el disco de quien haya
clonado. Por eso los mensajes dicen el orden correcto: si es una credencial,
**rotar primero** —eso invalida la copia filtrada— y limpiar después.

**No sustituye a un escáner de secretos.** `gitleaks` y `trufflehog` tienen
más catálogo de proveedores y verificación activa. Úsalos. Garita cubre lo que
ellos no ven: los nombres de tu propio padrón y los identificadores
nacionales.

## Reportar una vulnerabilidad

Si encuentras una forma de evadir un detector, o algo en Garita que filtre
datos, ábrelo como issue **sin incluir datos reales** en el reporte: construye
un caso sintético que reproduzca el problema.

Si crees que el hallazgo es delicado, escribe a la dirección de contacto del
perfil en vez de abrir un issue público.

## Los datos de este repositorio

Todos los identificadores que aparecen en el código, las pruebas y la
documentación son **claves de muestra publicadas por la autoridad** (RENAPO,
SAT, IMSS) o construidas sintéticamente calculando su dígito verificador.
Ninguno pertenece a una persona. Los nombres de ejemplo son ficticios.

Garita se revisa a sí misma en cada push; el trabajo `Garita se revisa a sí
misma` del CI es esa comprobación.
