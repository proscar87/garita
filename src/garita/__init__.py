"""Garita — impide que datos personales y credenciales entren a un repositorio.

El nombre es literal: una garita es el punto de revisión por el que nada
cruza sin inspección.

Nace de un problema común: un proyecto donde los datos financieros TIENEN que
estar versionados —hay que auditarlos— y el padrón de personas NO puede
estar. La regla que salió de ahí, y que resume la herramienta, es «la línea es
el lote, no el nombre»: se puede versionar el identificador de una unidad y su
adeudo; jamás la liga entre esa unidad y la persona.

Hecho con Claude Code (Anthropic).
"""

__version__ = "0.20.2"
