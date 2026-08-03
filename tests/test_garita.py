#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pruebas de Garita.

QUÉ SE PRUEBA Y POR QUÉ ESO

Una herramienta de seguridad tiene dos formas de fallar y sólo una duele de
inmediato. Si no detecta, el dato pasa — grave, pero silencioso. Si detecta
de más, alguien desactiva el paso «mientras tanto» y a partir de ahí no
detecta nada. La segunda falla es la que mata guardianes, así que aquí hay
tantos casos NEGATIVOS como positivos: cada uno es un falso positivo que no
queremos volver a ver.

Los casos negativos no son inventados. `sha512-…eyJ…` marcaba el
`package-lock.json` de un proyecto real, y perseguir eso fue lo que motivó
apretar el patrón de JWT.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI.parent / "src"))

from garita.config import Config, ConfigInvalida, cargar as cargar_config  # noqa: E402
from garita.detectores import construir                            # noqa: E402
from garita.detectores.secretos import (                              # noqa: E402
    buscar, buscar_asignaciones, es_marcador)
from garita.fuentes import FuenteInvalida, a_patron, cargar        # noqa: E402
from garita.detectores.paises.mx import (                             # noqa: E402
    clabe_valida, curp_valido, nss_valido, rfc_valido,
)
from garita.cli import main as garita_main                         # noqa: E402
from garita.nucleo import Exencion, revisar                        # noqa: E402


def repo_temporal(archivos: dict[str, str]) -> TemporaryDirectory:
    """Un repositorio git de verdad: Garita sólo mira lo que git rastrea."""
    td = TemporaryDirectory()
    raiz = Path(td.name)
    for rel, contenido in archivos.items():
        p = raiz / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contenido, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=raiz, check=True)
    subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
    return td


def correr_garita(raiz, *argv):
    """Corre garita como la corre el usuario: desde dentro del repo, leyendo
    lo que imprime y quedándose con el código de salida."""
    antes = Path.cwd()
    os.chdir(raiz)
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            codigo = garita_main(list(argv))
        return codigo, buf.getvalue()
    finally:
        os.chdir(antes)


class Secretos(unittest.TestCase):
    def detecta(self, texto: str) -> bool:
        return bool(list(buscar(texto, "f.py")))

    def test_detecta_jwt_completo(self):
        self.assertTrue(self.detecta(
            'k="eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZSJ9.firma"'))

    def test_no_marca_hash_de_lockfile(self):
        """El caso que motivó apretar el patrón.

        `eyJ` aparece a media cadena en un hash sha512 por coincidencia de
        base64. Marcarlo enseña al equipo a ignorar al guardián.
        """
        self.assertFalse(self.detecta(
            '"integrity": "sha512-V7QrIhZmdKPVrJYCTd8loIfBOYEJeyJIkqGIDMZPwPx24"'))

    def test_detecta_llave_privada(self):
        self.assertTrue(self.detecta("-----BEGIN RSA PRIVATE KEY-----"))

    def test_detecta_token_de_proveedor(self):
        for t in ["ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
                  "AKIAQWERTYUIOPASDFGH",
                  "sk-ant-api03-QwErTyUiOpAsDfGhJkLzXc"]:
            self.assertTrue(self.detecta(f"KEY = '{t}'"), t)

    def test_no_marca_la_llave_de_ejemplo_de_aws(self):
        """`AKIAIOSFODNN7EXAMPLE` es la clave canónica de la documentación de
        AWS. Aparece en incontables archivos de configuración de ejemplo, y
        marcarla es de los falsos positivos más comunes que existen."""
        self.assertFalse(self.detecta('accessKey: "AKIAIOSFODNN7EXAMPLE"'))

    def test_detecta_contrasena_en_url(self):
        self.assertTrue(self.detecta("postgres://admin:Kx9mPqR2vNw8@h:5432/d"))

    def test_no_marca_url_sin_contrasena(self):
        self.assertFalse(self.detecta("postgres://localhost:5432/d"))

    def test_no_marca_marcadores_de_posicion(self):
        for t in ["API_KEY=your_key_here", "token: <TU_TOKEN>",
                  "secret = 'change_me_please'", "key: xxxxxxxxxxxxxxxx"]:
            self.assertFalse(self.detecta(t), t)

    def test_no_imprime_el_secreto_completo(self):
        largo = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.firmaLarga"
        h = list(buscar(f"K='{largo}'", "f.py"))[0]
        self.assertNotIn(largo, h.que)
        self.assertIn("…", h.que)


class Asignaciones(unittest.TestCase):
    def test_detecta_valor_literal_largo(self):
        self.assertTrue(list(buscar_asignaciones('password = "Kx9mPqR2vNw8LtY4"', "f")))

    def test_no_marca_lectura_del_entorno(self):
        for t in ['password = process.env.DB_PASS',
                  'api_key = os.environ["K"]',
                  'secret = $SECRETO']:
            self.assertFalse(list(buscar_asignaciones(t, "f")), t)

    def test_no_marca_valor_corto(self):
        self.assertFalse(list(buscar_asignaciones('password = "1234"', "f")))


class RuidoDeReposReales(unittest.TestCase):
    """Casos tomados de repositorios públicos que rompían el build.

    Cinco proyectos populares sin un solo dato personal mexicano daban entre
    1 y 122 errores cada uno. Cada prueba de aquí es uno de esos falsos
    positivos, para que no vuelva: son los que deciden si alguien conserva la
    herramienta o la desinstala el primer día.
    """

    def sec(self, t):
        return bool(list(buscar(t, "x.py")))

    def asig(self, t):
        return bool(list(buscar_asignaciones(t, "x.py")))

    def test_desestructuracion_de_una_llamada(self):
        # requests/src/requests/adapters.py
        self.assertFalse(self.asig("username, password = get_auth_from_url(proxy)"))

    def test_token_de_parseo_no_es_credencial(self):
        # faker/src/modules/helpers/module.ts — «token» de un parser
        self.assertFalse(self.asig("let token = RANGE_REP_REG.exec(string);"))

    def test_referencia_a_campo(self):
        # argo-cd/pkg/apis/application/v1alpha1/types.go
        self.assertFalse(self.asig("Password: c.Config.Password,"))

    def test_llamada_en_el_readme_de_faker(self):
        self.assertFalse(self.asig("password: faker.internet.password(),"))

    def test_variable_de_ci_interpolada(self):
        # argo-cd/.github/workflows/release.yaml — es el patrón CORRECTO
        self.assertFalse(self.sec(
            'git push "https://x-access-token:${GH_TOKEN}@github.com/x.git"'))

    def test_constantes_cientificas_no_son_clabe(self):
        """numpy/random/src/distributions/ziggurat_constants.h daba 50 falsos
        positivos: la mantisa de un doble tiene 18 dígitos y uno de cada diez
        pasa el módulo 10. El catálogo de bancos es lo que los descarta."""
        from garita.detectores.paises.mx import detectores as mx
        from garita.config import Config
        d = {x.nombre: x for x in mx(Config())}["clabe"]
        for t in ["3.956832198097553231e-17,", "4.126611778175946428e-17,",
                  "p = 9.999999999333333333e-6 + x"]:
            self.assertFalse(list(d.buscar(t, "x.h")), t)

    def test_llaves_de_prueba_de_tls(self):
        """Todo proyecto que hable TLS versiona llaves de prueba. Marcarlas
        garantiza que el primer día de uso sea rojo."""
        td = repo_temporal({
            "tests/certs/server.key": "-----BEGIN RSA PRIVATE KEY-----\nabc\n",
            "src/real.key": "-----BEGIN RSA PRIVATE KEY-----\nabc\n",
        })
        with td:
            raiz = Path(td.name)
            cfg = cargar_config(raiz)
            res = revisar(raiz, construir(cfg, raiz), cfg.exenciones)
            archivos = {h.archivo for h in res.hallazgos}
            self.assertNotIn("tests/certs/server.key", archivos)
            self.assertIn("src/real.key", archivos,
                          "fuera de rutas de prueba sí debe marcarse")


class MarcadoresSobreElValor(unittest.TestCase):
    """El filtro de marcadores se aplicaba a la LÍNEA entera.

    Eso abría un boquete: una credencial real cuyo host dijera «example», o
    con un comentario «# ejemplo» al final, pasaba sin más.
    """

    def test_credencial_real_con_host_de_ejemplo(self):
        self.assertTrue(list(buscar(
            "DATABASE_URL=postgres://admin:Kx9mPqR2v@db.example.com:5432/prod",
            "x")))

    def test_credencial_real_con_comentario_ejemplo(self):
        self.assertTrue(list(buscar(
            "llave: sk-ant-api03-QwErTyUiOpAsDfGhJkLz  # ejemplo", "x")))

    def test_contrasena_que_si_es_marcador(self):
        self.assertFalse(list(buscar(
            'url = "postgres://user:your_password_here@localhost/db"', "x")))


class Fuentes(unittest.TestCase):
    def cargar(self, contenido: str, spec: str = "gen.py:PROHIBIDOS"):
        with TemporaryDirectory() as d:
            (Path(d) / "gen.py").write_text(contenido, encoding="utf-8")
            return cargar(spec, Path(d))

    def test_lee_constante_por_ast(self):
        self.assertEqual(
            self.cargar('PROHIBIDOS = ["Juanito", "Bermúdez"]\n'),
            ["Bermúdez", "Juanito"],
        )

    def test_no_ejecuta_el_archivo(self):
        """Leer por AST y no importar es una decisión de seguridad.

        Importar ejecutaría código del repositorio revisado dentro del
        guardián, en CI, con permisos sobre el propio repositorio.
        """
        with TemporaryDirectory() as d:
            marca = Path(d) / "EJECUTADO"
            (Path(d) / "gen.py").write_text(
                f'import pathlib; pathlib.Path(r"{marca}").touch()\n'
                'PROHIBIDOS = ["Ana Sofía"]\n', encoding="utf-8")
            cargar("gen.py:PROHIBIDOS", Path(d))
            self.assertFalse(marca.exists(), "el archivo se ejecutó")

    def test_falla_si_no_existe_la_constante(self):
        with self.assertRaises(FuenteInvalida):
            self.cargar("OTRA = [1]\n")

    def test_falla_con_lista_vacia(self):
        """Nunca se degrada a lista vacía: aprobar todo sin poder revisar es
        peor que no revisar, porque produce confianza sin respaldo."""
        with self.assertRaises(FuenteInvalida):
            self.cargar("PROHIBIDOS = []\n")

    def test_falla_con_entradas_muy_cortas(self):
        with self.assertRaises(FuenteInvalida):
            self.cargar('PROHIBIDOS = ["Li"]\n')

    def test_falla_si_no_es_literal(self):
        with self.assertRaises(FuenteInvalida):
            self.cargar('PROHIBIDOS = [x for x in "abc"]\n')

    def test_no_sale_del_repositorio(self):
        with self.assertRaises(FuenteInvalida):
            self.cargar("PROHIBIDOS = ['x']", spec="../fuera.py:X")


class Nombres(unittest.TestCase):
    def test_tolera_acentos_ausentes(self):
        rx = a_patron(["Bermúdez"])
        self.assertTrue(rx.search("firmó Bermudez el acta"))
        self.assertTrue(rx.search("firmó Bermúdez el acta"))

    def test_ignora_mayusculas(self):
        self.assertTrue(a_patron(["María"]).search("MARÍA GÓMEZ"))
        self.assertTrue(a_patron(["María"]).search("MARIA GOMEZ"),
                        "también sin acentos, como suele venir en un CSV")

    def test_no_casa_dentro_de_otra_palabra(self):
        """Sin fronteras de palabra, «Ana» casaría en «banana» y «Sonora»."""
        rx = a_patron(["Ana"])
        self.assertFalse(rx.search("comí una banana"))
        self.assertFalse(rx.search("viajé a Sonora"))
        self.assertTrue(rx.search("Ana firmó"))


class IdentificadoresMexicanos(unittest.TestCase):
    """Los algoritmos, contra vectores de muestra oficiales.

    Ningún identificador de aquí pertenece a una persona: son claves modelo
    publicadas por RENAPO, el SAT y el IMSS en sus instructivos, o
    construidas sintéticamente para estas pruebas.
    """

    def test_curp_vectores_oficiales(self):
        for v in ("HEGG560427MVZRRL04", "SASO750909HDFNNS05",
                  "ZUNA540308MNELTN05"):
            self.assertTrue(curp_valido(v), v)

    def test_curp_rechaza_digito_mutado(self):
        self.assertFalse(curp_valido("HEGG560427MVZRRL03"))

    def test_curp_diagrama_del_dof_no_valida(self):
        """El diagrama ilustrativo del DOF trae un dígito decorativo.

        Sirve como caso negativo, no como vector positivo — confundirlo es un
        error fácil para quien implemente esto después.
        """
        self.assertFalse(curp_valido("SABC560626MDFLRN09"))

    def test_rfc_vectores_oficiales(self):
        for v in ("GODE561231GR8", "CACX7605101P8"):
            self.assertTrue(rfc_valido(v), v)

    def test_rfc_generico_de_extranjero_si_valida(self):
        """XEXX010101000 pasa el módulo 11, así que necesita lista blanca
        explícita; XAXX010101000 no lo pasa y se descartaría solo."""
        self.assertTrue(rfc_valido("XEXX010101000"))
        self.assertFalse(rfc_valido("XAXX010101000"))

    def test_clabe_vector_publicado(self):
        self.assertTrue(clabe_valida("032180000118359719"))
        self.assertFalse(clabe_valida("032180000118359710"))

    def test_nss_luhn(self):
        self.assertTrue(nss_valido("92988084494"))
        self.assertFalse(nss_valido("92988084495"))
        self.assertFalse(nss_valido("29988084494"), "Luhn detecta transposición")

    # ── Evasiones que se encontraron probando ──────────────────────────────

    def _det(self, nombre):
        from garita.detectores.paises.mx import detectores
        from garita.config import Config
        return {d.nombre: d for d in detectores(Config())}[nombre]

    def test_curp_en_minusculas(self):
        """Un CSV exportado o un JSON de formulario traen los datos así.

        Un detector que sólo mira mayúsculas deja pasar el archivo completo.
        """
        d = self._det("curp")
        self.assertTrue(list(d.buscar("curp: aabb900101hdfcdf09", "f")))
        self.assertFalse(list(d.buscar("curp: hegg560427mvzrrl04", "f")),
                         "la clave de muestra sigue exenta en minúsculas")

    def test_rfc_en_minusculas(self):
        d = self._det("rfc")
        self.assertTrue(list(d.buscar("rfc gode561231gr8", "f")))
        self.assertFalse(list(d.buscar("rfc xaxx010101000", "f")))

    def test_clabe_agrupada_con_guiones(self):
        """Es el formato en que la imprime un estado de cuenta."""
        d = self._det("clabe")
        self.assertTrue(list(d.buscar("CLABE 0321-8000-0118-3597-19", "f")))
        self.assertFalse(list(d.buscar("CLABE 0321-8000-0118-3597-10", "f")))

    def test_clabe_no_confunde_fechas(self):
        d = self._det("clabe")
        self.assertFalse(list(d.buscar("del 2024-01-15 al 2024-01-16", "f")))

    def test_clabe_no_confunde_ids_largos(self):
        d = self._det("clabe")
        self.assertFalse(list(d.buscar("id 1394832713415360512", "f")))

    def test_nss_exige_contexto(self):
        """Luhn corta el 90%, que no basta: once dígitos también son un folio."""
        d = self._det("nss")
        self.assertTrue(list(d.buscar("NSS del trabajador 92988084494", "f")))
        self.assertFalse(list(d.buscar("folio 92988084494 de la orden", "f")))

    def test_telefono_no_confunde_marca_de_tiempo(self):
        d = self._det("telefono")
        self.assertFalse(list(d.buscar("el timestamp 1754236800", "f")))
        self.assertTrue(list(d.buscar("cel 55 1234 5678", "f")))


class Configuracion(unittest.TestCase):
    def cargar(self, yml: str):
        with TemporaryDirectory() as d:
            (Path(d) / ".garita.yml").write_text(yml, encoding="utf-8")
            return cargar_config(Path(d))

    def test_ruta_con_dos_puntos_no_se_parte(self):
        """«gen.py:PROHIBIDOS» es una ruta, no un mapa: en YAML un mapa exige
        espacio tras los dos puntos. Sin esta regla la fuente se perdía en
        silencio, que es el peor modo de falla de un guardián."""
        c = self.cargar("nombres:\n  - scripts/gen.py:PROHIBIDOS\n")
        self.assertEqual(c.fuentes_nombres, ["scripts/gen.py:PROHIBIDOS"])

    def test_exencion_exige_motivo(self):
        with self.assertRaises(ConfigInvalida):
            self.cargar("exenciones:\n  - archivo: x.md\n")

    def test_exencion_acotada_a_detectores(self):
        c = self.cargar(
            "exenciones:\n"
            "  - archivo: doc.md\n"
            "    motivo: ejemplos oficiales\n"
            "    detectores: curp, rfc\n"
        )
        e = c.exenciones[0]
        self.assertTrue(e.cubre("doc.md", "curp"))
        self.assertFalse(e.cubre("doc.md", "jwt"))

    def test_sin_archivo_apaga_solo_el_de_nombres(self):
        with TemporaryDirectory() as d:
            c = cargar_config(Path(d))
            self.assertFalse(c.activo("nombre"))
            self.assertTrue(c.activo("secretos"))


class DePuntaAPunta(unittest.TestCase):
    def test_repositorio_limpio_pasa(self):
        td = repo_temporal({
            "gen.py": 'PROHIBIDOS = ["Juanito"]\n',
            ".garita.yml": ("nombres:\n  - gen.py:PROHIBIDOS\n"
                            "exenciones:\n  - archivo: gen.py\n"
                            "    motivo: es la fuente\n"),
            "ok.py": "DEUDORES = {47: 5000}\nK = os.environ['X']\n",
        })
        with td:
            raiz = Path(td.name)
            cfg = cargar_config(raiz)
            res = revisar(raiz, construir(cfg, raiz), cfg.exenciones)
            self.assertEqual(res.hallazgos, [], [h.que for h in res.hallazgos])

    def test_detecta_la_liga_nombre_lote(self):
        """El caso que originó la herramienta."""
        td = repo_temporal({
            "gen.py": 'PROHIBIDOS = ["Juanito"]\n',
            ".garita.yml": ("nombres:\n  - gen.py:PROHIBIDOS\n"
                            "exenciones:\n  - archivo: gen.py\n"
                            "    motivo: es la fuente\n"),
            "padron.py": 'LOTES = {47: "Juanito Pérez"}\n',
        })
        with td:
            raiz = Path(td.name)
            cfg = cargar_config(raiz)
            res = revisar(raiz, construir(cfg, raiz), cfg.exenciones)
            self.assertEqual(len(res.errores), 1)
            self.assertEqual(res.errores[0].detector, "nombre")
            self.assertEqual(res.errores[0].archivo, "padron.py")

    def test_no_mira_archivos_sin_rastrear(self):
        """Lo ignorado por git no es problema de esta herramienta: el daño
        empieza al publicar."""
        td = repo_temporal({
            "gen.py": 'PROHIBIDOS = ["Juanito"]\n',
            ".garita.yml": ("nombres:\n  - gen.py:PROHIBIDOS\n"
                            "exenciones:\n  - archivo: gen.py\n"
                            "    motivo: es la fuente\n"),
        })
        with td:
            raiz = Path(td.name)
            (raiz / "borrador.txt").write_text("Juanito Pérez", encoding="utf-8")
            cfg = cargar_config(raiz)
            res = revisar(raiz, construir(cfg, raiz), cfg.exenciones)
            self.assertEqual(res.hallazgos, [])

    def test_exencion_se_aplica(self):
        td = repo_temporal({
            "gen.py": 'PROHIBIDOS = ["Juanito"]\n',
            ".garita.yml": ("nombres:\n  - gen.py:PROHIBIDOS\n"
                            "exenciones:\n"
                            "  - archivo: gen.py\n    motivo: es la fuente\n"
                            "  - archivo: acta.md\n"
                            "    motivo: registro publico de la mesa\n"
                            "    detectores: nombre\n"),
            "acta.md": "Firma Juanito, en su cargo de Secretario.\n",
        })
        with td:
            raiz = Path(td.name)
            cfg = cargar_config(raiz)
            res = revisar(raiz, construir(cfg, raiz), cfg.exenciones)
            self.assertEqual(res.hallazgos, [])
            self.assertIn("acta.md", res.exentos_aplicados)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class RegresionesDeCampo(unittest.TestCase):
    """Falsos positivos hallados corriendo Garita contra diez proyectos
    públicos reales (axios, Chart.js, express, faker, flask, hugo, prettier,
    requests, sinatra, vite — 19,920 archivos). Cada uno rompía el build de
    alguien que no tiene un solo dato personal en su repositorio, que es la
    forma más rápida de que se desinstale la herramienta."""

    def test_prefijo_posesivo_sigue_siendo_marcador(self):
        # axios documenta la autenticación básica con «myUser:myPassword».
        for v in ("myPassword", "myUser", "miClave", "mi_secreto"):
            self.assertTrue(es_marcador(v), v)

    def test_marcador_codificado_en_porcentaje(self):
        # «p%40ss» aparenta seis caracteres y es «p@ss»: cuatro.
        self.assertTrue(es_marcador("p%40ss"))

    def test_una_contrasena_real_codificada_no_se_perdona(self):
        # El arreglo anterior no debe volverse una puerta: decodificar y
        # seguir siendo larga es seguir siendo un secreto.
        self.assertFalse(es_marcador("Kx9mPqR2vNw8%21aB"))

    def test_lada_no_asignada_ya_ni_aparece(self):
        # «tel:484-695-3408» en una prueba de axios es un número de Estados
        # Unidos. Antes salía como aviso porque el 3-3-4 es idéntico al
        # mexicano; con la lista real del PNN, 484 no es una lada asignada
        # y el número simplemente no es un teléfono mexicano.
        d = self._tel()
        for t in ("axios.get('tel:484-695-3408')", "tel: 555-123-4567",
                  "cel 212-555-0123", "contacto: 202 456 1111",
                  "llamar al 206.684.2489"):
            self.assertFalse(list(d.buscar(t, "x")), t)

    def test_lada_no_asignada_con_52_tampoco(self):
        # Un «+52 555…» es un número inventado para una prueba (el 555 es
        # el prefijo ficticio de Norteamérica y no está en el PNN), no una
        # persona alcanzable.
        d = self._tel()
        self.assertFalse(list(d.buscar('TEL = "+52 555 123 4567"', "x")))

    def test_lada_valida_de_tres_digitos_sigue_siendo_aviso(self):
        # 272 (Córdoba) y 961 (Tuxtla) SÍ están asignadas: la coincidencia
        # con un número extranjero es posible, así que se avisa sin
        # afirmar. Forzar el cero aquí sería cegar el detector.
        d = self._tel()
        for t in ("tel: 272-123-4567", "cel 961 123 4567"):
            h = list(d.buscar(t, "x"))
            self.assertTrue(h, t)
            self.assertEqual(h[0].severidad, "aviso", t)

    def test_telefono_con_prefijo_sigue_siendo_error(self):
        d = self._tel()
        h = list(d.buscar('TEL = "+52 55 1234 5678"', "x"))
        self.assertEqual(h[0].severidad, "error")

    def test_lada_inequivocamente_mexicana_con_contexto_es_error(self):
        # 55, 56, 33 y 81 son ladas de dos dígitos: no existen fuera de México.
        d = self._tel()
        h = list(d.buscar("cel 55 1234 5678", "x"))
        self.assertEqual(h[0].severidad, "error")

    def _tel(self):
        from garita.detectores.paises.mx import detectores
        return {d.nombre: d for d in detectores(Config())}["telefono"]


class ExencionesMuertas(unittest.TestCase):
    """Una exención que no aplicó a nada es un renombre silencioso: el archivo
    lleva revisándose sin protección desde que cambió de nombre, y quien
    escribió la regla sigue creyendo que está cubierto."""

    def test_una_exencion_que_no_aplica_se_reporta(self):
        with tempfile.TemporaryDirectory() as d:
            raiz = pathlib.Path(d)
            subprocess.run(["git", "init", "-q"], cwd=raiz, check=True)
            (raiz / "vive.py").write_text("x = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            res = revisar(raiz, [], [
                Exencion(patron="vive.py", motivo="m", detectores=()),
                Exencion(patron="se_borro.py", motivo="m", detectores=()),
            ])
            self.assertEqual(res.exenciones_muertas, ["se_borro.py"])

    def test_revisando_archivos_sueltos_no_acusa_falsamente(self):
        # En el hook de pre-commit sólo llegan los archivos en preparación:
        # que una exención no aplique ahí no dice nada del repositorio.
        with tempfile.TemporaryDirectory() as d:
            raiz = pathlib.Path(d)
            subprocess.run(["git", "init", "-q"], cwd=raiz, check=True)
            (raiz / "a.py").write_text("x = 1\n", encoding="utf-8")
            (raiz / "b.py").write_text("y = 2\n", encoding="utf-8")
            res = revisar(raiz, [], [Exencion("b.py", "m", ())], archivos=["a.py"])
            self.assertEqual(res.exenciones_muertas, [])


class LineaBaseDePuntaAPunta(unittest.TestCase):
    """El modo de adopción: congelar lo que ya estaba y fallar sólo con lo
    nuevo. Se prueba por el CLI porque las promesas de la línea base son
    promesas sobre códigos de salida, y un código de salida sólo se prueba
    de verdad recorriendo el camino completo."""

    # Claves sintéticas con dígito verificador correcto, no personas. Los
    # vectores oficiales (HEGG…, SASO…, ZUNA…) no sirven aquí: el detector
    # los exenta por ser las claves de muestra de RENAPO.
    CURP_VIEJA = "AABB900101HDFCDF09"
    CURP_NUEVA = "CEDD850505MNELTN01"

    def _cli(self, raiz, *argv):
        return correr_garita(raiz, *argv)

    def test_congelar_sale_cero_aunque_haya_hallazgos(self):
        # Está registrando deuda, no reprobando. Y dice cuánto congeló,
        # porque alguien tiene que ver el tamaño de lo que acaba de aceptar.
        td = repo_temporal({"datos.csv": f"curp: {self.CURP_VIEJA}\n"})
        with td:
            raiz = Path(td.name)
            codigo, salida = self._cli(raiz, "--linea-base")
            self.assertEqual(codigo, 0, salida)
            self.assertIn("1 hallazgo", salida)
            self.assertTrue((raiz / ".garita-base.json").is_file())

    def test_congelado_no_reprueba_pero_tampoco_desaparece(self):
        td = repo_temporal({"datos.csv": f"curp: {self.CURP_VIEJA}\n"})
        with td:
            raiz = Path(td.name)
            self._cli(raiz, "--linea-base")
            codigo, salida = self._cli(raiz)
            self.assertEqual(codigo, 0, salida)
            # «Nada que reportar» a secas sería mentir por omisión.
            self.assertIn("nada nuevo", salida.lower())
            self.assertIn("Deuda aceptada", salida)
            self.assertIn("datos.csv", salida)

    def test_hallazgo_nuevo_reprueba_y_solo_el_nuevo_es_error(self):
        td = repo_temporal({"viejo.csv": f"curp: {self.CURP_VIEJA}\n"})
        with td:
            raiz = Path(td.name)
            self._cli(raiz, "--linea-base")
            (raiz / "nuevo.csv").write_text(
                f"curp: {self.CURP_NUEVA}\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            codigo, salida = self._cli(raiz)
            self.assertEqual(codigo, 1, salida)
            self.assertIn("1 error", salida)
            self.assertIn("nuevo.csv", salida)
            # El viejo sigue visible, pero como deuda, no como error.
            self.assertIn("Deuda aceptada", salida)

    def test_deuda_pagada_se_reporta_como_obsoleta(self):
        td = repo_temporal({
            "viejo.csv": f"curp: {self.CURP_VIEJA}\n",
            "otro.csv": f"curp: {self.CURP_NUEVA}\n",
        })
        with td:
            raiz = Path(td.name)
            self._cli(raiz, "--linea-base")
            (raiz / "viejo.csv").unlink()
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            codigo, salida = self._cli(raiz)
            self.assertEqual(codigo, 0, salida)
            self.assertIn("Deuda pagada", salida)
            self.assertIn("viejo.csv", salida)

    def test_archivos_sueltos_no_acusan_deuda_pagada(self):
        # En el hook de pre-commit sólo llegan los archivos en preparación:
        # que la deuda de otro archivo no aparezca ahí no dice que se pagó.
        td = repo_temporal({
            "viejo.csv": f"curp: {self.CURP_VIEJA}\n",
            "limpio.py": "x = 1\n",
        })
        with td:
            raiz = Path(td.name)
            self._cli(raiz, "--linea-base")
            codigo, salida = self._cli(raiz, "limpio.py")
            self.assertEqual(codigo, 0, salida)
            self.assertNotIn("Deuda pagada", salida)

    def test_archivo_roto_es_codigo_2_no_0_ni_1(self):
        td = repo_temporal({"x.py": "x = 1\n"})
        with td:
            raiz = Path(td.name)
            (raiz / ".garita-base.json").write_text("{ roto", encoding="utf-8")
            codigo, salida = self._cli(raiz)
            self.assertEqual(codigo, 2, salida)

    def test_formato_ajeno_es_codigo_2_y_dice_como_regenerar(self):
        td = repo_temporal({"x.py": "x = 1\n"})
        with td:
            raiz = Path(td.name)
            (raiz / ".garita-base.json").write_text(
                json.dumps({"formato": 99, "conteos": {}}), encoding="utf-8")
            codigo, salida = self._cli(raiz)
            self.assertEqual(codigo, 2, salida)
            self.assertIn("--linea-base", salida)

    def test_sin_linea_base_audita_de_verdad(self):
        td = repo_temporal({"datos.csv": f"curp: {self.CURP_VIEJA}\n"})
        with td:
            raiz = Path(td.name)
            self._cli(raiz, "--linea-base")
            codigo, salida = self._cli(raiz, "--sin-linea-base")
            self.assertEqual(codigo, 1, salida)

    def test_el_archivo_generado_no_contiene_el_valor(self):
        """La prueba que impide que alguien «optimice» el formato guardando
        hashes sin leer por qué no: un hash de CURP es un CURP con candado
        de juguete. Ni el valor ni NINGUNA subcadena suya pueden quedar en
        un archivo que se commitea."""
        td = repo_temporal({"datos.csv": f"curp: {self.CURP_VIEJA}\n"})
        with td:
            raiz = Path(td.name)
            self._cli(raiz, "--linea-base")
            contenido = (raiz / ".garita-base.json").read_text(encoding="utf-8")
            self.assertNotIn(self.CURP_VIEJA, contenido)
            for i in range(len(self.CURP_VIEJA) - 5):
                pedazo = self.CURP_VIEJA[i:i + 6]
                self.assertNotIn(pedazo, contenido, pedazo)

    def test_congelar_repo_limpio_no_escribe_archivo(self):
        td = repo_temporal({"x.py": "x = 1\n"})
        with td:
            raiz = Path(td.name)
            codigo, salida = self._cli(raiz, "--linea-base")
            self.assertEqual(codigo, 0, salida)
            self.assertFalse((raiz / ".garita-base.json").exists())

    def test_congelar_no_admite_archivos_sueltos(self):
        # Una línea base parcial perdonaría de menos: reprobaría deuda que
        # sí se aceptó en cuanto se revisara el repo completo.
        td = repo_temporal({"datos.csv": f"curp: {self.CURP_VIEJA}\n"})
        with td:
            raiz = Path(td.name)
            codigo, salida = self._cli(raiz, "--linea-base", "datos.csv")
            self.assertEqual(codigo, 2, salida)


class SalidaSarif(unittest.TestCase):
    """El formato que GitHub convierte en alertas de code scanning.

    No hay validador de esquema porque el repo no tiene dependencias y así
    se queda: se verifica a mano la estructura que la subida a GitHub
    rechaza cuando falta, que es lo que de verdad muerde."""

    CURP = "AABB900101HDFCDF09"
    OTRA = "CEDD850505MNELTN01"

    def _sarif(self, raiz, *argv):
        codigo, salida = correr_garita(raiz, "--formato", "sarif", *argv)
        return codigo, json.loads(salida)

    def test_estructura_que_github_exige(self):
        td = repo_temporal({"datos.csv": f"curp: {self.CURP}\n"})
        with td:
            codigo, doc = self._sarif(Path(td.name))
            self.assertEqual(codigo, 1)  # el formato no cambia el veredicto
            self.assertEqual(doc["version"], "2.1.0")
            self.assertIn("sarif-2.1.0", doc["$schema"])
            run = doc["runs"][0]
            self.assertEqual(run["tool"]["driver"]["name"], "Garita")
            ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
            for res in run["results"]:
                self.assertIn(res["ruleId"], ids)
                self.assertIn(res["level"], ("error", "warning", "note"))
                loc = res["locations"][0]["physicalLocation"]
                self.assertEqual(loc["artifactLocation"]["uri"], "datos.csv")
                self.assertEqual(loc["region"]["startLine"], 1)

    def test_ruleid_por_detector_no_por_hallazgo(self):
        # GitHub agrupa por regla; un ruleId por hallazgo llena la pestaña
        # de reglas de un solo uso.
        td = repo_temporal({
            "a.csv": f"curp: {self.CURP}\n",
            "b.csv": f"curp: {self.OTRA}\n",
        })
        with td:
            _, doc = self._sarif(Path(td.name))
            resultados = doc["runs"][0]["results"]
            self.assertEqual(len(resultados), 2)
            self.assertEqual({r["ruleId"] for r in resultados}, {"curp"})

    def test_ningun_valor_completo_en_el_documento(self):
        # El texto de una alerta lo ve más gente que el repositorio.
        td = repo_temporal({"datos.csv": f"curp: {self.CURP}\n"})
        with td:
            _, salida = correr_garita(Path(td.name), "--formato", "sarif")
            self.assertNotIn(self.CURP, salida)
            for i in range(len(self.CURP) - 5):
                self.assertNotIn(self.CURP[i:i + 6], salida)

    def test_la_huella_sigue_al_hallazgo_cuando_se_mueven_lineas(self):
        # partialFingerprints existe exactamente para esto. Y aplica la
        # misma regla que la línea base: nada derivado del valor.
        td = repo_temporal({"datos.csv": f"curp: {self.CURP}\n"})
        with td:
            raiz = Path(td.name)
            _, doc1 = self._sarif(raiz)
            (raiz / "datos.csv").write_text(
                f"\n\n\n\ncurp: {self.CURP}\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            _, doc2 = self._sarif(raiz)
            huella = lambda d: d["runs"][0]["results"][0]["partialFingerprints"]
            self.assertEqual(huella(doc1), huella(doc2))
            self.assertNotEqual(
                doc1["runs"][0]["results"][0]["locations"],
                doc2["runs"][0]["results"][0]["locations"])

    def test_deuda_aceptada_sale_como_note(self):
        td = repo_temporal({"datos.csv": f"curp: {self.CURP}\n"})
        with td:
            raiz = Path(td.name)
            correr_garita(raiz, "--linea-base")
            codigo, doc = self._sarif(raiz)
            self.assertEqual(codigo, 0)
            r = doc["runs"][0]["results"][0]
            self.assertEqual(r["level"], "note")
            self.assertIn("deuda aceptada", r["message"]["text"])

    def test_salida_escribe_el_archivo_y_la_consola_queda_humana(self):
        td = repo_temporal({"datos.csv": f"curp: {self.CURP}\n"})
        with td:
            raiz = Path(td.name)
            codigo, salida = correr_garita(
                raiz, "--formato", "sarif", "--salida", "reporte.sarif")
            self.assertEqual(codigo, 1)
            doc = json.loads((raiz / "reporte.sarif").read_text(encoding="utf-8"))
            self.assertEqual(doc["version"], "2.1.0")
            self.assertIn("datos.csv", salida)  # el reporte humano sigue

    def test_en_github_stdout_sigue_siendo_json_puro(self):
        # Las anotaciones ::error irían al mismo stdout que el documento y
        # lo corromperían.
        td = repo_temporal({"datos.csv": f"curp: {self.CURP}\n"})
        with td:
            antes = os.environ.get("GITHUB_ACTIONS")
            os.environ["GITHUB_ACTIONS"] = "true"
            try:
                _, salida = correr_garita(Path(td.name), "--formato", "sarif")
                json.loads(salida)  # truena si algo más se coló
            finally:
                if antes is None:
                    del os.environ["GITHUB_ACTIONS"]
                else:
                    os.environ["GITHUB_ACTIONS"] = antes

    def test_salida_sin_sarif_es_error_de_uso(self):
        td = repo_temporal({"x.py": "x = 1\n"})
        with td:
            codigo, _ = correr_garita(Path(td.name), "--salida", "r.txt")
            self.assertEqual(codigo, 2)


def _cargar_ejecutar():
    """El envoltorio de la Action no es un paquete; se carga por ruta."""
    import importlib.util
    ruta = AQUI.parent / "scripts" / "ejecutar.py"
    spec = importlib.util.spec_from_file_location("ejecutar", ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SoloCambios(unittest.TestCase):
    """El modo que más gente va a usar en un pull request y que hasta ahora
    era una promesa sin respaldo: `action.yml` exponía el input sin una sola
    prueba."""

    CURP = "AABB900101HDFCDF09"
    GIT = ["git", "-c", "user.name=prueba", "-c", "user.email=p@ej.mx"]

    def _pr(self, en_main: dict, cambios_en_pr):
        """Un origen con rama main y un clon con rama de pull request.

        Devuelve (TemporaryDirectory, ruta_del_clon). `cambios_en_pr` es una
        función que recibe la raíz del clon y hace ahí lo que haría el PR.
        """
        td = TemporaryDirectory()
        base = Path(td.name)
        origen = base / "origen"
        origen.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=origen, check=True)
        for rel, contenido in en_main.items():
            p = origen / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(contenido, encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=origen, check=True)
        subprocess.run(self.GIT + ["commit", "-q", "-m", "main"],
                       cwd=origen, check=True)
        clon = base / "clon"
        subprocess.run(["git", "clone", "-q", str(origen), str(clon)], check=True)
        subprocess.run(["git", "checkout", "-q", "-b", "pr"], cwd=clon, check=True)
        cambios_en_pr(clon)
        subprocess.run(["git", "add", "-A"], cwd=clon, check=True)
        subprocess.run(self.GIT + ["commit", "-q", "-m", "pr"],
                       cwd=clon, check=True)
        return td, clon

    def _archivos_del_pr(self, clon):
        ejecutar = _cargar_ejecutar()
        antes = Path.cwd()
        os.chdir(clon)
        try:
            return ejecutar.archivos_del_pr({"GITHUB_BASE_REF": "main"})
        finally:
            os.chdir(antes)

    def test_solo_revisa_los_archivos_del_diff(self):
        def pr(clon):
            (clon / "limpio.py").write_text("y = 2\n", encoding="utf-8")
            (clon / "nuevo.md").write_text("hola\n", encoding="utf-8")
        td, clon = self._pr({"limpio.py": "x = 1\n", "otro.py": "z = 3\n"}, pr)
        with td:
            self.assertEqual(set(self._archivos_del_pr(clon)),
                             {"limpio.py", "nuevo.md"})

    def test_hallazgo_en_archivo_no_tocado_no_truena_el_build(self):
        # La promesa central del modo: el PR que no tocó la deuda vieja no
        # carga con ella. (Y su costo, documentado: es ciego a lo que ya
        # estaba — por eso se usa junto a una revisión completa.)
        def pr(clon):
            (clon / "limpio.py").write_text("y = 2\n", encoding="utf-8")
        td, clon = self._pr(
            {"limpio.py": "x = 1\n", "sucio.csv": f"curp: {self.CURP}\n"}, pr)
        with td:
            cambios = self._archivos_del_pr(clon)
            self.assertEqual(cambios, ["limpio.py"])
            codigo, salida = correr_garita(clon, *cambios)
            self.assertEqual(codigo, 0, salida)
            codigo, _ = correr_garita(clon)   # la revisión completa sí lo ve
            self.assertEqual(codigo, 1)

    def test_archivo_renombrado_se_revisa_por_su_ruta_nueva(self):
        def pr(clon):
            (clon / "datos").mkdir()
            subprocess.run(["git", "mv", "viejo.csv", "datos/renombrado.csv"],
                           cwd=clon, check=True)
        td, clon = self._pr({"viejo.csv": f"curp: {self.CURP}\n"}, pr)
        with td:
            cambios = self._archivos_del_pr(clon)
            self.assertEqual(cambios, ["datos/renombrado.csv"])
            codigo, salida = correr_garita(clon, *cambios)
            self.assertEqual(codigo, 1, salida)
            self.assertIn("datos/renombrado.csv", salida)

    def test_solo_cambios_no_pisa_el_config(self):
        # Regresión: `argv = cambios` tiraba el `--config` ya acumulado y la
        # opción documentada volvía a ser inoperante, ahora en modo
        # solo-cambios.
        def pr(clon):
            (clon / "limpio.py").write_text("y = 2\n", encoding="utf-8")
        td, clon = self._pr({"limpio.py": "x = 1\n"}, pr)
        with td:
            ejecutar = _cargar_ejecutar()
            antes = Path.cwd()
            os.chdir(clon)
            try:
                argv = ejecutar.argumentos({
                    "GITHUB_BASE_REF": "main",
                    "GARITA_CONFIG": "otra.yml",
                    "GARITA_SOLO_CAMBIOS": "true",
                })
            finally:
                os.chdir(antes)
            self.assertEqual(argv[:2], ["--config", "otra.yml"])
            self.assertIn("limpio.py", argv)
