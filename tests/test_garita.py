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
        # La de muestra de la ABM quedó exenta; se usa una sintética.
        self.assertTrue(list(d.buscar("CLABE 0021-8000-0000-0010-08", "f")))
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


class Historial(unittest.TestCase):
    """El caso que duele: el secreto commiteado hace tres meses y «borrado»
    al día siguiente. La revisión normal no lo ve; el historial sí — y el
    reporte tiene que decir que borrar el archivo no borró el dato."""

    CURP = "AABB900101HDFCDF09"
    OTRA = "CEDD850505MNELTN01"

    def _commit(self, raiz, mensaje):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                        "commit", "-q", "-m", mensaje], cwd=raiz, check=True)

    def _repo(self):
        """main con: commit 1 (secreto.py + limpio.py), commit 2 (borra
        secreto.py), commit 3 (vivo.csv). Devuelve (td, raiz)."""
        td = TemporaryDirectory()
        raiz = Path(td.name)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=raiz, check=True)
        (raiz / "secreto.py").write_text(
            f"curp: {self.CURP}\n", encoding="utf-8")
        (raiz / "limpio.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
        self._commit(raiz, "inicio")
        subprocess.run(["git", "rm", "-q", "secreto.py"], cwd=raiz, check=True)
        self._commit(raiz, "borra el secreto (cree)")
        (raiz / "vivo.csv").write_text(f"curp: {self.OTRA}\n", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
        self._commit(raiz, "dato vivo")
        return td, raiz

    def test_el_secreto_borrado_aparece_y_dice_que_ya_no_esta(self):
        td, raiz = self._repo()
        with td:
            codigo, normal = correr_garita(raiz)
            self.assertNotIn("secreto.py", normal)  # la normal no lo ve
            codigo, salida = correr_garita(raiz, "--historial")
            self.assertEqual(codigo, 1, salida)
            self.assertIn("Sólo en el historial", salida)
            self.assertIn("secreto.py", salida)
            self.assertIn("no borró el dato", salida)
            self.assertIn("git-filter-repo", salida)

    def test_lo_vivo_se_marca_como_vivo(self):
        td, raiz = self._repo()
        with td:
            _, salida = correr_garita(raiz, "--historial")
            self.assertIn("Todavía en el árbol", salida)
            despues = salida.index("Todavía en el árbol")
            self.assertIn("vivo.csv", salida[despues:])
            self.assertNotIn("vivo.csv", salida[:despues])

    def test_reporta_el_commit_que_lo_introdujo(self):
        td, raiz = self._repo()
        with td:
            primero = subprocess.run(
                ["git", "rev-list", "--max-parents=0", "HEAD"],
                cwd=raiz, capture_output=True, check=True,
            ).stdout.decode().strip()[:10]
            _, salida = correr_garita(raiz, "--historial")
            self.assertIn(f"commit {primero}", salida)

    def test_historial_limpio_sale_cero(self):
        td = TemporaryDirectory()
        raiz = Path(td.name)
        with td:
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=raiz, check=True)
            (raiz / "limpio.py").write_text("x = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            self._commit(raiz, "inicio")
            codigo, salida = correr_garita(raiz, "--historial")
            self.assertEqual(codigo, 0, salida)
            self.assertIn("historial está limpio", salida)

    def test_exencion_de_hoy_aplica_a_la_ruta_historica(self):
        # Mismas reglas que el motor normal: dos motores con reglas
        # distintas darían dos verdades distintas.
        td, raiz = self._repo()
        with td:
            (raiz / ".garita.yml").write_text(
                "exenciones:\n"
                "  - archivo: secreto.py\n"
                "    motivo: datos sinteticos de una demo\n"
                "    detectores: curp\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            self._commit(raiz, "config")
            _, salida = correr_garita(raiz, "--historial")
            self.assertNotIn("secreto.py", salida)
            self.assertIn("vivo.csv", salida)  # el resto sigue vivo

    def test_no_admite_archivos_sueltos_ni_linea_base(self):
        td, raiz = self._repo()
        with td:
            for argv in (("--historial", "limpio.py"),
                         ("--historial", "--linea-base"),
                         ("--historial", "--sin-linea-base")):
                codigo, salida = correr_garita(raiz, *argv)
                self.assertEqual(codigo, 2, (argv, salida))

    def test_historial_habla_sarif(self):
        # La alerta apunta a la ruta HISTÓRICA (que puede ya no existir) y
        # el mensaje carga el commit; la huella es commit+ruta+regla+ordinal
        # — el historial es inmutable, así que identifica al hallazgo para
        # siempre sin derivar nada del valor.
        td, raiz = self._repo()
        with td:
            codigo, salida = correr_garita(raiz, "--historial",
                                           "--formato", "sarif")
            self.assertEqual(codigo, 1, salida)
            doc = json.loads(salida)
            self.assertEqual(doc["version"], "2.1.0")
            resultados = doc["runs"][0]["results"]
            muerto = next(r for r in resultados
                          if r["locations"][0]["physicalLocation"]
                          ["artifactLocation"]["uri"] == "secreto.py")
            self.assertIn("SÓLO EN EL HISTORIAL", muerto["message"]["text"])
            self.assertIn("commit", muerto["message"]["text"])
            huella = muerto["partialFingerprints"]["garitaHistorial/v1"]
            self.assertIn("secreto.py::curp", huella)
            for i in range(len(self.CURP) - 5):
                self.assertNotIn(self.CURP[i:i + 6], salida)

    def test_blob_grande_del_pasado_se_dice_no_se_calla(self):
        td = TemporaryDirectory()
        raiz = Path(td.name)
        with td:
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=raiz, check=True)
            (raiz / "volcado.csv").write_text(
                "x" * 2_100_000, encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            self._commit(raiz, "volcado")
            subprocess.run(["git", "rm", "-q", "volcado.csv"], cwd=raiz, check=True)
            self._commit(raiz, "lo borra")
            _, salida = correr_garita(raiz, "--historial")
            self.assertIn("Sin revisar por tamaño", salida)
            self.assertIn("volcado.csv", salida)


class RegresionesDelHistorial(unittest.TestCase):
    """Falsos positivos que salieron al auditar historiales completos de
    proyectos reales (requests: 307 antes de esto, 5 después). El pasado de
    un repo grande es un muestrario de layouts que ya no se usan."""

    def test_archivo_de_prueba_por_nombre_no_solo_por_carpeta(self):
        # test_requests.py vivió años en la RAÍZ de requests, con cientos de
        # credenciales de broma. La carpeta tests/ no lo cubría.
        from garita.nucleo import es_de_prueba
        for ruta in ("test_requests.py", "src/foo_test.go",
                     "web/boton.spec.ts", "lib/util.test.js", "conftest.py"):
            self.assertTrue(es_de_prueba(ruta), ruta)
        for ruta in ("requests/models.py", "protesta.py", "attest.py",
                     "src/testigo.py"):
            self.assertFalse(es_de_prueba(ruta), ruta)

    def test_prueba_por_nombre_relaja_secretos_pero_no_pii(self):
        td = repo_temporal({
            "test_api.py": ('URL = "postgres://admin:Kx9mPqR2vNw8@h:5432/d"\n'
                            "curp: AABB900101HDFCDF09\n"),
        })
        with td:
            raiz = Path(td.name)
            cfg = cargar_config(raiz)
            res = revisar(raiz, construir(cfg, raiz), cfg.exenciones)
            detectores = {h.detector for h in res.hallazgos}
            self.assertNotIn("credencial_en_url", detectores)
            self.assertIn("curp", detectores)  # un dato personal sigue siéndolo

    def test_bundle_de_ca_calla_identificadores_pero_no_llaves(self):
        # El cacert.pem de requests trae el CIF real de Camerfirma en el
        # asunto de sus certificados: público POR DISEÑO. Pero un bundle
        # mal armado puede traer la llave privada concatenada, y ésa suena.
        td = repo_temporal({
            "cacert.pem": ("# Subject: CN=Chambers of Commerce Root, "
                           "CIF A12345674\n"
                           "-----BEGIN RSA PRIVATE KEY-----\nabc\n"),
        })
        with td:
            raiz = Path(td.name)
            cfg = cargar_config(raiz)
            res = revisar(raiz, construir(cfg, raiz), cfg.exenciones)
            detectores = {h.detector for h in res.hallazgos}
            self.assertNotIn("cif", detectores)
            self.assertIn("llave_privada", detectores)

    def test_cpf_pelon_exige_que_lo_nombren(self):
        # idnadata.py de requests: una tabla unicode con un número de once
        # dígitos que pasa el módulo 11 por azar (uno de cada cien lo hace).
        from garita.detectores.paises.br import detectores as br
        d = {x.nombre: x for x in br(Config())}["cpf"]
        self.assertFalse(list(d.buscar("rango = (11144477735, 4)", "x")))
        self.assertTrue(list(d.buscar("cpf: 11144477735", "x")))
        self.assertTrue(list(d.buscar("titular 111.444.777-35", "x")))

    def test_la_clabe_de_muestra_de_la_banca_no_dispara(self):
        # La del instructivo de la ABM, que el propio historial de Garita
        # cargaba en la ruta vieja del módulo. Es la llave de ejemplo de
        # AWS en versión mexicana: documentación, no la cuenta de nadie.
        from garita.detectores.paises.mx import detectores as mx
        d = {x.nombre: x for x in mx(Config())}["clabe"]
        self.assertFalse(list(d.buscar("CLABE 032180000118359719", "x")))
        # Y la detección sigue viva: una CLABE válida cualquiera sí suena.
        self.assertTrue(list(d.buscar("CLABE 002180000000001008", "x")))


class ReporteHtml(unittest.TestCase):
    """El reporte gráfico autocontenido: el entregable para quien no vive
    ni en la terminal ni en GitHub."""

    CURP = "AABB900101HDFCDF09"

    def test_emite_html_y_el_veredicto_no_cambia(self):
        td = repo_temporal({"datos.csv": f"curp: {self.CURP}\n"})
        with td:
            codigo, salida = correr_garita(Path(td.name), "--formato", "html")
            self.assertEqual(codigo, 1)  # el formato no cambia el veredicto
            self.assertTrue(salida.startswith("<!doctype html>"))
            self.assertIn("Hallazgos por detector", salida)

    def test_ningun_valor_ni_peticion_externa(self):
        # Un reporte de seguridad que llama a un CDN al abrirse filtra a
        # terceros cuándo y dónde se lee. Y el valor completo, jamás.
        td = repo_temporal({"datos.csv": f"curp: {self.CURP}\n"})
        with td:
            _, salida = correr_garita(Path(td.name), "--formato", "html")
            for i in range(len(self.CURP) - 5):
                self.assertNotIn(self.CURP[i:i + 6], salida)
            import re
            self.assertFalse(
                re.findall(r'(?:src|href)="http', salida), "peticiones externas")

    def test_salida_escribe_archivo_y_la_consola_queda_humana(self):
        td = repo_temporal({"datos.csv": f"curp: {self.CURP}\n"})
        with td:
            raiz = Path(td.name)
            codigo, salida = correr_garita(
                raiz, "--formato", "html", "--salida", "reporte.html")
            self.assertEqual(codigo, 1)
            self.assertIn("<!doctype html>",
                          (raiz / "reporte.html").read_text(encoding="utf-8"))
            self.assertIn("datos.csv", salida)  # el reporte humano sigue

    def test_historial_tambien_habla_html(self):
        td = repo_temporal({"x.py": "x = 1\n"})
        with td:
            raiz = Path(td.name)
            (raiz / "secreto.csv").write_text(
                f"curp: {self.CURP}\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                            "commit", "-q", "-m", "entra"], cwd=raiz, check=True)
            subprocess.run(["git", "rm", "-q", "secreto.csv"], cwd=raiz, check=True)
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                            "commit", "-q", "-m", "lo borra"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz, "--historial",
                                           "--formato", "html")
            self.assertEqual(codigo, 1)
            self.assertIn("Sólo en el historial", salida)
            self.assertIn("git-filter-repo", salida)
            for i in range(len(self.CURP) - 5):
                self.assertNotIn(self.CURP[i:i + 6], salida)


class Clientes(unittest.TestCase):
    """La lista de clientes: nació de un caso real — un case study que
    nombraba al cliente, su dominio y el serial de su appliance en un repo
    cuya propia convención era el alias por sector. Mismo diseño de
    una-sola-lista que los nombres de personas."""

    def _repo(self):
        return repo_temporal({
            "clientes.txt": "AcmeCorp\nacme.edu.mx\n1506209900112233\n",
            ".garita.yml": ("clientes:\n  - clientes.txt\n"
                            "exenciones:\n  - archivo: clientes.txt\n"
                            "    motivo: es la fuente de la lista\n"
                            "    detectores: cliente\n"),
        })

    def _revisa(self, raiz):
        cfg = cargar_config(raiz)
        return revisar(raiz, construir(cfg, raiz), cfg.exenciones)

    def test_detecta_nombre_dominio_y_serial(self):
        td = self._repo()
        with td:
            raiz = Path(td.name)
            (raiz / "caso.md").write_text(
                "# Caso AcmeCorp\nhost: gm1.acme.edu.mx\n"
                "serial 1506209900112233\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            res = self._revisa(raiz)
            self.assertEqual(len(res.hallazgos), 3, [h.que for h in res.hallazgos])
            self.assertEqual({h.detector for h in res.hallazgos}, {"cliente"})

    def test_no_casa_dentro_de_otra_palabra(self):
        td = self._repo()
        with td:
            raiz = Path(td.name)
            (raiz / "nota.md").write_text(
                "estudiamos el caso de acmecorporativo\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            res = self._revisa(raiz)
            self.assertEqual(res.hallazgos, [], [h.que for h in res.hallazgos])

    def test_ignora_mayusculas(self):
        td = self._repo()
        with td:
            raiz = Path(td.name)
            (raiz / "caso.md").write_text("cliente: ACMECORP\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            res = self._revisa(raiz)
            self.assertEqual(len(res.hallazgos), 1)

    def test_el_historial_tambien_lo_ve(self):
        td = self._repo()
        with td:
            raiz = Path(td.name)
            (raiz / "caso.md").write_text("# Caso AcmeCorp\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                            "commit", "-q", "-m", "caso"], cwd=raiz, check=True)
            subprocess.run(["git", "rm", "-q", "caso.md"], cwd=raiz, check=True)
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                            "commit", "-q", "-m", "lo borra"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz, "--historial")
            self.assertEqual(codigo, 1, salida)
            self.assertIn("cliente", salida)
            self.assertIn("Sólo en el historial", salida)

    def test_sin_lista_el_detector_no_existe(self):
        td = repo_temporal({"x.md": "AcmeCorp por todos lados\n"})
        with td:
            raiz = Path(td.name)
            res = self._revisa(raiz)
            self.assertEqual(res.hallazgos, [])


class PaisesNuevos(unittest.TestCase):
    """EE.UU., Canadá, Portugal y Uruguay. Cada validación contra su fuente
    oficial; el SSN es el primer identificador SIN dígito verificador del
    proyecto, y estrena la regla de contexto obligatorio."""

    def _det(self, nombre):
        from garita.detectores.paises import cargar
        return {d.nombre: d for d in cargar(Config())}[nombre]

    # ── SSN ──
    def test_ssn_estructura_ssa(self):
        from garita.detectores.paises.us import ssn_valido
        self.assertTrue(ssn_valido("531882074"))
        for malo in ("000882074", "666882074", "900882074",
                     "531002074", "531880000"):
            self.assertFalse(ssn_valido(malo), malo)

    def test_ssn_exige_contexto_siempre(self):
        # Sin verificador, el formato no basta: 3-2-4 con guiones también
        # es un número de parte. La palabra que lo nombre es obligatoria.
        d = self._det("ssn")
        self.assertTrue(list(d.buscar("SSN: 531-88-2074", "x")))
        self.assertFalse(list(d.buscar("parte 531-88-2074 agotada", "x")))

    def test_ssn_el_de_la_cartera_de_woolworth_no_dispara(self):
        d = self._det("ssn")
        self.assertFalse(list(d.buscar("ssn de ejemplo: 078-05-1120", "x")))

    # ── SIN ──
    def test_sin_luhn_y_regiones(self):
        from garita.detectores.paises.ca import sin_valido
        self.assertTrue(sin_valido("730425618"))
        self.assertFalse(sin_valido("730425619"))
        # La CRA usa 046 454 286 de ejemplo PORQUE la región 0 no se asigna.
        self.assertFalse(sin_valido("046454286"))
        self.assertFalse(sin_valido("830425618"))

    def test_sin_pelon_exige_que_lo_nombren(self):
        d = self._det("sin_ca")
        self.assertTrue(list(d.buscar("SIN 730 425 618", "x")))
        self.assertFalse(list(d.buscar("folio=730425618", "x")))

    # ── NIF ──
    def test_nif_modulo_11(self):
        from garita.detectores.paises.pt import nif_valido
        self.assertTrue(nif_valido("203456785"))
        self.assertFalse(nif_valido("203456784"))

    def test_nif_placeholder_universal_exento(self):
        d = self._det("nif_pt")
        self.assertFalse(list(d.buscar("NIF: 123456789", "x")))
        self.assertTrue(list(d.buscar("NIF: 203456785", "x")))

    # ── CI Uruguay ──
    def test_ci_digito_verificador(self):
        from garita.detectores.paises.uy import ci_valida
        self.assertTrue(ci_valida("47329580"))
        self.assertFalse(ci_valida("47329581"))

    def test_ci_formato_oficial_dispara_y_repetidos_no(self):
        d = self._det("ci_uy")
        self.assertTrue(list(d.buscar("cédula 4.732.958-0", "x")))
        self.assertFalse(list(d.buscar("cédula 1.111.111-1", "x")))

    def test_acotar_paises_sigue_funcionando(self):
        from garita.detectores.paises import cargar
        nombres = {d.nombre for d in cargar(Config(paises=["us", "uy"]))}
        self.assertEqual(nombres, {"ssn", "ci_uy"})

    def test_grupos_de_tres_digitos_no_son_identificadores(self):
        # Los dos falsos que hugo destapó en la primera corrida: un slice
        # de una plantilla valida como NIF y una ruta SVG de KaTeX pasa
        # Luhn. El espacio como «formato» es señal demasiado débil para un
        # solo dígito verificador; por eso SIN y NIF exigen contexto.
        self.assertFalse(list(self._det("nif_pt").buscar(
            "{{ $shades := slice 300 400 500 }}", "x")))
        self.assertFalse(list(self._det("sin_ca").buscar(
            "m8 0v40h399730v-40zm0 194v40h399730v-40zM399738 392l", "x")))

    def test_la_preposicion_sin_no_es_contexto(self):
        # «sin» es la preposición más común del español: con ella de
        # gatillo, cualquier repo hispano con un grupo de nueve dígitos
        # que pase Luhn dispararía. Las siglas van en mayúsculas o no
        # cuentan.
        d = self._det("sin_ca")
        self.assertFalse(list(d.buscar(
            "quedó sin 730 425 618 pesos en la cuenta", "x")))
        self.assertTrue(list(d.buscar("SIN 730 425 618", "x")))


class FuentesOpcionales(unittest.TestCase):
    """El prefijo «?»: una lista que vive gitignoreada en las máquinas que
    la necesitan (la lista de clientes de un repo de consultoría, que
    volver a escribir en el repo re-filtraría los nombres). Ausente se
    tolera AVISANDO; rota truena igual que siempre."""

    def test_ausente_avisa_y_no_truena(self):
        td = repo_temporal({
            "x.md": "AcmeCorp por todos lados\n",
            ".garita.yml": "clientes:\n  - '?clientes.txt'\n",
        })
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 0, salida)
            self.assertIn("lista opcional", salida)
            self.assertIn("clientes.txt", salida)

    def test_presente_funciona_igual(self):
        td = repo_temporal({
            "x.md": "el caso AcmeCorp\n",
            "clientes.txt": "AcmeCorp\n",
            ".garita.yml": ("clientes:\n  - '?clientes.txt'\n"
                            "exenciones:\n  - archivo: clientes.txt\n"
                            "    motivo: fuente de la lista\n"
                            "    detectores: cliente\n"),
        })
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 1, salida)
            self.assertNotIn("lista opcional", salida)

    def test_presente_pero_rota_truena(self):
        # Opcional tolera la ausencia, jamás la corrupción: aprobar con la
        # lista que se creyó leer aprobaría hallazgos nuevos.
        td = repo_temporal({
            "clientes.txt": "",
            ".garita.yml": "clientes:\n  - '?clientes.txt'\n",
        })
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 2, salida)

    def test_obligatoria_ausente_sigue_tronando(self):
        td = repo_temporal({
            ".garita.yml": "clientes:\n  - clientes.txt\n",
        })
        with td:
            codigo, _ = correr_garita(Path(td.name))
            self.assertEqual(codigo, 2)
