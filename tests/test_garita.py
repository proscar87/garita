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

import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

AQUI = Path(__file__).resolve().parent
sys.path.insert(0, str(AQUI.parent / "src"))

from garita.config import ConfigInvalida, cargar as cargar_config  # noqa: E402
from garita.detectores import construir                            # noqa: E402
from garita.detectores.secretos import buscar, buscar_asignaciones # noqa: E402
from garita.fuentes import FuenteInvalida, a_patron, cargar        # noqa: E402
from garita.detectores.paises.mx import (                             # noqa: E402
    clabe_valida, curp_valido, nss_valido, rfc_valido,
)
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
