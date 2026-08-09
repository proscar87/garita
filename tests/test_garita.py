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
import unittest.mock
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
        self.assertTrue(self.detecta("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qWeRtY"))

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
            "tests/certs/server.key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qWeRtY\n",
            "src/real.key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qWeRtY\n",
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


class CalibracionDeSecretos(unittest.TestCase):
    """v0.9.0: cuatro maneras de aprobar en silencio, cerradas.

    Descartar un secreto real porque contiene «tu» como subcadena, no
    reconocer los prefijos vigentes de proveedor, exigir usuario en la URL,
    y cortar en la primera asignación de la línea.
    """

    def test_secreto_real_con_tu_dentro_ya_no_se_descarta(self):
        # «VirtualPass2024» contiene «tu» en «Virtual»; el .search sin
        # fronteras lo trataba como placeholder y la URL pasaba limpia.
        self.assertFalse(es_marcador("VirtualPass2024"))
        self.assertTrue(list(buscar(
            "postgres://app:VirtualPass2024@db.interno:5432/prod", "x")))

    def test_marcador_incrustado_entre_letras_ya_no_absuelve(self):
        # base64 aleatorio puede contener «fake» por azar, flanqueado
        # de letras: eso no vuelve ejemplo a la llave.
        self.assertFalse(es_marcador("QmXfakeR7tZw2LpXc8vN"))

    def test_el_posesivo_como_valor_entero_sigue_exento(self):
        for v in ("tu_clave", "tu-api-key-aqui", "tuclave123",
                  "your_password_here", "TU_TOKEN_AQUI", "yourkey12345"):
            self.assertTrue(es_marcador(v), v)

    def test_marcador_tras_digito_sigue_contando(self):
        # La llave canónica de la documentación de AWS: su «EXAMPLE» va
        # pegado a un dígito y cierra el valor. Sigue siendo ejemplo.
        self.assertTrue(es_marcador("AKIAIOSFODNN7EXAMPLE"))

    def test_formatos_vigentes_de_proveedor(self):
        # Las de Stripe se arman por concatenación: con el literal completo
        # en el archivo, la push protection de GitHub (con razón) no deja
        # subir esta prueba. El cuerpo es el de la documentación de Stripe.
        stripe = "4eC39HqLyjWDarjtT1zdp7dc"
        for t in ("sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z",   # OpenAI
                  "sk-svcacct-Ab3dEf6hIj9kLm2nOp5qRs8t",
                  "sk_live_" + stripe,
                  "rk_live_" + stripe,
                  "gho_16C7e42F292c6912E7710c838347Ae178B4a",   # GitHub OAuth
                  "npm_16C7e42F292c6912E7710c838347Ae178B4a"):
            self.assertTrue(list(buscar(f"KEY = '{t}'", "x")), t)

    def test_el_formato_legado_sigue_detectandose(self):
        self.assertTrue(list(buscar("k = 'sk-QwErTyUiOpAsDfGhJkLzXcVb'", "x")))

    def test_clase_css_de_esqueleto_no_es_llave(self):
        # Por esto el `sk-` pelón sigue exigiendo alfanumérico puro.
        self.assertFalse(list(buscar('class="sk-loading-spinner-grande"', "x")))

    def test_placeholder_con_prefijo_vigente_sigue_exento(self):
        self.assertFalse(list(buscar(
            "OPENAI_API_KEY=sk-proj-your_api_key_goes_here", "x")))

    def test_url_sin_usuario_pero_con_contrasena(self):
        # `redis://:contraseña@host` es la forma normal de redis y
        # memcached; exigir usuario la dejaba pasar limpia.
        self.assertTrue(list(buscar(
            "REDIS_URL=redis://:Kx9mPqR2vNw8@cache.interno:6379", "x")))

    def test_url_sin_contrasena_sigue_limpia(self):
        self.assertFalse(list(buscar("redis://cache.interno:6379/0", "x")))

    def test_dos_asignaciones_en_una_linea(self):
        # `search` cortaba en la primera; si era un marcador, el `continue`
        # se tragaba la línea entera con la credencial real que seguía.
        hs = list(buscar_asignaciones(
            'password = "your_password_here"; token = "Kx9mPqR2vNw8LtY4Qz"',
            "x"))
        self.assertEqual(1, len(hs))
        self.assertIn("Kx9m", hs[0].que)


class SilenciosDeMarcadores(unittest.TestCase):
    """v0.13.0: la segunda oleada encontró cuatro maneras nuevas de callar.

    Un refresh token más largo que su cuantificador, un posesivo que
    absolvía cualquier palabra, un marcador flotando entre dígitos, y la
    regresión inversa: los placeholders camelCase que dejaron de absolverse.
    """

    def test_refresh_token_de_github_de_76_caracteres(self):
        # ghp_/gho_/ghs_/ghu_ miden 36 tras el prefijo; los ghr_ vigentes
        # miden 76 y el {36} exacto con \b los dejaba pasar todos.
        self.assertTrue(list(buscar("token = ghr_" + "Ab12" * 19, "x")))
        # Las variantes de 36 siguen casando con la cota inferior.
        self.assertTrue(list(buscar("t = ghp_" + "A" * 30 + "123456", "x")))

    def test_empezar_por_tu_no_vuelve_marcador_al_valor(self):
        # El \w+ pelón del posesivo absolvía «Turquesa9Fuerte42x» entero;
        # una contraseña que arranque en «Tu» salía limpia de la URL.
        self.assertFalse(es_marcador("Turquesa9Fuerte42x"))
        self.assertTrue(list(buscar(
            "postgres://admin:Turbina88Xk@db.prod.interno:5432/app", "x")))

    def test_el_posesivo_con_sustantivo_de_marcador_sigue_exento(self):
        for v in ("tuclave", "your_token", "TU_PASSWORD_DE_DEV",
                  "tu_contrasena", "yourkey123"):
            self.assertTrue(es_marcador(v), v)

    def test_marcador_entre_digitos_no_absuelve_la_llave(self):
        # La excepción pensada para AKIAIOSFODNN7EXAMPLE se había
        # generalizado: cualquier «fake» o «EXAMPLE» entre dígitos dentro
        # de una llave con formato de proveedor la absolvía.
        self.assertTrue(list(buscar(
            "OPENAI_API_KEY=sk-Ab3Ru8Kp0Zw9fake2Xy7Qm4Rt8Kp", "x")))
        self.assertTrue(list(buscar("AKIA2EXAMPLE3XVWQP4J", "x")))
        # La canónica de AWS sigue exenta: su marcador cierra el valor.
        self.assertTrue(es_marcador("AKIAIOSFODNN7EXAMPLE"))

    def test_placeholder_camelcase_vuelve_a_absolverse(self):
        # Regresión de v0.9.0: la frontera no reconocía la transición
        # minúscula→Mayúscula, el estilo de media documentación JS/Java.
        for v in ("DummyPassword1234", "FakeApiKey12345678",
                  "ExampleTokenValue1"):
            self.assertTrue(es_marcador(v), v)
        self.assertFalse(list(buscar_asignaciones(
            'password = "DummyPassword1234"', "x")))
        # Y lo que nunca fue placeholder sigue sin absolverse.
        self.assertFalse(es_marcador("VirtualPass2024"))
        self.assertFalse(es_marcador("kR9mQz2Xv7Lp4Wn8"))


class LoQueElMotorNoLeia(unittest.TestCase):
    """v0.17.0: archivos que Garita juraba haber revisado.

    Un UTF-16 sin marca contado como binario, un Latin-1 con los acentos
    rotos —y con ellos las palabras de contexto—, y la coma del CSV
    tomada por punto decimal. Los tres callaban sobre el formato en que
    viaja un padrón.
    """

    CLABE = "002180000645829179"

    def test_utf16_sin_bom_se_lee(self):
        # Lo escriben iconv, java.io, .NET y el bcp -w de SQL Server: el
        # exportador de padrones. Sin marca era «lleno de nulos» =>
        # binario => omitido sin nombrarlo.
        from garita.nucleo import descifrar
        llave = "AKIA" + "QZLMWPXR2T7VBJ4K"
        for cod in ("utf-16-le", "utf-16-be"):
            texto = descifrar(f"aws_key = {llave}\n".encode(cod))
            self.assertIsNotNone(texto, cod)
            self.assertTrue(list(buscar(texto, "x")), cod)

    def test_el_binario_de_verdad_sigue_descartado(self):
        from garita.nucleo import descifrar
        self.assertIsNone(descifrar(bytes(range(256)) * 4))
        self.assertIsNone(descifrar(b"\0" * 400))
        self.assertIsNone(descifrar(b"\x89PNG\r\n\x1a\n" + b"\0\x01\x02" * 50))

    def test_latin1_conserva_sus_acentos_y_su_contexto(self):
        # «Cédula» decodificada con replace se vuelve «C�dula» y ningún
        # _CONTEXTO casa: el detector queda ciego y el archivo cuenta
        # como revisado, que es peor que omitirlo.
        from garita.nucleo import descifrar
        texto = descifrar("Cédula: 1710034065\n".encode("latin-1"))
        self.assertIn("Cédula", texto)
        td = repo_temporal({})
        with td:
            raiz = Path(td.name)
            (raiz / "latino.txt").write_bytes(
                "Cédula: 1710034065\n".encode("latin-1"))
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz)
            self.assertEqual(codigo, 1, salida)
            self.assertIn("cedula_ec", salida)

    def test_la_codificacion_se_decide_por_byte_no_por_archivo(self):
        # Tercera versión de esto, y la primera que sirve a las DOS
        # direcciones: v0.17.0 leía el archivo entero como cp1252 y un
        # byte Latin-1 arruinaba los acentos del UTF-8 mayoritario;
        # v0.20.2 lo invirtió y un carácter UTF-8 arruinaba los del padrón
        # Latin-1. Los archivos mezclados existen —un export de Excel al
        # que alguien le pegó una línea— y no hay que elegir.
        from garita.nucleo import descifrar
        cedula = "Cédula: 1710034065\n"
        casos = {
            "latin-1 puro": cedula.encode("latin-1"),
            "latin-1 con una línea utf-8":
                cedula.encode("latin-1") + "Observación\n".encode("utf-8"),
            "utf-8 con un byte latin-1":
                "Reporte de a".encode("utf-8") + b"\xf1"
                + ("o\n" + cedula).encode("utf-8"),
        }
        for nombre, crudo in casos.items():
            self.assertIn("Cédula", descifrar(crudo), nombre)

    def test_un_byte_suelto_no_manda_el_archivo_entero_a_cp1252(self):
        # El reintento de v0.17.0 era por ARCHIVO: una ñ Latin-1 pegada
        # en un export mezclado convertía «Cédula» (UTF-8) en «CÃ©dula» y
        # dejaba ciego a todo detector con contexto acentuado — sobre un
        # archivo que en su mayoría era UTF-8 correcto.
        from garita.nucleo import descifrar
        crudo = ("Reporte del mes de a".encode("utf-8") + b"\xf1"
                 + "o 2024\nCédula: 1710034065\n".encode("utf-8"))
        texto = descifrar(crudo)
        self.assertIn("Cédula", texto)
        td = repo_temporal({})
        with td:
            raiz = Path(td.name)
            (raiz / "mixto.txt").write_bytes(crudo)
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz)
            self.assertEqual(codigo, 1, salida)
            self.assertIn("cedula_ec", salida)

    def test_identificador_en_fila_csv_no_se_silencia(self):
        # La coma del CSV se tomaba por punto decimal y la fila entera se
        # descartaba antes de mirar nada más.
        from garita.detectores.paises._comun import dentro_de_un_numero
        linea = f"Juan Perez,55,{self.CLABE},1234.50"
        i = linea.index(self.CLABE)
        self.assertFalse(
            dentro_de_un_numero(linea, i, i + len(self.CLABE)))

    def test_el_numero_de_verdad_sigue_suprimido(self):
        # La calibración que sí se quería: mantisas y tablas numéricas.
        import re as _re
        from garita.detectores.paises._comun import dentro_de_un_numero
        for linea in ("x = 3.141592653589793e10",
                      "valor 1.234567890123456789"):
            m = _re.search(r"\d{10,}", linea)
            self.assertTrue(
                dentro_de_un_numero(linea, m.start(), m.end()), linea)

    def test_una_celda_propia_nunca_vive_dentro_de_un_numero(self):
        # Cambio deliberado de v0.24.0: si la coincidencia es un CAMPO
        # completo, la heurística de tabla numérica no aplica. Antes, una
        # fila de export bancario —cuenta, monto, comisión, IVA— llegaba a
        # las tres coincidencias de la ventana con sus propios importes y
        # la CLABE válida se descartaba sin validar nada.
        #
        # El costo es una tabla de decimales donde una celda sea, por azar,
        # un identificador con dígito verificador válido. Entre callar un
        # padrón y hacer ruido en ese caso, la doctrina elige el ruido.
        import re as _re
        from garita.detectores.paises._comun import dentro_de_un_numero
        for linea in (f"1234567890,{self.CLABE},1500.50,240.08,1740.58",
                      f"0,12, 3,45, 6,78, {self.CLABE}, 9,01",
                      f"cuenta\t{self.CLABE}\t9.999,50"):
            i = linea.index(self.CLABE)
            self.assertFalse(
                dentro_de_un_numero(linea, i, i + len(self.CLABE)), linea)
        del _re

    def test_columna_aparte_de_una_url_es_error_no_aviso(self):
        # El token retrocedía hasta la URL de la columna anterior y el
        # error se degradaba a aviso: veredicto 0 en datos raspados.
        from garita.detectores.paises._comun import dentro_de_url
        linea = f"Juan,https://ejemplo.invalido/juan,{self.CLABE}"
        self.assertFalse(dentro_de_url(linea, linea.index(self.CLABE)))
        # Y el identificador que sí vive DENTRO de la ruta sigue bajando.
        ruta = f"foto https://cdn.invalido/{self.CLABE}.jpg"
        self.assertTrue(dentro_de_url(ruta, ruta.index(self.CLABE)))

    def test_spec_de_contratos_no_es_carpeta_de_pruebas(self):
        # spec/ es donde vive el contrato OpenAPI, que se ESCRIBE — el
        # mismo argumento por el que examples/ no se suprime.
        from garita.nucleo import es_de_prueba
        self.assertFalse(es_de_prueba("spec/openapi.yaml"))
        # Y lo que sí es prueba con ese nombre sigue cubierto.
        self.assertTrue(es_de_prueba("foo_spec.rb"))
        self.assertTrue(es_de_prueba("a.spec.ts"))
        self.assertTrue(es_de_prueba("spec/fixtures/llave.pem"))


class LaRegresionYLosVeteranos(unittest.TestCase):
    """v0.19.0: las dos caras del posesivo, y lo que los detectores más
    viejos nunca cubrieron.
    """

    def test_mi_clave_no_absuelve_lo_que_le_sigue(self):
        # Regresión de v0.13.0: con «mi clave» en MARCADORES, la frontera
        # camelCase lo volvía prefijo absolutorio — y así se llama la
        # contraseña que uno se pone a sí mismo en español.
        self.assertFalse(es_marcador("MiClaveSegura2024"))
        self.assertFalse(es_marcador("MiSecretoNuclear99"))
        self.assertTrue(list(buscar(
            "DATABASE_URL=postgres://admin:MiClaveSegura2024@db.prod/ventas",
            "config.py")))

    def test_mi_clave_como_valor_entero_sigue_exenta(self):
        for v in ("miClave", "mi_secreto", "mi-llave", "MiClave", "mypassword"):
            self.assertTrue(es_marcador(v), v)

    def test_tu_clave_con_cola_vuelve_a_absolverse(self):
        # La otra cara: «TuClaveAqui» es el placeholder de toda plantilla.
        # La asimetría con «mi…» es del idioma — «tu clave» se escribe
        # dirigiéndose a quien lee.
        for v in ("TuClaveAqui", "tuPasswordAqui", "your_key_here",
                  "TU_TOKEN_AQUI"):
            self.assertTrue(es_marcador(v), v)
        self.assertFalse(list(buscar(
            "DATABASE_URL=postgres://usuario:TuClaveAqui@localhost:5432/app",
            "README.md")))

    def test_el_posesivo_sin_sustantivo_sigue_sin_absolver(self):
        for v in ("Turquesa9Fuerte42x", "Turbina88Xk", "yourself2024xyz"):
            self.assertFalse(es_marcador(v), v)

    def test_telefono_con_lada_entre_parentesis(self):
        # La forma impresa más común del país no casaba con nada.
        from garita.detectores.paises.mx import _buscar_telefono
        for linea in ("Tel: (55) 1234-5678", "Tel: +52 (55) 1234-5678",
                      "Contacto: (833) 123-4567"):
            self.assertTrue(list(_buscar_telefono(linea + "\n", "a")), linea)

    def test_telefono_al_final_de_una_oracion(self):
        from garita.detectores.paises.mx import _buscar_telefono
        self.assertTrue(list(_buscar_telefono(
            "Llama al tel 55 1234 5678.\n", "a")))
        # Y el decimal que el lookahead protege sigue protegido.
        self.assertFalse(list(_buscar_telefono(
            "valor 55 1234 5678.9\n", "a")))

    def test_nss_de_relleno_no_es_hallazgo(self):
        from garita.config import Config
        from garita.detectores.paises.mx import detectores as mx
        d = {x.nombre: x for x in mx(Config())}["nss"]
        self.assertFalse(list(d.buscar('nss = "00000000000"\n', "x")))
        self.assertFalse(list(d.buscar("imss: 99999999999\n", "x")))
        # El NSS de verdad sigue siendo error.
        self.assertTrue(list(d.buscar("nss: 92988084494\n", "x")))

    def test_descitar_conoce_los_siete_escapes_de_git(self):
        from garita.historial import _descitar
        self.assertEqual("tests/ca\amp.txt", _descitar('"tests/ca\\amp.txt"'))
        self.assertEqual("a\bb", _descitar('"a\\bb"'))
        self.assertEqual("peña.pem", _descitar('"pe\\303\\261a.pem"'))
        self.assertEqual('pe"a.pem', _descitar('"pe\\"a.pem"'))


class ElContratoYElParser(unittest.TestCase):
    """v0.21.0: la Action y el mini-YAML dejan de adivinar.

    Un input vacío que corría con otra configuración, un fetch que dejaba
    somero el clon ajeno, y cuatro maneras del parser de leer algo
    distinto de lo que el archivo decía.
    """

    def _accion(self):
        import importlib.util
        ruta = Path(__file__).resolve().parent.parent / "scripts/ejecutar.py"
        spec = importlib.util.spec_from_file_location("garita_action", ruta)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_el_input_config_vacio_no_corre_con_otra_cosa(self):
        # `config: ${{ vars.X }}` sin definir llega como cadena vacía y
        # Garita corría con la configuración por omisión, aprobando con 0
        # un repo cuyo padrón estaba a la vista.
        mod = self._accion()
        with self.assertRaises(SystemExit) as caso:
            mod.argumentos({"GARITA_CONFIG": ""})
        self.assertEqual(2, caso.exception.code)
        with self.assertRaises(SystemExit):
            mod.argumentos({"GARITA_CONFIG": "   "})
        # La ruta de verdad sigue pasándose, y la ausencia total de la
        # variable (correrlo fuera de la Action) no molesta.
        self.assertEqual(["--config", "otra.yml"],
                         mod.argumentos({"GARITA_CONFIG": "otra.yml"}))
        self.assertEqual([], mod.argumentos({}))

    def test_el_fetch_del_pr_no_vuelve_somero_el_clon(self):
        # `--depth=1` escribía .git/shallow sobre un clon pedido completo,
        # destruía el merge-base —así que solo-cambios caía siempre al
        # escaneo completo— y dejaba roto todo --historial posterior.
        mod = self._accion()

        def git(cwd, *args):
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                            *args], cwd=cwd, check=True, capture_output=True)

        with TemporaryDirectory() as d:
            origen = Path(d) / "origen"
            origen.mkdir()
            git(origen, "init", "-q", "-b", "main")
            (origen / "a.txt").write_text("base\n", encoding="utf-8")
            git(origen, "add", "-A")
            git(origen, "commit", "-qm", "c1")
            clon = Path(d) / "clon"
            subprocess.run(["git", "clone", "-q", f"file://{origen}",
                            str(clon)], check=True, capture_output=True)
            # La rama base avanza DESPUÉS del clon: es el caso de todo PR.
            (origen / "b.txt").write_text("mas\n", encoding="utf-8")
            git(origen, "add", "-A")
            git(origen, "commit", "-qm", "c2")
            git(clon, "checkout", "-qb", "feature")
            (clon / "propio.txt").write_text("del pr\n", encoding="utf-8")
            git(clon, "add", "-A")
            git(clon, "commit", "-qm", "pr")

            antes = os.getcwd()
            os.chdir(clon)
            try:
                archivos = mod.archivos_del_pr({"GITHUB_BASE_REF": "main"})
            finally:
                os.chdir(antes)
            # El clon sigue completo: sin esto, --historial saldría con 2.
            self.assertFalse((clon / ".git" / "shallow").exists())
            # Y el diff encuentra el archivo del PR en vez de salir vacío
            # y caer al escaneo completo.
            self.assertEqual(["propio.txt"], archivos)

    def test_lista_vacia_en_linea_es_lista_no_cadena(self):
        """«exenciones: []» quedaba como la CADENA "[]" y el validador la
        rechazaba pidiendo archivo y motivo — sobre una lista sin exenciones.
        Un repo que declara explícitamente «aquí no hay exenciones» es el caso
        que hay que premiar, y era el único que no compilaba."""
        from garita.config import _leer_yaml
        self.assertEqual(_leer_yaml("exenciones: []\n"), {"exenciones": []})
        self.assertEqual(_leer_yaml("exenciones: {}\n"), {"exenciones": {}})

    def test_los_booleanos_de_yaml_valen_todos(self):
        from garita.config import _valor
        for v in ("off", "no", "false", "n", "0", "NO", "Off"):
            self.assertIs(False, _valor(v), v)
        for v in ("on", "yes", "true", "sí", "y", "1", "ON"):
            self.assertIs(True, _valor(v), v)

    def test_fallar_en_aviso_apagado_con_off(self):
        aviso = {"conf.py": 'password = "Kx9mPqR2vNw8LtY4"\n'}
        td = repo_temporal({**aviso, ".garita.yml": "fallar_en_aviso: off\n"})
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 0, salida)
        td = repo_temporal({**aviso, ".garita.yml": "fallar_en_aviso: on\n"})
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 1, salida)

    def test_el_bom_no_borra_la_primera_clave(self):
        # Se leía con utf-8 y el BOM volvía la clave en «﻿nombres»:
        # la lista de nombres desaparecía y el detector se apagaba mudo.
        td = repo_temporal({"gen.py": 'PROHIBIDOS = ["Juanito"]\n',
                            "p.md": "lote 47: Juanito\n"})
        with td:
            raiz = Path(td.name)
            (raiz / ".garita.yml").write_text(
                "nombres:\n  - gen.py:PROHIBIDOS\n"
                "exenciones:\n  - archivo: gen.py\n    motivo: es la fuente\n"
                "    detectores: nombre\n",
                encoding="utf-8-sig")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz)
            self.assertEqual(codigo, 1, salida)
            self.assertIn("Juanito", salida)

    def test_una_fuente_mal_escrita_no_se_traga_en_silencio(self):
        # El espacio tras los dos puntos la volvía un mapa, el filtro la
        # borraba y el detector de nombres dejaba de correr con código 0.
        td = repo_temporal({"gen.py": 'PROHIBIDOS = ["Juanito"]\n',
                            ".garita.yml": "nombres:\n  - gen.py: PROHIBIDOS\n"})
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 2, salida)
            self.assertIn("se leyó como mapa", salida)

    def test_clave_repetida_es_error_de_configuracion(self):
        td = repo_temporal({
            "x.py": "x = 1\n",
            ".garita.yml": ("nombres:\n  - a.py:A\n"
                            "nombres:\n  - b.py:B\n"),
        })
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 2, salida)
            self.assertIn("ya se definió antes", salida)

    def test_configuracion_ilegible_es_codigo_2(self):
        td = repo_temporal({"x.py": "x = 1\n"})
        with td:
            raiz = Path(td.name)
            (raiz / ".garita.yml").write_bytes(
                "nombres:\n  - x.py:A\n".encode("utf-16"))
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz)
            self.assertEqual(codigo, 2, salida)

    def test_linea_base_a_ruta_imposible_es_codigo_2(self):
        td = repo_temporal({"conf.py": 'url = "postgres://a:Kx9mPqR2vNw8@d/p"\n'})
        with td:
            codigo, salida = correr_garita(
                Path(td.name), "--linea-base",
                "--linea-base-ruta", "noexiste/base.json")
            self.assertEqual(codigo, 2, salida)

    def test_congelar_un_repo_limpio_borra_la_base_pagada(self):
        # Dejarla era un no-op con código 0 sobre el comando que la propia
        # herramienta manda usar: la base vieja seguía en disco perdonando
        # lo que llegara después.
        sucio = {"conf.py": 'url = "postgres://a:Kx9mPqR2vNw8@d/p"\n'}
        td = repo_temporal(dict(sucio))
        with td:
            raiz = Path(td.name)
            correr_garita(raiz, "--linea-base")
            base = raiz / ".garita-base.json"
            self.assertTrue(base.is_file())
            (raiz / "conf.py").write_text("url = 'ok'\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz, "--linea-base")
            self.assertEqual(codigo, 0, salida)
            self.assertFalse(base.is_file(), salida)


class LoQueNoSePudoMirar(unittest.TestCase):
    """v0.22.0: no se aprueba lo que no se revisó, y las exenciones
    entienden lo que el reporte imprime."""

    CLABE = "002180000645829179"

    @unittest.skipIf(os.name == "nt", "los permisos POSIX no aplican")
    # getattr y no os.geteuid(): en Windows esa función NO EXISTE, el
    # decorador se evalúa al crear la clase y el AttributeError tumbaba el
    # módulo entero — el job de Windows corría 0 de 248 pruebas y nadie lo
    # notó, porque «0 pruebas» y «todo verde» se parecen demasiado.
    @unittest.skipIf(getattr(os, "geteuid", lambda: 1)() == 0,
                     "root lee todo")
    def test_un_archivo_ilegible_no_se_cuenta_como_binario(self):
        # Se contaba en «omitidos (binarios o muy grandes)», sin nombrarlo
        # y sin tocar el veredicto: se aprobaba con 0 algo que nadie miró.
        td = repo_temporal({"secreto.txt": f"CLABE {self.CLABE}\n",
                            "ok.py": "x = 1\n"})
        with td:
            raiz = Path(td.name)
            objetivo = raiz / "secreto.txt"
            objetivo.chmod(0o000)
            try:
                codigo, salida = correr_garita(raiz)
            finally:
                objetivo.chmod(0o644)
        self.assertEqual(codigo, 2, salida)
        self.assertIn("secreto.txt", salida)
        self.assertIn("No se pudieron leer", salida)
        # Y el ✓ no aparece: estaría mintiendo.
        self.assertNotIn("✓", salida)

    def test_exentar_por_la_etiqueta_que_imprime_el_reporte(self):
        # El reporte dice «llave_privada»; la exención sólo entendía
        # «secretos», así que copiar lo que se ve no exentaba nada — y
        # tampoco salía como exención muerta.
        llave = ("-----BEGIN RSA PRIVATE KEY-----\n"
                 "MIIEfalsaAAAA\n-----END RSA PRIVATE KEY-----\n")
        td = repo_temporal({
            "llave.pem": llave,
            ".garita.yml": ("exenciones:\n  - archivo: llave.pem\n"
                            "    motivo: fixture de TLS\n"
                            "    detectores: llave_privada\n"),
        })
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 0, salida)
        # Y el nombre del detector sigue valiendo igual.
        td = repo_temporal({
            "llave.pem": llave,
            ".garita.yml": ("exenciones:\n  - archivo: llave.pem\n"
                            "    motivo: fixture de TLS\n"
                            "    detectores: secretos\n"),
        })
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 0, salida)

    def test_el_posesivo_admite_calificativo_en_medio(self):
        # «yourDatabasePassword» es el placeholder de toda plantilla y se
        # denunciaba como credencial real.
        for v in ("yourDatabasePassword", "tu_clave_de_produccion",
                  "your_api_key_here", "TU_TOKEN_DE_ACCESO"):
            self.assertTrue(es_marcador(v), v)

    def test_el_posesivo_con_calificativo_no_absuelve_contrasenas(self):
        # La cuarta cara del posesivo no puede abrir las otras tres: el
        # sustantivo tiene que ser PALABRA, no subcadena.
        for v in ("turbopass2024", "Turbina88Xk", "Turquesa9Fuerte42x",
                  "MiClaveSegura2024", "yourself2024xyz"):
            self.assertFalse(es_marcador(v), v)


class NoCuelgaElCi(unittest.TestCase):
    """v0.23.0: un guardián que cuelga el build se desinstala igual que
    uno que grita. Los tiempos se miden, no se opinan."""

    def test_una_linea_minificada_no_dispara_el_retroceso(self):
        # El esquema sin cota hacía retroceder el motor desde cada
        # posición de una tirada de minúsculas con puntos: 117 KB en una
        # línea tardaban 21 segundos.
        import time
        linea = "a." * 60000
        inicio = time.perf_counter()
        list(buscar(linea, "x"))
        transcurrido = time.perf_counter() - inicio
        self.assertLess(transcurrido, 2.0,
                        f"tardó {transcurrido:.1f}s en 117 KB de una línea")

    def test_los_esquemas_de_verdad_siguen_casando(self):
        for u in ("postgres://admin:Kx9mPqR2vNw8@db.interno:5432/prod",
                  "redis://:Kx9mPqR2vNw8@cache.interno:6379",
                  "mongodb+srv://u:Kx9mPqR2vNw8@cluster0.invalido/db",
                  "amqps://user:Kx9mPqR2vNw8@rabbit.interno:5671"):
            self.assertTrue(list(buscar(u, "x")), u[:24])

    def test_muchas_coincidencias_en_una_linea_no_son_cuadraticas(self):
        # dentro_de_url copiaba y rastreaba todo el prefijo por cada
        # coincidencia. Se mide la FORMA, no el reloj: un umbral absoluto
        # reprueba por carga de la máquina y no por regresión, que es una
        # prueba que miente igual que un guardián que grita.
        import time
        from garita.detectores.paises._comun import dentro_de_url

        def tarda(largo):
            linea = "x" * largo + " 002180000645829179"
            inicio = time.perf_counter()
            for _ in range(300):
                dentro_de_url(linea, len(linea) - 18)
            return time.perf_counter() - inicio

        tarda(10_000)                      # calienta
        corto, largo = tarda(10_000), tarda(400_000)
        # Cuarenta veces más línea: si fuera cuadrático el cociente se
        # dispararía. Con el prefijo sin copiar, apenas cambia.
        self.assertLess(largo, max(corto * 8, 0.5),
                        f"40× de línea costó {largo / max(corto, 1e-6):.0f}× "
                        f"de tiempo ({corto:.3f}s → {largo:.3f}s)")


class LosCuatroCanalesDicenLoMismo(unittest.TestCase):
    """v0.25.0: quien mira un canal cree que vio todo."""

    def test_lo_no_revisado_llega_al_sarif_y_al_resumen(self):
        # El SARIF es el ÚNICO canal de la auditoría mensual: decía «cero
        # alertas» sobre un padrón de 2 MB que nadie leyó.
        from garita.nucleo import Resultado
        from garita.sarif import generar
        from garita.reporte import resumen_markdown
        res = Resultado()
        res.archivos_revisados = 3
        res.omitidos_grandes = [("volcado.csv", "pesa 2 MB, más del tope")]
        res.ilegibles = [("secreta/padron.txt", "Permission denied")]
        doc = generar(res, [])
        textos = " ".join(r["message"]["text"] for r in doc["runs"][0]["results"])
        self.assertIn("volcado.csv",
                      " ".join(str(r) for r in doc["runs"][0]["results"]))
        self.assertIn("no se pudo leer", textos.lower())
        resumen = resumen_markdown(res)
        self.assertIn("volcado.csv", resumen)
        self.assertIn("secreta/padron.txt", resumen)
        self.assertNotIn("## ✅", resumen)

    def test_las_otras_rutas_llegan_al_sarif(self):
        from garita.historial import HallazgoHistorico
        from garita.nucleo import Hallazgo
        from garita.sarif import generar_historial

        class Res:
            hallazgos = [HallazgoHistorico(
                hallazgo=Hallazgo(archivo="tests/fixture.pem", linea=1,
                                  detector="llave_privada", que="----…----",
                                  por_que="x", como_arreglar="y"),
                commit="abc1234567", fecha="2026-08-07", vivo=True,
                otras_rutas=("src/secreto.pem",))]

        doc = generar_historial(Res(), [])
        texto = doc["runs"][0]["results"][0]["message"]["text"]
        self.assertIn("src/secreto.pem", texto)


class PorDondeEntraElDato(unittest.TestCase):
    """v0.24.0: cuatro vías por las que un dato entraba sin que nadie
    quisiera evadir nada."""

    def test_nfd_no_ciega_a_los_detectores_con_contexto(self):
        # macOS y varios exportadores escriben «Cédula» como e + acento
        # combinante: otra cadena para cada patrón acentuado del proyecto,
        # y con exige_contexto eso es quedarse ciego del todo.
        import unicodedata
        from garita.nucleo import descifrar
        from garita.config import Config
        from garita.detectores.paises import ec
        d = {x.nombre: x for x in ec.detectores(Config())}["cedula_ec"]
        nfd = unicodedata.normalize("NFD", "Cédula: 1710034065\n")
        self.assertNotEqual(nfd, "Cédula: 1710034065\n")   # de verdad es NFD
        self.assertTrue(list(d.buscar(descifrar(nfd.encode()), "x")))

    def test_un_padron_de_una_sola_linea_reporta_todos_los_nombres(self):
        # Con `search` un JSON de `jq -c` con cuatrocientos nombres
        # reportaba UNO — y la línea base congelaba ese 1.
        td = repo_temporal({
            "gen.py": 'PROHIBIDOS = ["Ana Ruiz", "Beto Lara", "Carla Ortiz"]\n',
            "padron.json": ('[{"n":"Ana Ruiz"},{"n":"Beto Lara"},'
                            '{"n":"Carla Ortiz"}]\n'),
            ".garita.yml": ("nombres:\n  - gen.py:PROHIBIDOS\n"
                            "exenciones:\n  - archivo: gen.py\n"
                            "    motivo: es la fuente\n    detectores: nombre\n"),
        })
        with td:
            codigo, salida = correr_garita(Path(td.name))
        self.assertEqual(codigo, 1, salida)
        self.assertEqual(3, salida.count("  nombre  "), salida)

    def test_secretos_sin_comillas_de_env_y_compose(self):
        # Los formatos donde de verdad se filtra una credencial por
        # descuido no usan comillas por convención.
        from garita.detectores.secretos import buscar_asignaciones
        for linea in ("DB_PASSWORD=Kx9mPqR2vNw8LtY4Qz3b",
                      "APP_SECRET=Kx9mPqR2vNw8LtY4Qz3b",
                      "      POSTGRES_PASSWORD: Kx9mPqR2vNw8LtY4Qz3b",
                      "app.secret=Kx9mPqR2vNw8LtY4Qz3b",
                      "spring.datasource.password=Kx9mPqR2vNw8LtY4Qz3b"):
            self.assertTrue(
                list(buscar_asignaciones(linea + "\n", ".env")), linea)

    def test_el_valor_entrecomillado_con_prefijo_punteado_se_reporta(self):
        # Regresión de v0.24.0: el filtro de «referencia» estaba pensado
        # para el valor SIN comillas y quedó en el bucle común, así que
        # mató las credenciales de prefijo punteado —«hvs.» de Vault,
        # «dp.st.» de Doppler, «cs.live.»— que v0.23.0 sí reportaba.
        from garita.detectores.secretos import buscar_asignaciones
        for linea in ('api_key = "prod.a8Kd93jfKd93jfLs02mZ"',
                      'client_secret: "cs.live.9f8a7b6c5d4e3f2a1b0c"',
                      'token = "hvs.CAESIJm4Kd93jfKd93jfLs02mZq"'):
            self.assertTrue(
                list(buscar_asignaciones(linea + "\n", "config.py")), linea)

    def test_el_bom_y_el_utf16_tambien_se_normalizan(self):
        # El `normalize` estaba sólo en el return final, así que las ramas
        # del BOM y del UTF-16 devolvían el texto sin normalizar — y el
        # «CSV UTF-8» de Excel SIEMPRE escribe BOM. El padrón que más
        # importa seguía ciego después del arreglo de la víspera.
        import codecs as _codecs
        import unicodedata
        from garita.nucleo import descifrar
        nfd = unicodedata.normalize("NFD", "Cédula: 1710034065\n")
        casos = {
            "utf-8 con BOM": _codecs.BOM_UTF8 + nfd.encode("utf-8"),
            "utf-16-le": nfd.encode("utf-16"),
            "utf-16 sin marca": nfd.encode("utf-16-le"),
        }
        for nombre, crudo in casos.items():
            self.assertIn("Cédula", descifrar(crudo), nombre)

    def test_el_codigo_normal_no_se_marca_por_no_llevar_comillas(self):
        # El motivo por el que las comillas se exigían: no morder código.
        from garita.detectores.secretos import buscar_asignaciones
        for linea in ("username, password = get_auth_from_url(proxy)",
                      "password = config.db_password",
                      "self.api_key = settings.API_KEY",
                      'token = os.environ["T"]',
                      "password: $DB_PASS",
                      "secret_key = None",
                      "const password = req.body.password"):
            self.assertFalse(
                list(buscar_asignaciones(linea + "\n", "app.py")), linea)

    def test_el_prefijo_largo_no_dispara_retroceso(self):
        import time
        from garita.detectores.secretos import buscar_asignaciones
        linea = "a_" * 20000 + "password=" + "x" * 20
        inicio = time.perf_counter()
        list(buscar_asignaciones(linea + "\n", "x"))
        self.assertLess(time.perf_counter() - inicio, 1.0)


class ElDigitoVerificadorSeVerifica(unittest.TestCase):
    """Un vector negativo por país, que es lo que faltaba.

    La quinta oleada encontró la mutación: se podía quitar la comprobación
    del dígito de control de diez validadores y las pruebas seguían en
    verde, porque sólo se afirmaba lo que SÍ valida. La forma fuerte de
    exigirlo es ésta: de todos los dígitos de control posibles, **uno y
    sólo uno** puede ser el bueno. Si alguien afloja la validación, este
    conteo pasa de 1 y la prueba cae.
    """

    def _vectores(self):
        from garita.detectores.paises import (
            ar, br, ca, cl, co, do, ec, es, gt, mx, pe, pt, py, us, uy, ve)
        return [
            (ar.cuit_valido, "20-12345678-6", "0123456789"),
            (br.cpf_valido, "111.444.777-35", "0123456789"),
            (br.cnpj_valido, "12.345.678/0001-95", "0123456789"),
            (cl.rut_valido, "12.345.678-5", "0123456789K"),
            (co.nit_valido, "900.123.456-8", "0123456789"),
            (es.dni_valido, "10345678W", "TRWAGMYFPDXBNJZSQVHLCKE"),
            (es.nie_valido, "X1234567L", "TRWAGMYFPDXBNJZSQVHLCKE"),
            (es.cif_valido, "A12345674", "0123456789"),
            (pe.ruc_valido, "20100079772", "0123456789"),
            # El SSN NO lleva dígito verificador —valida por estructura de
            # la SSA— y por eso va aparte, abajo.
            (ca.sin_valido, "730 425 618", "0123456789"),
            (pt.nif_valido, "203456785", "0123456789"),
            (uy.ci_valida, "4.870.913-5", "0123456789"),
            (ec.cedula_ec_valida, "1710034065", "0123456789"),
            (do.cedula_do_valida, "001-1391820-5", "0123456789"),
            (ve.rif_valido, "J-12345678-4", "0123456789"),
            (py.ruc_py_valido, "80024242-4", "0123456789"),
            (gt.nit_gt_valido, "5000000-4", "0123456789K"),
            (mx.clabe_valida, "002180000000001008", "0123456789"),
            (mx.nss_valido, "92988084494", "0123456789"),
        ]

    def test_solo_un_digito_de_control_es_valido(self):
        for validar, vector, alfabeto in self._vectores():
            self.assertTrue(validar(vector), f"{validar.__name__}: {vector}")
            validos = [c for c in alfabeto
                       if validar(vector[:-1] + c)]
            self.assertEqual(
                1, len(validos),
                f"{validar.__name__}: {len(validos)} dígitos de control "
                f"válidos ({validos}); debería ser exactamente uno. Si son "
                f"todos, la comprobación no se está haciendo.")

    def test_el_iban_rechaza_sus_dos_digitos_de_control(self):
        # Aparte porque su control son DOS dígitos y valida dos veces: el
        # módulo 97 del IBAN y el control interno del CCC.
        from garita.detectores.paises.es import iban_valido
        bueno = "ES91 2100 0418 4502 0005 1332"
        self.assertTrue(iban_valido(bueno))
        validos = [f"{d:02d}" for d in range(100)
                   if iban_valido("ES" + f"{d:02d}" + bueno[4:])]
        self.assertEqual(["91"], validos)

    def test_el_archivo_grande_se_nombra_en_el_escaneo_normal(self):
        # Segunda mutación que sobrevivía: borrar la línea que NOMBRA el
        # archivo omitido por tamaño dejaba la suite en verde, porque sólo
        # el camino de --historial lo exigía. El del hook, el de la Action
        # y el de la CLI ordinaria pasan por aquí, y un volcado de 2 MB
        # con un padrón dentro desaparecía en el conteo agregado.
        td = repo_temporal({"chico.py": "x = 1\n"})
        with td:
            raiz = Path(td.name)
            (raiz / "volcado.csv").write_text("x" * 2_100_000,
                                              encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz)
        self.assertIn("volcado.csv", salida)
        self.assertIn("Sin revisar por tamaño", salida)

    def test_el_ssn_rechaza_lo_que_la_ssa_nunca_asigna(self):
        # No tiene dígito verificador: su validación es estructural, así
        # que el vector negativo son los rangos que nunca se emitieron.
        from garita.detectores.paises.us import ssn_valido
        self.assertTrue(ssn_valido("531-88-2074"))
        for malo in ("000-88-2074",     # área 000
                     "666-88-2074",     # área 666, nunca asignada
                     "531-00-2074",     # grupo 00
                     "531-88-0000",     # serie 0000
                     "900-45-2074"):    # 9xx fuera de los rangos ITIN
            self.assertFalse(ssn_valido(malo), malo)

    def test_el_curp_y_el_rfc_rechazan_su_control(self):
        from garita.detectores.paises.mx import curp_valido, rfc_valido
        curp = "AABB900101HDFCDF09"
        self.assertTrue(curp_valido(curp))
        self.assertEqual(
            1, sum(1 for c in "0123456789" if curp_valido(curp[:-1] + c)))
        rfc = "GOPE800101A18"
        self.assertTrue(rfc_valido(rfc))
        alfabeto = "0123456789ABCDEFGHIJKLMNPQRSTUVWXYZ"
        self.assertEqual(
            1, sum(1 for c in alfabeto if rfc_valido(rfc[:-1] + c)))


class ElRepoRevisadoNoMandA(unittest.TestCase):
    """v0.25.0: Garita corre dentro de CI sobre código que no controla, a
    veces con permisos de escritura. Lo que el repositorio revisado trae
    —nombres de archivo, configuración, patrones— no puede desarmarla."""

    def test_un_archivo_llamado_como_bandera_no_apaga_la_revision(self):
        # `git diff --name-only` devuelve el nombre crudo y argparse lee
        # como BANDERA todo lo que empiece por guion: un archivo llamado
        # «--version» imprimía la versión y salía 0 sin mirar nada. El
        # nombre lo elige quien manda el pull request.
        from garita.cli import main
        td = repo_temporal({"llave.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qWeRtY\n"})
        with td:
            raiz = Path(td.name)
            antes = os.getcwd()
            os.chdir(raiz)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    codigo = main(["--", "llave.pem"])
            finally:
                os.chdir(antes)
        self.assertEqual(codigo, 1)

    def test_el_envoltorio_separa_los_nombres_con_dos_guiones(self):
        import importlib.util
        ruta = Path(__file__).resolve().parent.parent / "scripts/ejecutar.py"
        spec = importlib.util.spec_from_file_location("garita_action2", ruta)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.archivos_del_pr = lambda entorno: ["--version", "a.py"]
        argv = mod.argumentos({"GARITA_SOLO_CAMBIOS": "true"})
        self.assertIn("--", argv)
        self.assertLess(argv.index("--"), argv.index("--version"))

    def test_apagar_detectores_se_anuncia(self):
        # El .garita.yml lo trae el repositorio revisado: en un PR de fork
        # lo escribe quien manda el PR. Tres líneas apagaban todo y la
        # salida era «✓ nada que reportar» sin mencionarlo.
        td = repo_temporal({
            "llave.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qWeRtY\n",
            ".garita.yml": "detectores:\n  - secretos: false\n",
        })
        with td:
            codigo, salida = correr_garita(Path(td.name))
        self.assertEqual(codigo, 0, salida)
        self.assertIn("detectores apagados por la configuración", salida)
        self.assertIn("secretos", salida)

    def test_sin_configuracion_no_se_anuncia_nada(self):
        # `nombre` se apaga solo al no haber lista: anunciarlo sería ruido
        # en todo repositorio sin configuración.
        td = repo_temporal({"x.py": "x = 1\n"})
        with td:
            codigo, salida = correr_garita(Path(td.name))
        self.assertNotIn("detectores apagados", salida)

    def test_una_fuente_no_puede_salir_del_arbol_por_prefijo(self):
        # La guardia comparaba PREFIJOS de cadena: la raíz «/w/trav» daba
        # por dentro a «/w/trav-secretos/padron.txt», un directorio
        # HERMANO cuyo nombre empieza igual.
        from garita.fuentes import FuenteInvalida, cargar
        with TemporaryDirectory() as d:
            base = Path(d)
            (base / "trav").mkdir()
            (base / "trav-secretos").mkdir()
            (base / "trav-secretos" / "padron.txt").write_text(
                "Juanito Perez\n", encoding="utf-8")
            with self.assertRaises(FuenteInvalida):
                cargar("../trav-secretos/padron.txt", base / "trav")

    def test_un_patron_con_muchos_comodines_no_cuelga(self):
        # Doce «**» sobre una ruta de veinte segmentos tardaban 222
        # segundos POR ARCHIVO, y el patrón vive en el .garita.yml del
        # repositorio revisado.
        import time
        from garita.nucleo import casa_ruta
        inicio = time.perf_counter()
        casa_ruta("a/" * 20 + "b.py", "**/" * 14 + "b.py")
        self.assertLess(time.perf_counter() - inicio, 1.0)


class LasExcepcionesSeDocumentan(unittest.TestCase):
    """v0.26.0: usar Garita implica tener excepciones, y el diseño hace
    que cada una nazca con su justificación escrita."""

    REPO = {"datos.txt": "CLABE 002180000645829179\nRFC GOPE800101A18\n",
            "llave.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qWeRtY\n"}

    def test_propone_el_bloque_agrupado_por_archivo(self):
        td = repo_temporal(dict(self.REPO))
        with td:
            codigo, salida = correr_garita(
                Path(td.name), "--proponer-exenciones")
        self.assertEqual(codigo, 0, salida)
        self.assertIn("exenciones:", salida)
        # Anclado desde v0.29.0: un archivo de la raíz se nombra «/x» para
        # que la propuesta no exente además sus homónimos de subcarpetas.
        self.assertIn("- archivo: /datos.txt", salida)
        self.assertIn("detectores: clabe, rfc", salida)
        self.assertIn("- archivo: /llave.pem", salida)
        # Ningún valor: la exención se define por archivo y detector.
        self.assertNotIn("002180000645829179", salida)
        self.assertNotIn("GOPE800101A18", salida)

    def test_el_esqueleto_pegado_sin_llenar_detiene_a_garita(self):
        # El punto entero: no se puede pegar y olvidar. Un motivo en
        # blanco es código 2, así que el esqueleto no abre un agujero.
        td = repo_temporal(dict(self.REPO))
        with td:
            raiz = Path(td.name)
            _, propuesta = correr_garita(raiz, "--proponer-exenciones")
            bloque = "\n".join(l for l in propuesta.splitlines()
                               if not l.startswith("#"))
            (raiz / ".garita.yml").write_text(bloque, encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz)
        self.assertEqual(codigo, 2, salida)
        self.assertIn("no tiene motivo", salida)

    def test_con_los_motivos_escritos_si_exenta(self):
        td = repo_temporal(dict(self.REPO))
        with td:
            raiz = Path(td.name)
            (raiz / ".garita.yml").write_text(
                "exenciones:\n"
                "  - archivo: datos.txt\n"
                "    motivo: catálogo público del banco, no de personas\n"
                "    detectores: clabe, rfc\n"
                "  - archivo: llave.pem\n"
                "    motivo: llave de prueba del fixture de TLS\n"
                "    detectores: llave_privada\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz)
        self.assertEqual(codigo, 0, salida)

    def test_el_reporte_ofrece_el_comando(self):
        td = repo_temporal(dict(self.REPO))
        with td:
            codigo, salida = correr_garita(Path(td.name))
        self.assertEqual(codigo, 1, salida)
        self.assertIn("--proponer-exenciones", salida)

    def test_sin_hallazgos_no_propone_nada(self):
        td = repo_temporal({"x.py": "x = 1\n"})
        with td:
            codigo, salida = correr_garita(
                Path(td.name), "--proponer-exenciones")
        self.assertEqual(codigo, 0, salida)
        self.assertNotIn("exenciones:", salida)

    def test_no_se_combina_con_los_otros_modos(self):
        td = repo_temporal(dict(self.REPO))
        with td:
            for extra in (["--historial"], ["--linea-base"],
                          ["--formato", "sarif"]):
                codigo, salida = correr_garita(
                    Path(td.name), "--proponer-exenciones", *extra)
                self.assertEqual(codigo, 2, (extra, salida))


class LaCabeceraPemNoEsLaLlave(unittest.TestCase):
    """v0.27.0: medido sobre un repositorio público real, 48 de 48
    hallazgos de `llave_privada` eran una línea de documentación que
    mencionaba el formato. Ese ruido es lo que enseña a un equipo a
    ignorar al guardián — y el día que lo ignora deja pasar la llave."""

    CUERPO = ("MIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qW"
              "eRtY")

    def test_mencionar_el_formato_no_es_una_llave(self):
        c = self.CUERPO
        for texto in (
            "Expects a PEM file starting with -----BEGIN RSA PRIVATE KEY-----",
            "# El archivo debe empezar con -----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----\nEsa es la cabecera a buscar.\n",
            # Las dos formas reales del repositorio que se midió: el ejemplo
            # recortado dentro de un docstring, con el cuerpo separado por
            # un espacio…
            f":param private_key: For example, `-----BEGIN RSA PRIVATE "
            f"KEY----- {c}. -----END RSA PRIVATE KEY-----`",
            # …y pegado, que es la otra mitad. Ahí lo que delata es la
            # frase que va delante.
            f"        :param private_key: The URL-encoded representation of "
            f"the private key. Strip everything outside of the headers, "
            f"e.g. `-----BEGIN RSA PRIVATE KEY-----{c}",
        ):
            self.assertFalse(list(buscar(texto, "docs.md")), texto[:40])

    def test_la_llave_de_verdad_sigue_sonando(self):
        c = self.CUERPO
        for texto in (
            f"-----BEGIN RSA PRIVATE KEY-----\n{c}\n-----END RSA PRIVATE KEY-----",
            # Cifrada: trae cabeceras RFC 1421 antes del cuerpo.
            f"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
            f"DEK-Info: AES-256-CBC,1F2A\n\n{c}\n",
            # En un .env o un JSON, con los saltos escapados.
            f'KEY="-----BEGIN RSA PRIVATE KEY-----\\n{c}"',
            f'{{"key": "-----BEGIN PRIVATE KEY-----{c}"}}',
            f"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk{c}\n",
            # En código: una asignación y una llamada con varios argumentos
            # llevan prefijo corto, no una frase.
            f'private_key = "-----BEGIN RSA PRIVATE KEY-----\\n{c}"',
            f'config.set("tls", "key", "-----BEGIN RSA PRIVATE KEY-----\\n{c}")',
        ):
            self.assertTrue(list(buscar(texto, "llave.pem")), texto[:44])


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

    def test_clabe_de_fintech_tambien_es_clabe(self):
        # Mercado Pago (722), Cuenca (723) y Spin (728) emiten buena parte
        # de las CLABEs modernas y no estaban en el catálogo: la CLABE más
        # probable en un volcado de 2026 pasaba limpia.
        from garita.detectores.paises.mx import _banco_existe, clabe_valida
        d = self._det("clabe")
        self.assertTrue(clabe_valida("722969000000000018"))
        self.assertTrue(list(d.buscar("CLABE 722969000000000018", "x")))
        # Y un «banco» inexistente sigue cortando aunque el dígito valide.
        self.assertFalse(_banco_existe("999999999999999999"))

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


class LosDocumentosNoMienten(unittest.TestCase):
    """v0.20.0: el reporte no puede re-filtrar lo que denuncia, ni jurar
    algo que no cumple.
    """

    def test_ningun_valor_sale_completo_por_corto_que_sea(self):
        # `len(v) <= 8` devolvía íntegras las cédulas uruguayas y los RUT
        # de ocho dígitos — al SARIF, que la pestaña Security muestra a
        # más gente que el repo, y al HTML, cuyo pie jura lo contrario.
        from garita.detectores.paises._comun import recortar
        for v in ("41234563", "12345678", "1234", "12", "123456789012"):
            self.assertNotEqual(v, recortar(v), v)
            self.assertIn("…", recortar(v), v)

    def test_el_sarif_no_trae_el_valor_entero(self):
        td = repo_temporal({"datos.txt": "cedula 41234563 del titular\n"})
        with td:
            codigo, salida = correr_garita(
                Path(td.name), "--formato", "sarif")
        self.assertNotIn("41234563", salida)

    def test_la_ruta_del_sarif_es_una_referencia_uri(self):
        # Un espacio o unas comillas producían un documento que no valida;
        # un «#» lo parte en fragmento y la alerta apunta a la nada.
        from garita.sarif import _uri
        self.assertEqual("raro%20%231.txt", _uri("raro #1.txt"))
        self.assertEqual("a/b/c.txt", _uri("a/b/c.txt"))
        self.assertEqual("pe%C3%B1a.pem", _uri("peña.pem"))

    def test_las_banderas_vacias_no_corren_con_otra_cosa(self):
        # `--config "$VAR"` con la variable sin definir corría con la
        # configuración por omisión y aprobaba con 0.
        td = repo_temporal({"x.py": "x = 1\n"})
        with td:
            for bandera in ("--config", "--linea-base-ruta", "--salida"):
                codigo, salida = correr_garita(Path(td.name), bandera, "")
                self.assertEqual(codigo, 2, (bandera, salida))

    def test_el_html_dice_cuando_corta_la_deuda_pagada(self):
        from garita.reporte_html import generar

        class Res:
            hallazgos = []
            archivos_revisados = 1
            archivos_omitidos = 0
            omitidos_grandes = []
            exenciones_muertas = []
            exentos_aplicados = {}

        class Base:
            creada = "2026-08-05"

        html = generar(Res(), raiz="x", fecha="2026-08-05", base=Base(),
                       nuevos=[], conocidos=[],
                       pagadas=[f"a{i}.txt · rfc" for i in range(15)])
        self.assertIn("y 5 más", html[html.index("Deuda pagada"):])


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


class ElVeredictoNoMiente(unittest.TestCase):
    """Los modos de falla donde Garita aprobaba sin haber revisado: la
    marca verde sin revisión, que es peor que cualquier falso positivo."""

    def test_archivo_inexistente_es_codigo_2_no_0(self):
        # `garita archibo_mal_tecleado.py` decía «✓ nada que reportar…
        # 1 omitidos (binarios o muy grandes)» y aprobaba. El hook entero
        # podía llevar meses aprobando un nombre mal escrito en su config.
        td = repo_temporal({"real.py": "x = 1\n"})
        with td:
            codigo, salida = correr_garita(Path(td.name), "no_existe.py")
            self.assertEqual(codigo, 2, salida)
            self.assertIn("no_existe.py", salida)
            self.assertNotIn("nada que reportar", salida)

    def test_ruta_fuera_del_repo_es_codigo_2(self):
        # Una ruta absoluta de fuera sí se revisaba (pathlib descarta la
        # raíz al concatenar absolutas) pero sus hallazgos escapaban a las
        # exenciones y a la línea base, que hablan en rutas del repo.
        td = repo_temporal({"real.py": "x = 1\n"})
        ajeno = tempfile.NamedTemporaryFile(suffix=".py", delete=False)
        ajeno.close()
        try:
            with td:
                codigo, salida = correr_garita(Path(td.name), ajeno.name)
                self.assertEqual(codigo, 2, salida)
                self.assertIn("fuera del repositorio", salida)
        finally:
            os.unlink(ajeno.name)

    def test_ruta_absoluta_de_dentro_se_normaliza(self):
        # La misma invocación no puede aprobar con ruta relativa y reprobar
        # con la absoluta equivalente: se normaliza al idioma del repo.
        td = repo_temporal({
            "datos.py": "curp: AABB900101HDFCDF09\n",
            ".garita.yml": ("exenciones:\n"
                            "  - archivo: datos.py\n"
                            "    motivo: sintetico de demo\n"),
        })
        with td:
            raiz = Path(td.name)
            codigo_rel, _ = correr_garita(raiz, "datos.py")
            codigo_abs, salida = correr_garita(raiz, str(raiz / "datos.py"))
            self.assertEqual((codigo_rel, codigo_abs), (0, 0), salida)

    def test_historial_en_clon_somero_es_codigo_2(self):
        # El default de actions/checkout es --depth 1: la auditoría corría
        # sobre el pedazo visible y decía «historial limpio».
        td = TemporaryDirectory()
        with td:
            base = Path(td.name) / "origen"
            base.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"],
                           cwd=base, check=True)
            (base / "secreto.py").write_text(
                "curp: AABB900101HDFCDF09\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=base, check=True)
            subprocess.run(["git", "-c", "user.name=t", "-c",
                            "user.email=t@t", "commit", "-q", "-m", "uno"],
                           cwd=base, check=True)
            subprocess.run(["git", "rm", "-q", "secreto.py"],
                           cwd=base, check=True)
            subprocess.run(["git", "-c", "user.name=t", "-c",
                            "user.email=t@t", "commit", "-q", "-m", "dos"],
                           cwd=base, check=True)
            clon = Path(td.name) / "somero"
            subprocess.run(["git", "clone", "-q", "--depth", "1",
                            f"file://{base}", str(clon)],
                           check=True, capture_output=True)
            codigo, salida = correr_garita(clon, "--historial")
            self.assertEqual(codigo, 2, salida)
            self.assertIn("somero", salida)
            self.assertIn("fetch-depth: 0", salida)
            self.assertNotIn("historial está limpio", salida)

    def test_copia_en_fixtures_no_absuelve_al_secreto_de_src(self):
        # Mismo contenido = mismo blob. Si la única ruta registrada era la
        # del fixture, la copia «inocente» absolvía a la original.
        llave = ("-----BEGIN RSA PRIVATE KEY-----\n"
                 "MIIEowIBAAKCAQEA7bq8s2Kx9mPqR2vNw8Kx9mPqR2vNw8Kx\n"
                 "-----END RSA PRIVATE KEY-----\n")
        td = TemporaryDirectory()
        with td:
            raiz = Path(td.name)
            subprocess.run(["git", "init", "-q", "-b", "main"],
                           cwd=raiz, check=True)
            (raiz / "fixtures").mkdir()
            (raiz / "fixtures" / "ejemplo.pem").write_text(
                llave, encoding="utf-8")
            (raiz / "src").mkdir()
            (raiz / "src" / "secreto.pem").write_text(llave, encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            subprocess.run(["git", "-c", "user.name=t", "-c",
                            "user.email=t@t", "commit", "-q", "-m", "uno"],
                           cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz, "--historial")
            self.assertEqual(codigo, 1, salida)
            self.assertIn("llave", salida)

    def test_credencial_en_examples_suena_como_aviso(self):
        # La mitad de las fugas reales son el archivo de ejemplo que alguien
        # llenó con valores verdaderos. Antes se suprimía sin dejar rastro;
        # ahora suena como aviso: no reprueba, pero tampoco calla.
        td = repo_temporal({
            "examples/config.yml":
                'db = "postgres://admin:Kx9mPqR2vNw8@h:5432/d"\n',
        })
        with td:
            raiz = Path(td.name)
            cfg = cargar_config(raiz)
            res = revisar(raiz, construir(cfg, raiz), cfg.exenciones)
            self.assertEqual(len(res.errores), 0, res.hallazgos)
            avisos = {h.detector for h in res.avisos}
            self.assertIn("credencial_en_url", avisos)

    def test_en_tests_la_relajacion_sigue_intacta(self):
        # La relajación en rutas de PRUEBA es intencional y se queda: los
        # fixtures de TLS versionados son el pan de cada día.
        td = repo_temporal({
            "tests/config.yml":
                'db = "postgres://admin:Kx9mPqR2vNw8@h:5432/d"\n',
        })
        with td:
            raiz = Path(td.name)
            cfg = cargar_config(raiz)
            res = revisar(raiz, construir(cfg, raiz), cfg.exenciones)
            self.assertEqual(len(res.hallazgos), 0, res.hallazgos)

    def test_la_action_escribe_su_salida(self):
        # action.yml declara `hallazgos` y el README la documenta; nadie la
        # escribía y todo workflow que la usara recibía cadena vacía.
        td = repo_temporal({"datos.py": "curp: AABB900101HDFCDF09\n"})
        destino = tempfile.NamedTemporaryFile(delete=False)
        destino.close()
        try:
            with td:
                os.environ["GITHUB_OUTPUT"] = destino.name
                try:
                    correr_garita(Path(td.name))
                finally:
                    del os.environ["GITHUB_OUTPUT"]
                contenido = Path(destino.name).read_text(encoding="utf-8")
                self.assertIn("hallazgos=1", contenido)
        finally:
            os.unlink(destino.name)


class ElCliNoSorprende(unittest.TestCase):
    """v0.10.0: banderas que se aceptaban y no se obedecían.

    Aceptar una orden y no cumplirla es la versión de interfaz de aprobar
    sin revisar. Cada caso se reprodujo antes de arreglarse.
    """

    REPO = {"app.py": 'url = "postgres://app:Kx9mPqR2vNw8@db/prod"\n'}

    def test_salida_hacia_directorio_inexistente_es_codigo_2(self):
        # Tronaba con traceback y código 1 — el reservado para «hay
        # hallazgos» — mandando a buscar un dato personal que no existe.
        td = repo_temporal(dict(self.REPO))
        with td:
            codigo, salida = correr_garita(
                Path(td.name), "--formato", "sarif",
                "--salida", "no/existe/x.sarif")
            self.assertEqual(codigo, 2, salida)
            self.assertIn("no pude escribir", salida)

    def test_linea_base_rechaza_formato_y_salida(self):
        # Aceptaba --formato sarif y lo ignoraba: congelaba sin documento.
        td = repo_temporal(dict(self.REPO))
        with td:
            codigo, salida = correr_garita(
                Path(td.name), "--linea-base", "--formato", "sarif")
            self.assertEqual(codigo, 2, salida)
            self.assertIn("--linea-base", salida)

    def test_explicar_rechaza_formato(self):
        td = repo_temporal(dict(self.REPO))
        with td:
            codigo, salida = correr_garita(
                Path(td.name), "--explicar", "--formato", "html")
            self.assertEqual(codigo, 2, salida)

    def test_explicar_de_punta_a_punta(self):
        # El primer comando que el README enseña no tenía ni una prueba.
        td = repo_temporal(dict(self.REPO))
        with td:
            codigo, salida = correr_garita(Path(td.name), "--explicar")
            self.assertEqual(codigo, 0, salida)
            self.assertIn("Detectores activos", salida)

    def test_sin_color_apaga_el_ansi_hasta_en_terminal(self):
        # La bandera existía desde el principio y no se leía en ninguna
        # parte: quien la pasaba seguía recibiendo colores.
        from garita.reporte import imprimir

        class TTY(io.StringIO):
            def isatty(self):
                return True

        td = repo_temporal(dict(self.REPO))
        with td:
            raiz = Path(td.name)
            cfg = cargar_config(raiz)
            res = revisar(raiz, construir(cfg, raiz), cfg.exenciones)
        con, sin = TTY(), TTY()
        # En Actions GITHUB_ACTIONS=true apaga el color por otra vía; hay
        # que despejarla para que la prueba mida solo la bandera.
        with unittest.mock.patch.dict(os.environ, {"GITHUB_ACTIONS": ""}):
            imprimir(res, salida=con)
            imprimir(res, salida=sin, sin_color=True)
        self.assertIn("\x1b[", con.getvalue())
        self.assertNotIn("\x1b[", sin.getvalue())

    def test_fallar_en_aviso_cambia_el_veredicto(self):
        # Las dos ramas del código de salida no tenían ninguna prueba.
        aviso = {"conf.py": 'password = "Kx9mPqR2vNw8LtY4"\n'}
        td = repo_temporal(dict(aviso))
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 0, salida)
        td = repo_temporal({**aviso, ".garita.yml": "fallar_en_aviso: true\n"})
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 1, salida)

    def test_anotaciones_escapan_la_sintaxis(self):
        # «::error file=…,line=…::» usa %, coma y dos puntos como sintaxis:
        # una ruta con coma partía la anotación en dos propiedades.
        from garita.nucleo import Hallazgo, Resultado
        from garita.reporte import anotaciones_github
        h = Hallazgo(archivo="datos, viejos/f.py", linea=3, detector="x",
                     que="q", por_que="50% del riesgo", como_arreglar="rota")
        buf = io.StringIO()
        previo = os.environ.get("GITHUB_ACTIONS")
        os.environ["GITHUB_ACTIONS"] = "true"
        try:
            anotaciones_github(Resultado(hallazgos=[h]), salida=buf)
        finally:
            if previo is None:
                del os.environ["GITHUB_ACTIONS"]
            else:
                os.environ["GITHUB_ACTIONS"] = previo
        linea = buf.getvalue()
        self.assertIn("file=datos%2C viejos/f.py", linea)
        self.assertIn("50%25 del riesgo", linea)


class ElCanalDeActions(unittest.TestCase):
    """v0.14.0: el mismo stdout que GitHub parsea, y los veredictos que
    mentían.

    Una ruta sin escapar era un comando de workflow; una variable de
    entorno rota convertía un repo limpio en «hay hallazgos»; --explicar
    aceptaba órdenes que no iba a cumplir; un symlink rastreado tumbaba
    el hook; --salida vacía volcaba el documento a stdout.
    """

    REPO = {"app.py": 'url = "postgres://app:Kx9mPqR2vNw8@db/prod"\n'}

    @unittest.skipIf(os.name == "nt",
                     "«:» es ilegal en nombres de archivo de Windows")
    def test_ruta_con_prefijo_de_comando_no_inyecta(self):
        # Un archivo llamado «::stop-commands::x» apagaba las anotaciones
        # que siguieran; la vía también forjaba ::error ajenos.
        td = repo_temporal(
            {"::stop-commands::x": 'password = "Kx9mPqR2vNw8LtY4"\n'})
        with td:
            with unittest.mock.patch.dict(
                    os.environ, {"GITHUB_ACTIONS": "true"}):
                codigo, salida = correr_garita(Path(td.name))
        # Las únicas líneas que pueden empezar por «::» son las
        # anotaciones legítimas, que ya escapan sus propiedades.
        for linea in salida.splitlines():
            if linea.startswith("::"):
                self.assertRegex(linea, r"^::(warning|error|notice) ")
        self.assertIn("%3A%3Astop-commands", salida)

    @unittest.skipIf(os.name == "nt",
                     "«:» es ilegal en nombres de archivo de Windows")
    def test_en_terminal_la_ruta_sale_tal_cual(self):
        td = repo_temporal(
            {"::stop-commands::x": 'password = "Kx9mPqR2vNw8LtY4"\n'})
        with td:
            with unittest.mock.patch.dict(
                    os.environ, {"GITHUB_ACTIONS": ""}):
                codigo, salida = correr_garita(Path(td.name))
        self.assertIn("::stop-commands::x", salida)

    def test_github_output_roto_es_error_de_entorno(self):
        # Tronaba con traceback y código 1 —el de «hay hallazgos»— sobre
        # un repo limpio, después de haberlo revisado.
        td = repo_temporal({"limpio.py": 'texto = "hola"\n'})
        with td:
            with unittest.mock.patch.dict(
                    os.environ, {"GITHUB_OUTPUT": "/inexistente/dir/out"}):
                codigo, salida = correr_garita(Path(td.name))
        self.assertEqual(codigo, 2, salida)
        self.assertIn("no pude escribir", salida)

    def test_step_summary_roto_es_error_de_entorno(self):
        td = repo_temporal({"limpio.py": 'texto = "hola"\n'})
        with td:
            with unittest.mock.patch.dict(
                    os.environ,
                    {"GITHUB_STEP_SUMMARY": "/inexistente/dir/sum",
                     "GITHUB_OUTPUT": ""}):
                codigo, salida = correr_garita(Path(td.name))
        self.assertEqual(codigo, 2, salida)

    def test_explicar_rechaza_ordenes_que_no_cumpliria(self):
        # «garita --linea-base --explicar» salía 0 sin congelar nada;
        # «--explicar archivo-con-secreto» salía 0 donde la revisión da 1.
        td = repo_temporal(dict(self.REPO))
        with td:
            for extra in (["--linea-base"], ["--historial"], ["app.py"]):
                codigo, salida = correr_garita(
                    Path(td.name), "--explicar", *extra)
                self.assertEqual(codigo, 2, (extra, salida))
            self.assertFalse((Path(td.name) / ".garita-base.json").exists())

    def test_salida_vacia_es_error_de_uso(self):
        # El caso ordinario en CI: --salida "$RUTA" con la variable sin
        # definir. El documento se volcaba a stdout y el paso siguiente
        # no encontraba archivo.
        td = repo_temporal(dict(self.REPO))
        with td:
            codigo, salida = correr_garita(
                Path(td.name), "--formato", "sarif", "--salida", "")
        self.assertEqual(codigo, 2, salida)
        self.assertNotIn('"$schema"', salida)

    def test_symlink_rastreado_no_tumba_el_hook(self):
        # resolve() seguía el enlace: el que apuntaba fuera «quedaba
        # fuera del repositorio» (código 2) y el roto «no existía»,
        # aunque el repo completo pasara con 0 revisándolos igual.
        td = repo_temporal({"a.py": 'texto = "hola"\n'})
        with td:
            raiz = Path(td.name)
            (raiz / "enlace_fuera.txt").symlink_to("/etc/hosts")
            (raiz / "enlace_roto.txt").symlink_to("no_existe.txt")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            completo, _ = correr_garita(raiz)
            hook, salida = correr_garita(
                raiz, "a.py", "enlace_fuera.txt", "enlace_roto.txt")
            self.assertEqual(0, completo)
            self.assertEqual(completo, hook, salida)

    def test_archivo_inexistente_sigue_rechazado(self):
        td = repo_temporal({"a.py": 'texto = "hola"\n'})
        with td:
            codigo, salida = correr_garita(Path(td.name), "no_existe.py")
        self.assertEqual(codigo, 2, salida)


class LasViasDeCallar(unittest.TestCase):
    """v0.18.0: las dos vías legítimas de callar a Garita, y el filtro de
    la Action — las tres callaban de más.
    """

    CLABE = "002180000645829179"

    def test_un_aviso_congelado_no_absuelve_un_error_nuevo(self):
        # La CLABE dentro de una URL es aviso; a pelo, error. Sin la
        # severidad en la clave, el error nuevo consumía el perdón del
        # aviso viejo y con fallar_en_aviso apagado el veredicto era 0.
        url = f"ver https://banco.invalido/cuenta/{self.CLABE}/estado\n"
        td = repo_temporal({"datos.txt": f"nota\n{url}"})
        with td:
            raiz = Path(td.name)
            codigo, salida = correr_garita(raiz, "--linea-base")
            self.assertEqual(codigo, 0, salida)
            (raiz / "datos.txt").write_text(
                f"CLABE destino: {self.CLABE}\nnota\n{url}", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz)
            self.assertEqual(codigo, 1, salida)

    def test_la_deuda_del_mismo_nivel_sigue_perdonandose(self):
        td = repo_temporal({"datos.txt": f"CLABE {self.CLABE}\n"})
        with td:
            raiz = Path(td.name)
            correr_garita(raiz, "--linea-base")
            codigo, salida = correr_garita(raiz)
            self.assertEqual(codigo, 0, salida)
            self.assertIn("nada nuevo", salida)

    def test_el_asterisco_de_la_exencion_no_cruza_las_barras(self):
        # Con barra en el patrón, la ruta casa por segmentos.
        from garita.nucleo import casa_ruta
        self.assertFalse(casa_ruta("tests_reales/datos.txt", "tests*"))
        self.assertFalse(casa_ruta("tests/algo.txt", "tests*"))
        # Las formas que sí se quieren decir.
        self.assertTrue(casa_ruta("tests/algo.txt", "tests/*"))
        self.assertTrue(casa_ruta("tests/hondo/algo.txt", "tests/**"))
        self.assertTrue(casa_ruta("tests/algo.txt", "tests/**"))
        self.assertTrue(casa_ruta("docs/IDENTIFICADORES.md",
                                  "docs/IDENTIFICADORES.md"))
        self.assertTrue(casa_ruta("src/a/b.py", "**/b.py"))
        self.assertFalse(casa_ruta("src/hondo/b.py", "src/*.py"))

    def test_un_patron_sin_barra_casa_a_cualquier_profundidad(self):
        # La regla de .gitignore, que es la que la gente ya tiene en la
        # cabeza. Anclar TODO patrón a la raíz rompió «*.test.ts» —la
        # forma en que medio mundo exenta sus vectores— en cada repo que
        # lo usaba.
        from garita.nucleo import casa_ruta
        for archivo in ("x.test.ts", "src/lib/validation/ids.test.ts",
                        "a/b/c/d.test.ts"):
            self.assertTrue(casa_ruta(archivo, "*.test.ts"), archivo)
        self.assertTrue(casa_ruta("sub/dir/README.md", "README.md"))
        self.assertFalse(casa_ruta("src/a/notas.md", "*.test.ts"))

    def test_exencion_que_ya_no_casa_se_reporta_muerta(self):
        # Falla ruidosa en vez de absorción silenciosa: quien escribió
        # «tests*» se entera de que quería «tests/**».
        td = repo_temporal({
            "tests_reales/datos.txt": f"CLABE {self.CLABE}\n",
            ".garita.yml": ("exenciones:\n  - archivo: tests*\n"
                            "    motivo: fixtures\n"),
        })
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 1, salida)
            self.assertIn("no aplicaron", salida)

    def test_detectores_en_forma_de_lista_yaml(self):
        # Llegaba como list, str() la volvía «['clabe']» y la exención
        # dejaba de exentar en silencio.
        td = repo_temporal({
            "datos.txt": f"CLABE {self.CLABE}\n",
            ".garita.yml": ("exenciones:\n  - archivo: datos.txt\n"
                            "    motivo: inventados\n"
                            "    detectores:\n      - clabe\n"),
        })
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 0, salida)

    @unittest.skipIf(os.name == "nt", "el escenario usa enlaces simbólicos")
    def test_el_pr_ve_los_cambios_de_tipo_y_las_rutas_con_acentos(self):
        # Dos defectos en el mismo camino: un symlink reemplazado por
        # archivo regular es estado T (excluido por ACMR, el PR salía
        # verde), y las rutas no ASCII venían citadas por git, con lo que
        # la CLI respondía «no existe el archivo» y tumbaba el paso
        # entero con código 2 sin revisar nada.
        import importlib.util
        ruta = Path(__file__).resolve().parent.parent / "scripts/ejecutar.py"
        spec = importlib.util.spec_from_file_location("garita_action", ruta)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        def git(cwd, *args):
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                            *args], cwd=cwd, check=True,
                           capture_output=True)

        with TemporaryDirectory() as d:
            origen = Path(d) / "origen"
            origen.mkdir()
            git(origen, "init", "-q", "-b", "main")
            (origen / "leeme.md").write_text("base\n", encoding="utf-8")
            (origen / "config.txt").symlink_to("/etc/hosts")
            git(origen, "add", "-A")
            git(origen, "commit", "-qm", "base")
            git(origen, "checkout", "-qb", "feature")
            (origen / "config.txt").unlink()
            (origen / "config.txt").write_text(
                f"CLABE destino: {self.CLABE}\n", encoding="utf-8")
            (origen / "señales.csv").write_text(
                f"CLABE {self.CLABE}\n", encoding="utf-8")
            (origen / "leeme.md").write_text("base\nmás\n", encoding="utf-8")
            git(origen, "add", "-A")
            git(origen, "commit", "-qm", "pr")

            clon = Path(d) / "clon"
            subprocess.run(["git", "clone", "-q", f"file://{origen}",
                            str(clon), "--branch", "feature"], check=True,
                           capture_output=True)
            antes = os.getcwd()
            os.chdir(clon)
            try:
                archivos = mod.archivos_del_pr({"GITHUB_BASE_REF": "main"})
            finally:
                os.chdir(antes)
        # El typechange entra, y el nombre con ñ llega sin comillas.
        self.assertIn("config.txt", archivos)
        self.assertIn("señales.csv", archivos)


class HistorialCompleto(unittest.TestCase):
    """La auditoría ve ramas remotas y rutas con acentos. (v0.10.0)"""

    def _commit(self, raiz, mensaje):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                        "commit", "-q", "-m", mensaje], cwd=raiz, check=True)

    def test_la_rama_de_origin_sin_mergear_tambien_se_audita(self):
        # En un clon fresco esa rama sólo existe como ref remota; sin
        # --remotes la auditoría declaraba limpio lo que nunca vio.
        with TemporaryDirectory() as d:
            origen = Path(d) / "origen"
            origen.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"],
                           cwd=origen, check=True)
            (origen / "leeme.md").write_text("hola\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=origen, check=True)
            self._commit(origen, "base")
            subprocess.run(["git", "checkout", "-qb", "fuga"],
                           cwd=origen, check=True)
            (origen / "colado.pem").write_text(
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qWeRtY\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=origen, check=True)
            self._commit(origen, "secreto en rama")
            subprocess.run(["git", "checkout", "-q", "main"],
                           cwd=origen, check=True)
            clon = Path(d) / "clon"
            subprocess.run(["git", "clone", "-q", f"file://{origen}",
                            str(clon)], check=True)
            codigo, salida = correr_garita(clon, "--historial")
            self.assertEqual(codigo, 1, salida)
            self.assertIn("colado.pem", salida)

    def test_ruta_con_ene_se_reporta_entera(self):
        # git la entregaba C-quoted («"pe\303\261a.pem"») y así se
        # reportaba: mutilada y sin coincidir con la misma ruta de rev-list.
        with TemporaryDirectory() as d:
            raiz = Path(d)
            subprocess.run(["git", "init", "-q", "-b", "main"],
                           cwd=raiz, check=True)
            (raiz / "peña.pem").write_text(
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qWeRtY\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            self._commit(raiz, "entra")
            subprocess.run(["git", "rm", "-q", "peña.pem"],
                           cwd=raiz, check=True)
            self._commit(raiz, "sale")
            codigo, salida = correr_garita(raiz, "--historial")
            self.assertEqual(codigo, 1, salida)
            self.assertIn("peña.pem", salida)
            self.assertNotIn("\\303", salida)


class AlcanceDelHistorial(unittest.TestCase):
    """v0.15.0: lo que el alcance de la auditoría todavía no veía.

    Un commit colgado de la HEAD suelta, una ruta con comillas que se
    desdoblaba en fantasma, y los secretos nacidos en un merge sin
    commit de origen.
    """

    def _commit(self, raiz, mensaje):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                        "commit", "-q", "-m", mensaje], cwd=raiz, check=True)

    def test_commit_en_head_suelta_se_audita(self):
        # checkout --detach + commit: alcanzable desde NINGUNA ref. Sin
        # HEAD en el alcance, la auditoría aprobaba con 0 sin revisarlo —
        # el mismo agujero que la guardia de shallow, por otra puerta.
        with TemporaryDirectory() as d:
            raiz = Path(d)
            subprocess.run(["git", "init", "-q", "-b", "main"],
                           cwd=raiz, check=True)
            (raiz / "a.txt").write_text("hola\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            self._commit(raiz, "base")
            subprocess.run(["git", "checkout", "-q", "--detach"],
                           cwd=raiz, check=True)
            (raiz / "secreto.pem").write_text(
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qWeRtY\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            self._commit(raiz, "fuga")
            codigo, salida = correr_garita(raiz, "--historial")
            self.assertEqual(codigo, 1, salida)
            self.assertIn("secreto.pem", salida)

    def test_repo_sin_commits_no_truena(self):
        # HEAD pelón hace fallar a git en un repo recién inicializado; el
        # alcance lo añade sólo cuando resuelve.
        with TemporaryDirectory() as d:
            raiz = Path(d)
            subprocess.run(["git", "init", "-q", "-b", "main"],
                           cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz, "--historial")
            self.assertEqual(codigo, 0, salida)

    @unittest.skipIf(os.name == "nt",
                     "las comillas son ilegales en nombres de Windows")
    def test_ruta_con_comillas_no_desdobla_el_blob(self):
        # `git log --raw` C-quota las comillas aunque quotepath=false;
        # la ruta fantasma citada no casaba con RUTAS_DE_PRUEBA y anulaba
        # la relajación: la llave del fixture salía como ERROR con la
        # ruta mutilada.
        from garita.historial import _descitar
        self.assertEqual('tests/pe"a.pem', _descitar('"tests/pe\\"a.pem"'))
        with TemporaryDirectory() as d:
            raiz = Path(d)
            subprocess.run(["git", "init", "-q", "-b", "main"],
                           cwd=raiz, check=True)
            (raiz / "tests").mkdir()
            (raiz / 'tests/pe"a.pem').write_text(
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qWeRtY\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            self._commit(raiz, "fixture")
            codigo, salida = correr_garita(raiz, "--historial")
            # Una sola ruta, la de pruebas: lo criptográfico se relaja.
            self.assertEqual(codigo, 0, salida)

    def test_el_reporte_nombra_las_otras_rutas_del_blob(self):
        # El reporte nombra la ruta de ORIGEN, que es la que hay que
        # buscar en el historial — pero ésa puede ser la inocente: una
        # llave nacida en tests/fixture.pem y hoy viva en src/secreto.pem
        # se reportaba con el nombre del fixture, el que invita a cerrar
        # el reporte sin mirar.
        with TemporaryDirectory() as d:
            raiz = Path(d)
            subprocess.run(["git", "init", "-q", "-b", "main"],
                           cwd=raiz, check=True)
            (raiz / "tests").mkdir()
            (raiz / "src").mkdir()
            (raiz / "tests/fixture.pem").write_text(
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qWeRtY\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            self._commit(raiz, "nace en tests")
            subprocess.run(["git", "mv", "tests/fixture.pem",
                            "src/secreto.pem"], cwd=raiz, check=True)
            self._commit(raiz, "promovida a src")
            codigo, salida = correr_garita(raiz, "--historial")
        self.assertEqual(codigo, 1, salida)
        self.assertIn("tests/fixture.pem", salida)
        self.assertIn("src/secreto.pem", salida)

    def test_el_origen_es_topologico_no_cronologico(self):
        # `git log` ordena por fecha de committer, que un reloj adelantado
        # o un rebase desordenan: el secreto nacido en una rama lateral se
        # le atribuía al merge que lo trajo —anterior en el reloj,
        # posterior en la historia— y quien limpiaba buscaba en el commit
        # equivocado.
        def commit_en(raiz, mensaje, cuando):
            entorno = {**os.environ, "GIT_COMMITTER_DATE": cuando,
                       "GIT_AUTHOR_DATE": cuando}
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                            "commit", "-q", "-m", mensaje], cwd=raiz,
                           check=True, env=entorno, capture_output=True)

        with TemporaryDirectory() as d:
            raiz = Path(d)
            subprocess.run(["git", "init", "-q", "-b", "main"],
                           cwd=raiz, check=True)
            (raiz / "a.txt").write_text("base\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            commit_en(raiz, "c1", "2026-01-01T00:00:00")
            subprocess.run(["git", "checkout", "-qb", "lado"],
                           cwd=raiz, check=True)
            (raiz / "colado.py").write_text(
                'password = "Kx9mPqR2vNw8LtY4"\n', encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            # El lateral trae fecha POSTERIOR al merge que lo integrará.
            commit_en(raiz, "nace aquí", "2026-03-15T00:00:00")
            lateral = subprocess.run(
                ["git", "rev-parse", "--short=10", "HEAD"], cwd=raiz,
                check=True, capture_output=True, text=True).stdout.strip()
            subprocess.run(["git", "checkout", "-q", "main"],
                           cwd=raiz, check=True)
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                            "merge", "lado", "--no-ff", "-qm", "merge"],
                           cwd=raiz, check=True,
                           env={**os.environ,
                                "GIT_COMMITTER_DATE": "2026-02-01T00:00:00",
                                "GIT_AUTHOR_DATE": "2026-02-01T00:00:00"},
                           capture_output=True)
            codigo, salida = correr_garita(raiz, "--historial")
        self.assertIn(lateral, salida)

    def test_secreto_nacido_en_un_merge_conoce_su_commit(self):
        # `git log --raw` calla en los merges: un secreto metido al
        # resolver (el «arreglo rápido» del conflicto) se reportaba con
        # «desde el commit ? (?)» — justo el dato que quien limpia
        # necesita para buscar en el historial.
        with TemporaryDirectory() as d:
            raiz = Path(d)
            subprocess.run(["git", "init", "-q", "-b", "main"],
                           cwd=raiz, check=True)
            (raiz / "a.txt").write_text("base\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            self._commit(raiz, "c1")
            subprocess.run(["git", "checkout", "-qb", "lado"],
                           cwd=raiz, check=True)
            (raiz / "b.txt").write_text("lado\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            self._commit(raiz, "c2")
            subprocess.run(["git", "checkout", "-q", "main"],
                           cwd=raiz, check=True)
            (raiz / "c.txt").write_text("main\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            self._commit(raiz, "c3")
            # El merge también exige identidad (para el reflog), aunque
            # sea --no-commit; sin las -c truena donde no hay gitconfig
            # global — o sea, en CI y en ninguna máquina de desarrollo.
            subprocess.run(["git", "-c", "user.name=t",
                            "-c", "user.email=t@t", "merge", "lado",
                            "--no-commit", "--no-ff", "-q"],
                           cwd=raiz, check=True)
            (raiz / "colado.py").write_text(
                'password = "Kx9mPqR2vNw8LtY4"\n', encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            self._commit(raiz, "merge con sorpresa")
            codigo, salida = correr_garita(raiz, "--historial")
            self.assertIn("colado.py", salida)
            self.assertNotIn("commit ? (?)", salida)


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
                           "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qWeRtY\n"),
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
        # 9xx con grupo de ITIN (50-65, 70-88, 90-92, 94-99) ya no es
        # «malo»: es un ITIN. Fuera de esos grupos sigue sin ser nada.
        for malo in ("000882074", "666882074", "900452074",
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


class DatosRaspados(unittest.TestCase):
    """Calibración que pidió pokefig: los CDN y las wikis cargan tiras de
    dígitos que validan por azar. Dentro de una URL el hallazgo baja a
    AVISO — visible pero sin romper, porque una CLABE en la ruta de un API
    sí puede ser fuga real y cegarse está prohibido."""

    def _det(self, nombre):
        from garita.detectores.paises import cargar
        return {d.nombre: d for d in cargar(Config())}[nombre]

    def test_id_de_foto_de_instagram_baja_a_aviso(self):
        # El caso literal de pokefig: el segmento de 18 dígitos del CDN de
        # Instagram pasa el módulo de la CLABE y el catálogo de bancos.
        linea = ('"https://scontent.cdninstagram.com/v/t39.30808-6/'
                 '436878177_17891258928005714_902303669466701189_n.jpg"')
        h = list(self._det("clabe").buscar(linea, "x"))
        self.assertTrue(h)
        self.assertEqual(h[0].severidad, "aviso")

    def test_fuera_de_url_sigue_siendo_error(self):
        h = list(self._det("clabe").buscar("CLABE 002180000000001008", "x"))
        self.assertEqual(h[0].severidad, "error")

    def test_aplica_a_todos_los_paises_via_buscador(self):
        # El mismo principio para los detectores que arma `buscador`.
        h = list(self._det("cpf").buscar(
            "https://sitio.br/doc/cpf/111.444.777-35", "x"))
        self.assertTrue(h)
        self.assertEqual(h[0].severidad, "aviso")


class PaisesNuevos2(unittest.TestCase):
    """Ecuador y República Dominicana."""

    def _det(self, nombre):
        from garita.detectores.paises import cargar
        return {d.nombre: d for d in cargar(Config())}[nombre]

    def test_cedula_ec_algoritmo_y_estructura(self):
        from garita.detectores.paises.ec import cedula_ec_valida
        self.assertTrue(cedula_ec_valida("1710034065"))
        self.assertFalse(cedula_ec_valida("1710034066"))
        self.assertFalse(cedula_ec_valida("9910034065"))  # provincia 99
        self.assertFalse(cedula_ec_valida("1770034065"))  # 3er dígito > 5

    def test_cedula_ec_exige_que_la_nombren(self):
        d = self._det("cedula_ec")
        self.assertTrue(list(d.buscar("cédula: 1710034065", "x")))
        self.assertFalse(list(d.buscar("folio 1710034065", "x")))

    def test_cedula_do_luhn_y_contexto(self):
        from garita.detectores.paises.do import cedula_do_valida
        self.assertTrue(cedula_do_valida("00113918205"))
        self.assertFalse(cedula_do_valida("00113918206"))
        d = self._det("cedula_do")
        self.assertTrue(list(d.buscar("cédula 001-1391820-5", "x")))
        self.assertFalse(list(d.buscar("tracking 00113918205", "x")))

    def test_repetidas_exentas(self):
        for nombre, valor in (("cedula_ec", "cédula 2222222222"),
                              ("cedula_do", "cédula 22222222222")):
            d = self._det(nombre)
            self.assertFalse(list(d.buscar(valor, "x")), nombre)

    def test_marca_de_tiempo_no_es_cnpj(self):
        # «"ts": "20010706161900"» —un timestamp del Wayback Machine en
        # pokefig— pasa el doble módulo 11. Catorce dígitos pelones exigen
        # que los nombren; con la puntuación oficial dispara solo.
        d = self._det("cnpj")
        self.assertFalse(list(d.buscar('"ts": "20010706161900",', "x")))
        self.assertTrue(list(d.buscar("empresa 12.345.678/0001-95", "x")))
        self.assertTrue(list(d.buscar("cnpj: 12345678000195", "x")))


class PaisesCalibrados(unittest.TestCase):
    """v0.10.0: los detectores de país contra la vida real del software.

    Cada caso de aquí se reprodujo antes de arreglarse (regla del roadmap).
    """

    def _det(self, nombre):
        from garita.config import Config
        import importlib
        mods = {"ci_uy": "uy", "cif": "es", "nie": "es", "ssn": "us",
                "nit": "co"}
        mod = importlib.import_module(
            f"garita.detectores.paises.{mods[nombre]}")
        return {x.nombre: x for x in mod.detectores(Config())}[nombre]

    def test_uy_la_integracion_continua_no_es_una_cedula(self):
        # «CI corrió el 20250801»: la fecha pasa el módulo 10 y la palabra
        # «ci» — integración continua — la reforzaba. La misma lección que
        # ca.py documenta con «SIN».
        d = self._det("ci_uy")
        self.assertFalse(list(d.buscar("CI corrio el 20250801 sin fallas", "x")))

    def test_uy_con_puntos_o_palabra_completa_si(self):
        d = self._det("ci_uy")
        self.assertTrue(list(d.buscar("c.i. 4.870.913-5 del titular", "x")))
        self.assertTrue(list(d.buscar("cédula 4.870.913-5", "x")))

    def test_es_cif_con_guion_es_la_forma_comun(self):
        d = self._det("cif")
        self.assertTrue(list(d.buscar("proveedor B-58800004 facturando", "x")))

    def test_es_nie_pelon_ya_no_suena_solo(self):
        # Una letra de control es 1/23: «lote X1234567L» valida por azar.
        # Con separadores o con la palabra que lo nombre, sí.
        d = self._det("nie")
        self.assertFalse(list(d.buscar("lote X1234567L revisado", "x")))
        self.assertTrue(list(d.buscar("NIE X1234567L del residente", "x")))
        self.assertTrue(list(d.buscar("doc X-1234567-L", "x")))

    def test_us_itin_por_fin_detectable(self):
        # El contexto anunciaba «itin» pero toda área 9xx se rechazaba.
        d = self._det("ssn")
        self.assertTrue(list(d.buscar("ITIN: 912-70-1234 del contribuyente", "x")))
        # Fuera de los rangos de grupo del IRS sigue sin ser nada.
        self.assertFalse(list(d.buscar("ITIN: 912-45-1234", "x")))
        # Y un SSN normal sigue exigiendo su palabra.
        self.assertTrue(list(d.buscar("SSN: 531-88-2074", "x")))

    def test_co_nit_de_cedula_antigua(self):
        # Las cédulas viejas (hoy NIT de persona natural) tienen base de
        # ocho dígitos; exigir nueve las dejaba todas fuera.
        d = self._det("nit")
        self.assertTrue(list(d.buscar("NIT 12.345.678-8 del proveedor", "x")))
        self.assertTrue(list(d.buscar("NIT 900.123.456-8", "x")))


class CalibracionFinal(unittest.TestCase):
    """v0.16.0: los seis plausibles que cerraron la oleada — 20 de 20.

    Exentos oficiales que los docstrings citaban y el código no exentaba,
    el espacio como refuerzo del CIF, y la base de ocho del NIT
    colombiano cazando folios y RUTs chilenos.
    """

    def _det(self, nombre, mod):
        from garita.config import Config
        import importlib
        m = importlib.import_module(f"garita.detectores.paises.{mod}")
        return {x.nombre: x for x in m.detectores(Config())}[nombre]

    def test_los_rif_de_la_papeleria_oficial_estan_exentos(self):
        # G-20000303-0 (SENIAT) y J-00123072-6 (PDVSA): los vectores del
        # propio docstring. Citar la guía oficial no debe dar error.
        d = self._det("rif", "ve")
        self.assertFalse(list(d.buscar(
            "reproduce el del SENIAT (G-20000303-0) y PDVSA (J-00123072-6)",
            "x")))

    def test_el_nit_del_instructivo_de_la_sat_esta_exento(self):
        d = self._det("nit_gt", "gt")
        self.assertFalse(list(d.buscar("nit: 3602978-5 (ejemplo FEL)", "x")))

    def test_el_ruc_de_puros_ceros_es_relleno(self):
        # Valida en sus cuatro largos (suma 0, residuo 0, dv 0); ve.py y
        # gt.py ya generaban sus repetidos, py.py no.
        d = self._det("ruc_py", "py")
        for v in ("00000-0", "000000-0", "0000000-0", "00000000-0"):
            self.assertFalse(list(d.buscar(f"ruc: {v}", "x")), v)

    def test_cif_el_espacio_solo_no_es_evidencia(self):
        # Con \s en la regex, el mismo espacio que permitía el match
        # satisfacía el refuerzo: «modelo A 1234567 4» era error sin
        # palabra alguna. El separador del CIF es el guion.
        d = self._det("cif", "es")
        self.assertFalse(list(d.buscar("modelo A 1234567 4", "x")))
        # El guion sigue siendo refuerzo y el contexto sigue vivo.
        self.assertTrue(list(d.buscar("titular B-12345674", "x")))
        self.assertTrue(list(d.buscar("CIF A12345674", "x")))

    def test_co_base_de_ocho_exige_la_palabra_que_la_nombra(self):
        # La forma de ocho es exactamente la del RUT chileno y ~10% de los
        # folios de nueve dígitos pasan el dígito de la DIAN: junto a
        # «factura» o «cc» disparaban, y cada RUT bien escrito salía
        # duplicado como NIT del país equivocado.
        d = self._det("nit", "co")
        self.assertFalse(list(d.buscar("Factura 123456788 pagada", "x")))
        self.assertFalse(list(d.buscar("cc: 123456788", "x")))
        self.assertFalse(list(d.buscar("RUT 14.588.824-7", "x")))
        # Nombrado de verdad, sigue detectándose; el chileno sigue siendo
        # del detector chileno.
        self.assertTrue(list(d.buscar("NIT 14.588.824-7", "x")))
        self.assertTrue(list(
            self._det("rut", "cl").buscar("RUT 14.588.824-7", "x")))


class PaisesNuevos3(unittest.TestCase):
    """Venezuela, Paraguay y Guatemala (v0.12.0).

    Los tres entraron con algoritmo reproducido contra vectores públicos:
    el RIF del propio SENIAT y el de PDVSA, los dos RUC de ejemplo de la
    documentación paraguaya, y el NIT del instructivo FEL. Bolivia, Costa
    Rica y Panamá quedaron fuera a propósito — sin fuente verificable no
    hay detector, porque uno aproximado es peor que ninguno.
    """

    def _det(self, nombre, mod):
        from garita.config import Config
        import importlib
        m = importlib.import_module(f"garita.detectores.paises.{mod}")
        return {x.nombre: x for x in m.detectores(Config())}[nombre]

    # ── Venezuela ──
    def test_rif_reproduce_los_publicos(self):
        from garita.detectores.paises.ve import rif_valido
        self.assertTrue(rif_valido("G-20000303-0"))   # SENIAT
        self.assertTrue(rif_valido("J-00123072-6"))   # PDVSA
        self.assertFalse(rif_valido("G-20000303-1"))

    def test_rif_exige_refuerzo(self):
        d = self._det("rif", "ve")
        self.assertTrue(list(d.buscar("RIF: J-12345678-4", "x")))
        # Pelado y sin palabra que lo nombre, se calla.
        self.assertFalse(list(d.buscar("id J123456784 en el lote", "x")))

    def test_rif_repetido_es_relleno(self):
        d = self._det("rif", "ve")
        self.assertFalse(list(d.buscar("RIF J-00000000-0 de prueba", "x")))

    def test_rif_con_letra_c_de_consejo_comunal(self):
        # El SENIAT emite RIF con C (consejos comunales y comunas, migrados
        # de la J desde 2015); C vale 3, igual que J, y la clase del regex
        # la omitía: un RIF C válido ni siquiera casaba. Vector derivado
        # del de PDVSA: mismos dígitos, letra de igual valor.
        from garita.detectores.paises.ve import rif_valido
        self.assertTrue(rif_valido("C-00123072-6"))
        d = self._det("rif", "ve")
        self.assertTrue(list(d.buscar("RIF C-00123072-6 del consejo", "x")))
        # El repetido con C también es relleno.
        self.assertFalse(list(d.buscar("RIF C-00000000-0 de prueba", "x")))

    # ── Paraguay ──
    def test_ruc_py_reproduce_los_de_la_documentacion(self):
        from garita.detectores.paises.py import ruc_py_valido
        self.assertTrue(ruc_py_valido("1946520-3"))
        self.assertTrue(ruc_py_valido("80009735-1"))
        self.assertFalse(ruc_py_valido("80009735-2"))

    def test_ruc_py_exige_contexto(self):
        d = self._det("ruc_py", "py")
        self.assertTrue(list(d.buscar("RUC 80024242-4 del proveedor", "x")))
        # Un rango de líneas con la misma forma no es un RUC.
        self.assertFalse(list(d.buscar("ver lineas 80024242-4", "x")))

    def test_ruc_py_los_ejemplos_oficiales_estan_exentos(self):
        d = self._det("ruc_py", "py")
        self.assertFalse(list(d.buscar("RUC 1946520-3 de ejemplo", "x")))

    # ── Guatemala ──
    def test_nit_gt_reproduce_el_del_instructivo(self):
        from garita.detectores.paises.gt import nit_gt_valido
        self.assertTrue(nit_gt_valido("3602978-5"))
        self.assertFalse(nit_gt_valido("3602978-6"))
        self.assertTrue(nit_gt_valido("1000002-K"))  # el residuo 10 es K

    def test_nit_gt_exige_contexto(self):
        d = self._det("nit_gt", "gt")
        self.assertTrue(list(d.buscar("NIT 5000000-4 del cliente", "x")))
        self.assertFalse(list(d.buscar("rango 5000000-4 del log", "x")))

    def test_nit_gt_repetidos_exentos(self):
        from garita.detectores.paises.gt import nit_gt_valido
        d = self._det("nit_gt", "gt")
        # El repetido que valide, exento; se busca uno vivo para no fijar
        # un literal que dependa del algoritmo.
        for n in range(10):
            v = str(n) * 7
            for dv in "0123456789K":
                if nit_gt_valido(v + dv):
                    self.assertFalse(
                        list(d.buscar(f"NIT {v}-{dv}", "x")), v + dv)


class DeteccionViva(unittest.TestCase):
    """El paso 4 de la lista de publicación, ahora permanente: bajar falsos
    positivos no sirve de nada si la herramienta se volvió ciega, y las dos
    fallas se ven idénticas en la tabla de controles. Cada tipo de detector
    dispara sobre un repo sintético — si uno se apaga, CI lo grita."""

    VECTORES = {
        "secretos": 'k="eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZSJ9.firmaX"',
        "asignacion_sospechosa": 'password = "Kx9mPqR2vNw8LtY4"',
        "curp": "curp: AABB900101HDFCDF09",
        "rfc": "RFC GOPE800101A18",
        "clabe": "CLABE 002180000000001008",
        "nss": "nss: 92988084494",
        "telefono": "cel 55 1234 5678",
        "cuit": "CUIT 20-12345678-6",
        "cpf": "CPF 111.444.777-35",
        "cnpj": "CNPJ 12.345.678/0001-95",
        "rut": "RUT 12.345.678-5",
        "nit": "NIT 900.123.456-8",
        "dni_es": "DNI 10345678W",
        "nie": "NIE X1234567L",
        "cif": "CIF A12345674",
        "iban_es": "IBAN ES91 2100 0418 4502 0005 1332",
        "ruc": "RUC 20100079772",
        "ssn": "SSN: 531-88-2074",
        "sin_ca": "SIN 730 425 618",
        "nif_pt": "NIF: 203456785",
        "cedula_ec": "cédula: 1710034065",
        "cedula_do": "cédula 001-1391820-5",
        "rif": "RIF J-12345678-4",
        "ruc_py": "RUC 80024242-4",
        "nit_gt": "NIT 5000000-4",
    }

    def test_todos_los_tipos_disparan(self):
        archivos = {f"{k}.txt": v + "\n" for k, v in self.VECTORES.items()}
        archivos["gen.py"] = 'PROHIBIDOS = ["Juanito"]\n'
        archivos["clientes.txt"] = "AcmeCorp\n"
        archivos["padron.py"] = 'LOTES = {47: "Juanito Pérez"}\n'
        archivos["caso.md"] = "# Caso AcmeCorp\n"
        archivos[".garita.yml"] = (
            "nombres:\n  - gen.py:PROHIBIDOS\n"
            "clientes:\n  - clientes.txt\n"
            "exenciones:\n"
            "  - archivo: gen.py\n    motivo: fuente\n    detectores: nombre\n"
            "  - archivo: clientes.txt\n    motivo: fuente\n    detectores: cliente\n")
        td = repo_temporal(archivos)
        with td:
            codigo, salida = correr_garita(Path(td.name))
            self.assertEqual(codigo, 1)
            esperados = set(self.VECTORES) | {"nombre", "cliente"}
            muertos = [e for e in esperados
                       if f" {e} " not in salida and f" {e}\n" not in salida]
            self.assertEqual(muertos, [], f"detectores ciegos: {muertos}")


class SeisManerasDeAprobarSinMirar(unittest.TestCase):
    """Séptima oleada (v0.28.0). Seis caminos por los que Garita salía con
    código 0 sobre un dato que sí estaba: tres de ellos abiertos por los
    arreglos de la víspera. Cada prueba de aquí es una versión que se
    publicó rota."""

    CUERPO = ("MIIEowIBAAKCAQEAx7Zq9K3mF2vN8pQr4tYuI6oP0aSdFgHjKlZxCvBnM1qW"
              "eRtY")

    def test_la_llave_de_cuenta_de_servicio_minificada_suena(self):
        # v0.27.0 contaba TOKENS separados por espacio para distinguir la
        # prosa, y un JSON de cuenta de servicio de Google en una línea
        # —la forma canónica en que esa llave se filtra— llega a ocho
        # antes de «"private_key": "». La llave desaparecía con código 0.
        c = self.CUERPO
        for texto in (
            '{"type": "service_account", "project_id": "p", '
            '"private_key_id": "k", "private_key": '
            '"-----BEGIN PRIVATE KEY-----\\n%s\\n-----END PRIVATE KEY-----"}' % c,
            "CREDS = {'type': 'service_account', 'project': 'p', 'key_id': "
            "'k', 'private_key': '-----BEGIN PRIVATE KEY-----\\n%s'}" % c,
            'GCP_SA_KEY: \'{"type": "service_account", "project_id": "p", '
            '"private_key": "-----BEGIN PRIVATE KEY-----\\n%s"}\'' % c,
        ):
            self.assertTrue(list(buscar(texto, "sa.json")), texto[:60])

    def test_la_frase_que_termina_en_dos_puntos_sigue_callada(self):
        # La comilla es obligatoria en `_ASIGNACION`: sin ella vuelve el
        # ruido de la documentación que anuncia el formato.
        self.assertFalse(list(buscar(
            "Provide the contents of a file that begins with: "
            "-----BEGIN RSA PRIVATE KEY-----%s" % self.CUERPO, "docs.md")))

    def test_la_llave_cifrada_y_la_de_pgp_suenan(self):
        # `openssl genpkey -aes256`, `openssl genrsa -aes256` y `openssl
        # pkcs8 -topk8` escriben ENCRYPTED PRIVATE KEY: la forma más común
        # hoy de una llave con contraseña, y no casaba. Y el «PGP» que el
        # patrón anunciaba era letra muerta, porque gpg escribe « BLOCK».
        c = self.CUERPO
        for texto in (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n%s\n" % c,
            "-----BEGIN DSA PRIVATE KEY-----\n%s\n" % c,
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n%s\n" % c,
        ):
            self.assertTrue(list(buscar(texto, "llave.pem")), texto[:45])

    def test_el_valor_pelon_con_prefijo_punteado_se_reporta(self):
        # Gemela de la de v0.24.0, pero en la rama SIN comillas — la que
        # existe justo para el .env, que es donde estos tokens viven. El
        # arreglo de entonces curó la entrecomillada y dejó viva la fuga.
        for linea in (
            "VAULT_TOKEN=hvs.CAESIHrGkQ9tXbW2yL5pAcXdEfGhJkLmNoPqRsTuVwXyZ01",
            "DOPPLER_TOKEN=dp.st.prd.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ab",
            "STRIPE_SECRET=cs.live.9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f00",
        ):
            self.assertTrue(
                list(buscar_asignaciones(linea + "\n", ".env")), linea)

    def test_la_referencia_de_codigo_sigue_callada(self):
        # El contrapeso: lo que se apretó no puede volver a morder el
        # código, que es lo que pone ahí quien hizo las cosas bien.
        for linea in ("password=config.db_password",
                      "token=settings.API_KEY_PRODUCTION",
                      "secret=os.environ[SECRET]",
                      "api_key=c.Config.Password"):
            self.assertFalse(
                list(buscar_asignaciones(linea + "\n", ".env")), linea)

    def test_detectores_vacio_no_exenta_el_archivo_entero(self):
        # Regresión de v0.26.1: al hacer que «[]» se leyera como lista,
        # «detectores: []» pasó de no casar nada —y salir denunciado como
        # exención muerta— a casar TODO. Se lee como «ninguno» y silencia
        # el archivo completo. Se rechaza ruidoso: código 2, no 0.
        for escritura in ("    detectores: []\n", "    detectores:\n"):
            archivos = {
                "app.py": 'TOKEN = "ghp_' + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + '"\n',
                ".garita.yml": ("exenciones:\n  - archivo: app.py\n"
                                "    motivo: pendiente\n" + escritura),
            }
            with repo_temporal(archivos) as td:
                codigo, salida = correr_garita(Path(td))
            self.assertEqual(codigo, 2, escritura)
            self.assertIn("detectores", salida)

    def test_la_exencion_acotada_sigue_exentando(self):
        # El contrapeso del anterior: nombrar los detectores funciona, y
        # «exenciones: []» de nivel superior —lo que arregló v0.26.1—
        # sigue leyéndose como una lista vacía y no como la cadena «[]».
        secreto = 'TOKEN = "ghp_' + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + '"\n'
        with repo_temporal({
            "app.py": secreto,
            ".garita.yml": ("exenciones:\n  - archivo: app.py\n"
                            "    motivo: llave de prueba rotada\n"
                            "    detectores: llave_proveedor\n"),
        }) as td:
            codigo, _ = correr_garita(Path(td))
        self.assertEqual(codigo, 0)
        with repo_temporal({"limpio.txt": "nada\n",
                            ".garita.yml": "exenciones: []\n"}) as td:
            codigo, _ = correr_garita(Path(td))
        self.assertEqual(codigo, 0)

    def test_el_bom_tambien_usa_el_respaldo_por_byte(self):
        # El «CSV UTF-8» de Excel SIEMPRE escribe BOM, así que la rama que
        # más necesitaba el respaldo cp1252 era justo la que no lo tenía:
        # un byte Latin-1 volvía «Cédula» en «C?dula», el contexto dejaba
        # de casar, y el archivo se contaba como REVISADO.
        from garita.nucleo import descifrar
        bom = b"\xef\xbb\xbf"
        cedula = "1719141770"
        for crudo in (
            bom + ("C\xe9dula: %s\n" % cedula).encode("cp1252"),
            # Mezclado: la mitad UTF-8, una línea pegada desde Excel.
            bom + "Año: 2026\n".encode("utf-8")
                + ("C\xe9dula: %s\n" % cedula).encode("cp1252"),
        ):
            texto = descifrar(crudo)
            self.assertIsNotNone(texto)
            self.assertIn("Cédula", texto)

    def test_lo_rastreado_y_ausente_del_arbol_se_lee_del_indice(self):
        # `git sparse-checkout` —soportado por actions/checkout— deja el
        # archivo en el índice y en HEAD, o sea que `git push` lo publica,
        # pero fuera del disco. Garita decidía con `is_file()` y salía con
        # «✓ nada que reportar, 1 omitidos (binarios o muy grandes)».
        llave = "AKIA" + "QWERTYUIOPASDFGH"
        with repo_temporal({"src/main.py": "print('hola')\n",
                            "config/prod.env": "AWS_ACCESS_KEY_ID=%s\n" % llave}) as td:
            raiz = Path(td)
            subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                            "commit", "-qm", "inicial"], cwd=raiz, check=True)
            # Sin sparse-checkout (que necesita un git reciente y config
            # extra), la vía equivalente y más directa: borrar del disco
            # sin `git rm`. El índice y HEAD quedan intactos.
            (raiz / "config" / "prod.env").unlink()
            self.assertIn("config/prod.env",
                          subprocess.run(["git", "ls-files"], cwd=raiz,
                                         capture_output=True, text=True).stdout)
            codigo, salida = correr_garita(raiz)
        self.assertEqual(codigo, 1, salida)
        self.assertIn("prod.env", salida)

    def test_el_borrado_de_verdad_no_inventa_hallazgos(self):
        # El contrapeso: un `git rm` sale de `git ls-files`, así que la
        # rama nueva no se dispara sobre borrados legítimos.
        llave = "AKIA" + "QWERTYUIOPASDFGH"
        with repo_temporal({"a.txt": "hola\n",
                            "viejo.env": "AWS_ACCESS_KEY_ID=%s\n" % llave}) as td:
            raiz = Path(td)
            subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t",
                            "commit", "-qm", "inicial"], cwd=raiz, check=True)
            subprocess.run(["git", "rm", "-q", "viejo.env"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz)
        self.assertEqual(codigo, 0, salida)


class LaExencionNombraLoQueExenta(unittest.TestCase):
    """v0.29.0: `casa_ruta` implementaba dos de las tres reglas de
    gitignore. Faltaba el ANCLAJE, y era el único caso que el usuario no
    podía expresar: «config.json» exentaba también el de cualquier
    subcarpeta y no había forma de decir «sólo el de la raíz». Por eso la
    propuesta de --proponer-exenciones salía más ancha que su hallazgo."""

    def test_la_barra_inicial_ancla_a_la_raiz(self):
        from garita.nucleo import casa_ruta
        self.assertTrue(casa_ruta("config.json", "/config.json"))
        self.assertFalse(casa_ruta("sub/config.json", "/config.json"))
        self.assertFalse(casa_ruta("a/b/config.json", "/config.json"))
        # Anclado con comodín, y anclado con más de un segmento.
        self.assertTrue(casa_ruta("vectores.json", "/*.json"))
        self.assertFalse(casa_ruta("sub/vectores.json", "/*.json"))
        self.assertTrue(casa_ruta("docs/api.md", "/docs/*.md"))
        self.assertFalse(casa_ruta("v1/docs/api.md", "/docs/*.md"))

    def test_las_otras_dos_reglas_de_gitignore_no_cambian(self):
        # El contrapeso que importa: anclar TODO patrón fue la regresión de
        # v0.18.0 que rompió «*.test.ts» en cada repo que lo usaba, y llevó
        # a un consumidor de 53 hallazgos a 320.
        from garita.nucleo import casa_ruta
        self.assertTrue(casa_ruta("src/lib/parse.test.ts", "*.test.ts"))
        self.assertTrue(casa_ruta("sub/dir/README.md", "README.md"))
        self.assertTrue(casa_ruta("tests/a/b/c.py", "tests/**"))
        self.assertFalse(casa_ruta("tests_reales/a.py", "tests*"))

    def test_la_propuesta_no_exenta_mas_de_lo_que_encontro(self):
        # De punta a punta: se pega SÓLO la entrada de la raíz, con su
        # motivo, y el homónimo de la subcarpeta sigue siendo hallazgo.
        clabe = "CLABE 002180000645829179\n"
        with repo_temporal({"vectores.json": clabe,
                            "sub/vectores.json": clabe}) as td:
            raiz = Path(td)
            codigo, propuesta = correr_garita(raiz, "--proponer-exenciones")
            self.assertEqual(codigo, 0)
            self.assertIn("- archivo: /vectores.json", propuesta)
            (raiz / ".garita.yml").write_text(
                "exenciones:\n  - archivo: /vectores.json\n"
                "    motivo: vectores oficiales del catálogo público\n"
                "    detectores: clabe\n", encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=raiz, check=True)
            codigo, salida = correr_garita(raiz)
        self.assertEqual(codigo, 1, salida)
        # El de la subcarpeta sigue siendo hallazgo; el de la raíz, exento.
        self.assertIn("sub/vectores.json", salida)
        self.assertNotIn("\nvectores.json", salida)
