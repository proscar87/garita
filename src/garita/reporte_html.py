#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
El reporte gráfico: un HTML autocontenido para quien no vive en GitHub.

PARA QUIÉN ES

La consola es para quien va a arreglar; la pestaña Security es para quien
trabaja en GitHub. Este archivo es para el tercero que también existe: el
cliente, el auditor, el consejo directivo. Alguien que necesita ver el
resultado de una revisión —sobre todo de una auditoría de historial— en
algo que se abre con doble clic, se imprime y se anexa a un entregable.

TRES REGLAS DE FORMA

1. **Autocontenido de verdad.** Cero peticiones externas: ni fuentes, ni
   scripts, ni CSS de un CDN. Un reporte de seguridad que llama a servidores
   de terceros al abrirse filtra a esos terceros cuándo y dónde se lee. Todo
   va en línea; las gráficas son CSS puro.

2. **Los mismos límites que todo lo demás.** Ningún valor completo: el
   reporte usa el `que` ya recortado, igual que la consola y el SARIF.

3. **La severidad nunca es sólo color.** Cada error lleva su ✗ y cada aviso
   su !, porque el color no le habla a todo el mundo — ni al daltonismo ni
   a la impresora en blanco y negro.
"""
from __future__ import annotations

import html

from . import __version__

_E = html.escape

# Paleta de estatus (fija, validada para ambos fondos): el error y el aviso
# son ESTADO, no series de una gráfica. Siempre acompañados de su icono.
_CSS = """
:root {
  color-scheme: light;
  --fondo: #f9f9f7; --superficie: #fcfcfb;
  --tinta: #0b0b0b; --tinta-2: #52514e; --tinta-suave: #898781;
  --linea: #e1e0d9; --borde: rgba(11,11,11,.10);
  --error: #d03b3b; --aviso: #fab219; --bien: #0ca30c;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --fondo: #0d0d0d; --superficie: #1a1a19;
    --tinta: #ffffff; --tinta-2: #c3c2b7; --tinta-suave: #898781;
    --linea: #2c2c2a; --borde: rgba(255,255,255,.10);
    --error: #d03b3b; --aviso: #fab219; --bien: #0ca30c;
  }
}
@media print { :root { color-scheme: light;
  --fondo: #fff; --superficie: #fff; --tinta: #000; } }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--fondo); color: var(--tinta);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif;
  padding: 40px 20px; }
main { max-width: 860px; margin: 0 auto; display: grid; gap: 22px; }
header h1 { font-size: 24px; letter-spacing: -.01em; }
header p { color: var(--tinta-2); margin-top: 4px; }
.tarjeta { background: var(--superficie); border: 1px solid var(--borde);
  border-radius: 10px; padding: 20px 22px; }
h2 { font-size: 16px; margin-bottom: 12px; }
.fichas { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px; }
.ficha { background: var(--superficie); border: 1px solid var(--borde);
  border-radius: 10px; padding: 14px 16px; }
.ficha b { display: block; font-size: 30px; font-weight: 650; }
.ficha span { color: var(--tinta-2); font-size: 13px; }
.ficha.mal b { color: var(--error); }
.ficha.regular b { color: var(--tinta); }
.veredicto { display: inline-block; padding: 3px 12px; border-radius: 99px;
  font-size: 13px; font-weight: 600; margin-top: 10px;
  border: 1px solid var(--borde); }
.veredicto.bien { color: var(--bien); }
.veredicto.mal { color: var(--error); }
.grafica { display: grid; gap: 8px; }
.fila { display: grid; grid-template-columns: 170px 1fr 60px;
  align-items: center; gap: 10px; font-size: 13px; }
.fila .nombre { color: var(--tinta-2); text-align: right;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.fila .valor { color: var(--tinta-2); font-variant-numeric: tabular-nums; }
.pista { display: flex; height: 14px; }
.seg { height: 14px; }
.seg.error { background: var(--error); }
.seg.aviso { background: var(--aviso); }
.seg:last-child { border-radius: 0 4px 4px 0; }
.seg + .seg { margin-left: 2px; }
.leyenda { display: flex; gap: 18px; margin-top: 10px; font-size: 13px;
  color: var(--tinta-2); }
.leyenda i { font-style: normal; font-weight: 700; }
.leyenda .e { color: var(--error); } .leyenda .a { color: var(--aviso); }
table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
th { text-align: left; color: var(--tinta-suave); font-weight: 600;
  font-size: 12px; text-transform: uppercase; letter-spacing: .04em;
  padding: 6px 10px 6px 0; border-bottom: 1px solid var(--linea); }
td { padding: 8px 10px 2px 0; vertical-align: top;
  border-top: 1px solid var(--linea); }
tr.detalle td { border-top: 0; padding-top: 0; padding-bottom: 10px;
  color: var(--tinta-2); font-size: 13px; }
.marca { font-weight: 700; }
.marca.error { color: var(--error); } .marca.aviso { color: var(--aviso); }
code { font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
.gris { color: var(--tinta-2); } .suave { color: var(--tinta-suave); }
ol.guia { padding-left: 20px; color: var(--tinta-2); display: grid; gap: 6px; }
footer { color: var(--tinta-suave); font-size: 12.5px; text-align: center; }
"""


def _pagina(titulo: str, subtitulo: str, cuerpo: str) -> str:
    return (
        "<!doctype html>\n<html lang=\"es\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>{_E(titulo)}</title>\n<style>{_CSS}</style>\n</head>\n<body>\n"
        f"<main>\n<header><h1>{_E(titulo)}</h1>"
        f"<p>{subtitulo}</p></header>\n{cuerpo}\n"
        f"<footer>Generado por Garita {_E(__version__)} — ningún valor completo "
        f"aparece en este reporte, a propósito.</footer>\n</main>\n</body>\n</html>\n"
    )


def _fichas(pares) -> str:
    filas = []
    for etiqueta, valor, clase in pares:
        filas.append(f'<div class="ficha {clase}"><b>{valor:,}</b>'
                     f'<span>{_E(etiqueta)}</span></div>')
    return f'<div class="fichas">{"".join(filas)}</div>'


def _grafica(titulo: str, conteos: dict[str, tuple[int, int]]) -> str:
    """Barras apiladas error/aviso por clave, en CSS puro.

    El ancho es proporcional al máximo; el número exacto va como texto al
    lado, porque una barra sin número obliga a estimar.
    """
    if not conteos:
        return ""
    tope = max(e + a for e, a in conteos.values()) or 1
    filas = []
    for clave, (e, a) in sorted(conteos.items(),
                                key=lambda kv: -(kv[1][0] + kv[1][1])):
        segs = []
        if e:
            segs.append(f'<div class="seg error" style="width:{e / tope * 100:.1f}%"'
                        f' title="{e} error(es)"></div>')
        if a:
            segs.append(f'<div class="seg aviso" style="width:{a / tope * 100:.1f}%"'
                        f' title="{a} aviso(s)"></div>')
        total = e + a
        filas.append(f'<div class="fila"><span class="nombre">{_E(clave)}</span>'
                     f'<div class="pista">{"".join(segs)}</div>'
                     f'<span class="valor">{total:,}</span></div>')
    leyenda = ('<div class="leyenda"><span><i class="e">✗</i> errores</span>'
               '<span><i class="a">!</i> avisos</span></div>')
    return (f'<section class="tarjeta"><h2>{_E(titulo)}</h2>'
            f'<div class="grafica">{"".join(filas)}</div>{leyenda}</section>')


def _fila_hallazgo(celdas: list[str], severidad: str, detalle: str) -> str:
    marca = "✗" if severidad == "error" else "!"
    clase = "error" if severidad == "error" else "aviso"
    tds = "".join(f"<td>{c}</td>" for c in celdas)
    n = len(celdas) + 1
    return (f'<tr><td><span class="marca {clase}">{marca}</span></td>{tds}</tr>'
            f'<tr class="detalle"><td></td><td colspan="{n - 1}">{detalle}</td></tr>')


def _tabla(encabezados: list[str], filas: list[str]) -> str:
    ths = "<th></th>" + "".join(f"<th>{_E(e)}</th>" for e in encabezados)
    return f"<table><thead><tr>{ths}</tr></thead><tbody>{''.join(filas)}</tbody></table>"


def _seccion_omitidos(omitidos) -> str:
    if not omitidos:
        return ""
    filas = "".join(f'<li><code>{_E(o)}</code> <span class="suave">— {_E(m)}'
                    f"</span></li>" for o, m in omitidos[:10])
    resto = (f'<p class="suave">…y {len(omitidos) - 10} más.</p>'
             if len(omitidos) > 10 else "")
    return (f'<section class="tarjeta"><h2>Sin revisar por tamaño</h2>'
            f'<ul style="padding-left:20px" class="gris">{filas}</ul>{resto}'
            f'<p class="suave" style="margin-top:8px">Un archivo grande es '
            f'justo donde cabe un padrón entero. Revísalos aparte.</p></section>')


def _seccion_reservas(res, cfg=None) -> str:
    """Todo lo que le pone un asterisco al veredicto, en el documento que se
    entrega.

    El HTML es el canal que el docstring de este módulo describe como el
    entregable «para el cliente, el auditor, el consejo directivo», y era el
    más callado de los cuatro: no mencionaba los archivos ilegibles, ni los
    detectores que la configuración apagó, ni las exenciones muertas. Un
    documento que dice «nada que reportar» sobre archivos que nadie leyó
    —o con la mitad de los detectores apagados— no es un entregable, es una
    coartada.
    """
    from .reporte import recortes_de_configuracion

    bloques = []
    if getattr(res, "ilegibles", None):
        filas = "".join(f'<li><code>{_E(a)}</code> <span class="suave">— '
                        f"{_E(m)}</span></li>"
                        for a, m in res.ilegibles[:10])
        bloques.append(
            f"<h3>No se pudieron leer</h3>"
            f'<ul style="padding-left:20px" class="gris">{filas}</ul>'
            f'<p class="suave">Garita no puede decir que están limpios: no '
            f"los miró.</p>")
    for recorte in (recortes_de_configuracion(cfg) if cfg else []):
        bloques.append(f'<p class="gris">Configuración: {_E(recorte)}.</p>')
    if getattr(res, "exenciones_muertas", None):
        filas = "".join(f"<li><code>{_E(p)}</code></li>"
                        for p in res.exenciones_muertas[:10])
        bloques.append(
            f"<h3>Exenciones que no aplicaron</h3>"
            f'<ul style="padding-left:20px" class="gris">{filas}</ul>'
            f'<p class="suave">El archivo se renombró o se borró. Si se '
            f"renombró, lleva revisándose sin exención desde entonces.</p>")
    if not bloques:
        return ""
    return (f'<section class="tarjeta"><h2>Reservas sobre este veredicto</h2>'
            f"{''.join(bloques)}</section>")


def generar(res, raiz: str, fecha: str, base=None, nuevos=None,
            conocidos=None, pagadas=None, cfg=None) -> str:
    """El reporte de una revisión del árbol de trabajo."""
    if nuevos is None:
        nuevos = res.hallazgos
    conocidos = conocidos or []
    pagadas = pagadas or []

    e = sum(1 for h in nuevos if h.severidad == "error")
    a = sum(1 for h in nuevos if h.severidad == "aviso")

    if e:
        veredicto = f'<span class="veredicto mal">✗ {e} error{"es" if e != 1 else ""}</span>'
    elif conocidos and not nuevos:
        veredicto = '<span class="veredicto bien">✓ Nada nuevo — con deuda aceptada</span>'
    elif a:
        veredicto = f'<span class="veredicto mal" style="color:var(--aviso)">! {a} aviso{"s" if a != 1 else ""}</span>'
    else:
        veredicto = '<span class="veredicto bien">✓ Nada que reportar</span>'

    partes = [_fichas([
        ("errores", e, "mal" if e else ""),
        ("avisos", a, "regular" if a else ""),
        ("archivos revisados", res.archivos_revisados, ""),
        ("deuda aceptada", len(conocidos), "regular") if base else
        ("archivos omitidos", res.archivos_omitidos, ""),
    ])]

    conteos: dict[str, tuple[int, int]] = {}
    for h in nuevos:
        pe, pa = conteos.get(h.detector, (0, 0))
        conteos[h.detector] = (pe + (h.severidad == "error"),
                               pa + (h.severidad == "aviso"))
    partes.append(_grafica("Hallazgos por detector", conteos))

    if nuevos:
        filas = [
            _fila_hallazgo(
                [f"<code>{_E(h.archivo)}</code>", str(h.linea),
                 _E(h.detector), f"<code>{_E(h.que)}</code>"],
                h.severidad,
                f"{_E(h.por_que)}<br>→ {_E(h.como_arreglar)}")
            for h in nuevos
        ]
        partes.append(f'<section class="tarjeta"><h2>Hallazgos</h2>'
                      f'{_tabla(["Archivo", "Línea", "Detector", "Qué"], filas)}'
                      f"</section>")

    if conocidos:
        filas = "".join(
            f'<li><code>{_E(h.archivo)}</code> · línea {h.linea} · '
            f"{_E(h.detector)}</li>" for h in conocidos[:20])
        resto = (f'<p class="suave">…y {len(conocidos) - 20} más.</p>'
                 if len(conocidos) > 20 else "")
        partes.append(
            f'<section class="tarjeta"><h2>Deuda aceptada — línea base del '
            f"{_E(base.creada)}</h2>"
            f'<ul style="padding-left:20px" class="gris">{filas}</ul>{resto}'
            f'<p class="suave" style="margin-top:8px">No reprueba el build, '
            f"pero tampoco desaparece: una línea base es una promesa de "
            f"limpiar después.</p></section>")

    if pagadas:
        filas = "".join(f"<li><code>{_E(p)}</code></li>" for p in pagadas[:10])
        # El «…y N más» que sus dos hermanas ya emiten: sin él, quien
        # regenera la línea base guiándose por este documento cree que la
        # lista que ve es toda la lista.
        resto = (f'<p class="suave">…y {len(pagadas) - 10} más.</p>'
                 if len(pagadas) > 10 else "")
        partes.append(
            f'<section class="tarjeta"><h2>Deuda pagada</h2>'
            f'<ul style="padding-left:20px" class="gris">{filas}</ul>{resto}'
            f'<p class="suave" style="margin-top:8px">Entradas de la línea '
            f"base que ya no corresponden a nada. Regenera con "
            f"<code>garita --linea-base</code> para achicar el archivo."
            f"</p></section>")

    partes.append(_seccion_omitidos(res.omitidos_grandes))
    partes.append(_seccion_reservas(res, cfg))

    sub = (f"Revisión del árbol de trabajo · <code>{_E(raiz)}</code> · "
           f"{_E(fecha)} · {veredicto}")
    return _pagina("Garita — reporte de revisión", sub, "\n".join(p for p in partes if p))


def generar_historial(res, raiz: str, fecha: str) -> str:
    """El reporte de una auditoría de historial: el entregable."""
    e, a = len(res.errores), len(res.avisos)
    muertos = [h for h in res.hallazgos if not h.vivo]
    vivos = [h for h in res.hallazgos if h.vivo]

    veredicto = (
        f'<span class="veredicto mal">✗ {e} error{"es" if e != 1 else ""} en el historial</span>'
        if e else
        (f'<span class="veredicto mal" style="color:var(--aviso)">! {a} aviso{"s" if a != 1 else ""}</span>'
         if a else '<span class="veredicto bien">✓ Historial limpio</span>'))

    partes = [_fichas([
        ("errores", e, "mal" if e else ""),
        ("avisos", a, "regular" if a else ""),
        ("versiones de archivo revisadas", res.blobs_revisados, ""),
        ("commits", res.commits, ""),
    ])]

    conteos: dict[str, tuple[int, int]] = {}
    anios: dict[str, tuple[int, int]] = {}
    for hh in res.hallazgos:
        h = hh.hallazgo
        pe, pa = conteos.get(h.detector, (0, 0))
        conteos[h.detector] = (pe + (h.severidad == "error"),
                               pa + (h.severidad == "aviso"))
        anio = hh.fecha[:4] if hh.fecha[:4].isdigit() else "¿?"
        pe, pa = anios.get(anio, (0, 0))
        anios[anio] = (pe + (h.severidad == "error"),
                       pa + (h.severidad == "aviso"))
    partes.append(_grafica("Hallazgos por detector", conteos))
    if len(anios) > 1:
        partes.append(_grafica("Por año en que entraron al repositorio", anios))

    def tabla_de(hs):
        filas = []
        for hh in hs:
            h = hh.hallazgo
            duracion = (f" · {hh.versiones} versiones" if hh.versiones > 1 else "")
            # La ruta que encabeza es la de ORIGEN, que puede ser la
            # inocente: una llave nacida en un fixture y viva hoy en src/
            # se anunciaba con el nombre del fixture.
            otras = getattr(hh, "otras_rutas", ())
            tambien = ("<br><span class='suave'>también en: "
                       + ", ".join(_E(r) for r in otras[:5]) + "</span>"
                       if otras else "")
            filas.append(_fila_hallazgo(
                [f"<code>{_E(h.archivo)}</code>{tambien}",
                 f"<code>{_E(hh.commit)}</code><br><span class='suave'>"
                 f"{_E(hh.fecha)}{duracion}</span>",
                 _E(h.detector), f"<code>{_E(h.que)}</code>"],
                h.severidad, _E(h.por_que)))
        return _tabla(["Archivo", "Entró en", "Detector", "Qué"], filas)

    if muertos:
        partes.append(
            f'<section class="tarjeta"><h2>Sólo en el historial — se borró '
            f"del árbol, pero git no olvida</h2>"
            f'<p class="gris" style="margin-bottom:10px">Estos datos ya no '
            f"están en ningún archivo actual y siguen en cada clon y cada "
            f"fork del repositorio.</p>{tabla_de(muertos)}"
            f'<ol class="guia" style="margin-top:14px">'
            f"<li>Si es una credencial, <b>rotarla hoy</b>: eso invalida "
            f"todas las copias; lo demás es limpieza.</li>"
            f"<li>Si es un dato personal, evaluar limpiar el historial "
            f"(<code>git-filter-repo</code>) con respaldo previo y avisando "
            f"a quien haya clonado. Garita no reescribe historia: esa "
            f"decisión es humana.</li>"
            f"<li>Si es legítimo, exentar la ruta en <code>.garita.yml</code> "
            f"con su motivo.</li></ol></section>")

    if vivos:
        partes.append(
            f'<section class="tarjeta"><h2>Todavía en el árbol</h2>'
            f'<p class="gris" style="margin-bottom:10px">La revisión normal '
            f"también los ve; se arreglan como siempre.</p>{tabla_de(vivos)}"
            f"</section>")

    if not res.hallazgos:
        partes.append('<section class="tarjeta"><h2>Historial limpio</h2>'
                      '<p class="gris">Ninguna versión de ningún archivo '
                      "trae datos personales ni credenciales detectables."
                      "</p></section>")

    partes.append(_seccion_omitidos(res.omitidos_grandes))
    partes.append(_seccion_reservas(res))

    sub = (f"Auditoría del historial completo · <code>{_E(raiz)}</code> · "
           f"{_E(fecha)} · {veredicto}")
    return _pagina("Garita — auditoría de historial", sub,
                   "\n".join(p for p in partes if p))
