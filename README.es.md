# Tux Health EasyKit (THEK)

**THEK = Tux Health EasyKit**: un botiquín para tu Linux, pensado para quien no es experto en seguridad.

Un menú de terminal para **auditar, escanear, limpiar y endurecer un equipo Linux**, con informes
escritos para que **cualquier IA** (local o en la nube) los lea y te diga qué hacer.

No reinventa nada: pone herramientas conocidas (ClamAV, rkhunter, chkrootkit, Lynis,
[Zero Breach Toolkit](https://github.com/interplains/Zero-Breach-Toolkit) y tu gestor de paquetes)
detrás de un solo menú, lee lo que entregan y lo junta en un informe.

[Read in English](README.md)

> **Un resultado limpio significa "no se encontró nada conocido en lo que se pudo revisar". No
> significa que tu equipo esté a salvo.** Lo que THEK no pudo revisar aparece como
> `UNAVAILABLE`, nunca como limpio. Si crees que te están atacando de forma dirigida, busca ayuda
> experta primero: [Access Now Digital Security Helpline](https://www.accessnow.org/help/).

## Inicio rápido

```sh
git clone <este repositorio> tux-health-easykit
cd tux-health-easykit
python3 THEK_run.py
```

Solo necesita Python 3.9+: sin `pip install` ni dependencias. **La opción 1 · Preparar y
actualizar** muestra qué tienes y qué falta, y actualiza solo eso; **la opción 2 · Revisión total**
después hace todo en una pasada y deja un único informe.

```
python3 THEK_run.py                 # menú (1 = preparar, 2 = todo)
python3 THEK_run.py --audit quick   # sin root, sin red
python3 THEK_run.py --audit full    # pide root una vez
python3 THEK_run.py --install       # instala lo que falte (pregunta antes)
python3 THEK_run.py --doctor        # qué ve THEK en este equipo
python3 THEK_run.py --lang es       # o en; por defecto sigue tu idioma
```

Códigos de salida de `--audit`: `0` nada encontrado, `2` algo crítico, `3` avisos o lagunas.

## Qué hace

| Menú | Qué |
|---|---|
| **1 · Preparar y actualizar** | revisa las herramientas del sistema, Zero Breach Toolkit, sus indicadores de spyware y las firmas de ClamAV, e instala o actualiza solo lo que falta; busca una versión nueva de Zero Breach Toolkit y la toma solo si dices que sí |
| **2 · Revisión total** | todo en una pasada: auditoría completa, journal contra indicadores de spyware, opcionalmente el escaneo de Zero Breach Toolkit, un solo informe y exportación opcional |
| **3 · Revisar ›** | **Auditoría rápida**: actualizaciones y reinicio pendientes, firewall, SELinux/AppArmor, puertos abiertos, permisos de `~/.ssh`, claves autorizadas, programas que arrancan solos, procesos que corren desde `/tmp` o con el ejecutable borrado, antigüedad de las firmas de ClamAV, tokens en nombres de archivo, archivos escribibles por cualquiera, permisos de Flatpak, intentos fallidos de SSH. **Auditoría completa**: lo mismo y, con **una sola** petición de root, rkhunter, chkrootkit, Lynis, integridad de paquetes (`rpm -Va` / `debsums` / `pacman -Qkk`), programas SUID sin paquete, configuración de `sshd`, cuentas sin contraseña, cron del sistema, salud SMART de los discos, nftables. **Antivirus (ClamAV) ›**: actualizar firmas; escanear Descargas, el home, una carpeta o todo el equipo; mover lo detectado a la cuarentena. **Spyware ›**: Zero Breach Toolkit (fijado a un commit revisado) y la revisión de todo el journal de systemd contra sus indicadores (en streaming, sin copia a disco). **Secretos expuestos**: tokens (GitHub, Hugging Face, OpenAI, Anthropic, AWS, Slack) y claves privadas dentro de archivos |
| **4 · Limpiar ›** | caché de paquetes, paquetes sin uso (con vista previa), runtimes Flatpak sin uso, journal antiguo, papelera, miniaturas, coredumps |
| **5 · Proteger ›** | firewall, firmas de ClamAV automáticas, actualizaciones automáticas donde la distro las recomienda, actualizar el sistema ahora (herramienta de la distro, Flatpak, firmware) |
| **6 · Informes ›** | ver el último informe; exportarlo a `output_docs/` como `.md` con fecha y hora (censurado o completo) para que tú se lo des a la IA en la que confíes |

Cada opción primero explica qué hace (si lee o cambia algo, si pide tu clave o usa la red, y cuánto
tarda) y **espera tu sí**. Cuando una opción termina vuelves al menú principal; si respondes que no,
te quedas donde estabas. Toda acción que modifica el sistema **muestra el comando exacto y pregunta
antes**. Nada de lo detectado se borra: va a la cuarentena con un manifiesto. La configuración del
servidor SSH solo se reporta, nunca se edita (una edición mala puede dejarte fuera).

## Distros soportadas

| Familia | Ejemplos | Gestor |
|---|---|---|
| debian | Debian, Ubuntu, Kubuntu, Mint, Pop!_OS, Kali, Raspberry Pi OS | apt |
| fedora | Fedora, Nobara, RHEL, Rocky, AlmaLinux, CentOS Stream | dnf |
| arch | Arch, Manjaro, EndeavourOS | pacman |
| suse | openSUSE Leap / Tumbleweed, SLES | zypper |

Otras distros corren los chequeos genéricos y las acciones de paquetes dicen "no soportado".
chkrootkit no está en los repositorios oficiales de Arch (AUR). En RHEL/Rocky/Alma las herramientas
de seguridad vienen de EPEL. THEK lo sugiere, pero nunca lo activa por ti.

## Privacidad

- **Sin telemetría y sin conexión a ninguna IA.** THEK mismo nunca abre conexiones de red ni
  habla con ninguna IA. La red solo la usan las herramientas detrás de acciones que tú inicias:
  actualizar, instalar, descargar firmas o indicadores.
- **Los informes quedan en tu equipo**, en `~/.local/share/thek/` (`$XDG_DATA_HOME`), con
  carpetas `0700` y archivos `0600`. Solo lo que exportas va a `output_docs/`, que git ignora.
- **Los secretos nunca se guardan completos**: solo su tipo, dónde están y los primeros caracteres.
- **Dos versiones de cada informe**: `report.md` (completo) y `report.redacted.md` (sin tu usuario,
  nombre del equipo, ruta del home, direcciones IP y MAC, correos ni comentarios de claves SSH).
- **La revisión del journal va en streaming.** El journal del sistema se lee línea a línea y nunca
  se copia; al informe solo llegan las líneas que coinciden (máximo 5 por indicador).

## Qué descarga THEK y dónde

THEK es autocontenido: clonas una carpeta y todo lo que necesita vive dentro de ella o viene de
tu distribución.

| Pieza | Dónde | Por qué |
|---|---|---|
| Zero Breach Toolkit (código) | `vendor/zero-breach-toolkit/`, se descarga al primer uso | Python que corre con tu usuario; fijado a un commit revisado y verificado después de bajarlo |
| Sus listas de indicadores (~10 MB) | `vendor/zbt-indicators/` | datos de terceros que cambian seguido |
| ClamAV, rkhunter, chkrootkit, Lynis | tu sistema, con **1 · Preparar y actualizar** | corren como root: los paquetes firmados de tu distro son más seguros que código bajado de la web |
| Exportaciones para tu IA | `output_docs/` | archivos `.md` con fecha que tú entregas |
| Informes internos, cuarentena | `~/.local/share/thek/` | datos sensibles, fuera del repositorio |

`vendor/` y `output_docs/` están en `.gitignore`: nada de eso se commitea ni se publica.

## Actualizar componentes externos

**1 · Preparar y actualizar** baja el historial publicado de Zero Breach Toolkit,
muestra los commits nuevos y un resumen de cambios, y pasa a la versión nueva **solo si dices que
sí**. Después ofrece refrescar las listas de indicadores si faltan o tienen más de 30 días. La versión que THEK fija en la primera
descarga es la que revisaron sus autores; lo más nuevo queda a tu criterio.

## Usar el informe con tu IA

THEK no envía el informe a ninguna parte. **Informes › Exportar para tu IA** deja el
último informe en `output_docs/thek-informe-<fecha>_<hora>-<censurado|completo>.md` e imprime su
ruta y una línea `cd` para copiar:

- **Censurado** (por defecto, Enter): sin tu usuario, nombre del equipo, ruta del home, IPs, MAC,
  correos ni comentarios de claves SSH. Es el que corresponde para IAs en la nube (ChatGPT, Claude,
  Gemini…).
- **Completo** (`c`): incluye todo eso. Dáselo solo a una IA que corra en tu equipo o en la que
  confíes con esos datos.
- En los dos, los secretos (tokens, claves) van recortados.

El archivo empieza con instrucciones para el modelo: adjúntalo o pégalo tal cual en el chat.

Los agentes de terminal (Claude Code, Codex, Aider…) leen [AGENTS.md](AGENTS.md): abre uno en esta
carpeta y pídele "analiza el último informe de THEK".

## Configuración

Todo opcional, todo por variables de entorno:

| Variable | Qué |
|---|---|
| `THEK_LANG` | `es` o `en` |
| `THEK_SCAN_ROOTS` | carpetas extra para la búsqueda de secretos, separadas por `:` |
| `NO_COLOR` | sin colores |

## Recuperar un archivo de la cuarentena

Cada carpeta de `~/.local/share/thek/quarantine/` tiene un `manifest.json` con la ruta original:

```sh
mv ~/.local/share/thek/quarantine/<fecha>/000-archivo /ruta/original/archivo
chmod 644 /ruta/original/archivo
```

## Tests

```sh
python3 test_thek.py      # imprime "ok"
sh tests/containers.sh        # cada distro soportada en contenedores podman
```

## Créditos

THEK solo orquesta estos proyectos; el trabajo de fondo es de ellos:
[ClamAV](https://www.clamav.net/) (GPL-2.0), [rkhunter](https://rkhunter.sourceforge.net/) (GPL-2.0),
[chkrootkit](https://www.chkrootkit.org/), [Lynis](https://cisofy.com/lynis/) (GPL-3.0) y
[Zero Breach Toolkit](https://github.com/interplains/Zero-Breach-Toolkit) (Apache-2.0).

## Licencia

MIT, ver [LICENSE](LICENSE).
