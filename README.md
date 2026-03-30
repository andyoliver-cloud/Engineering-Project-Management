# CivilPM — Gestor de Proyectos para Ingeniería Civil

Aplicación web para gestión de proyectos de ingeniería civil, diseñada para
ejecutarse en un Synology NAS y ser accesible por todos los usuarios de la red local.

---

## Requisitos

- **Python 3.8+** (preinstalado en la mayoría de los Synology NAS)
- **Flask** (`pip install flask`)

---

## Instalación Rápida

```bash
# 1. Copiar la carpeta 'civilpm' a tu Synology NAS
#    (por ejemplo, a /volume1/apps/civilpm/)

# 2. Instalar Flask
pip install flask

# 3. Ejecutar la aplicación
cd /volume1/apps/civilpm
python3 app.py
```

La aplicación estará disponible en: `http://<IP-DEL-NAS>:5100`

---

## Configuración en Synology NAS (paso a paso)

### Opción A: Usando Docker (Recomendado)

Si tu NAS tiene Docker (Container Manager), esta es la forma más limpia:

1. **Instala Container Manager** desde el Centro de Paquetes del Synology.

2. **Crea un `Dockerfile`** en la carpeta del proyecto:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install flask
EXPOSE 5100
CMD ["python3", "app.py"]
```

3. **Construye y ejecuta el contenedor:**
   - En Container Manager → Project → Create
   - Selecciona la carpeta con el proyecto
   - O desde SSH:
     ```bash
     cd /volume1/docker/civilpm
     docker build -t civilpm .
     docker run -d --name civilpm -p 5100:5100 -v /volume1/docker/civilpm/data:/app civilpm
     ```

4. El contenedor se reiniciará automáticamente con el NAS.


### Opción B: Ejecución Directa con Python

1. **Habilita SSH** en tu Synology:
   Panel de Control → Terminal y SNMP → Habilitar servicio SSH

2. **Conéctate por SSH:**
   ```bash
   ssh admin@<IP-DEL-NAS>
   ```

3. **Instala Python3 y pip** (si no están):
   - Panel de Control → Centro de Paquetes → instalar "Python 3"
   - O desde SSH: `sudo apt-get install python3 python3-pip`

4. **Copia los archivos** a una carpeta compartida:
   ```bash
   mkdir -p /volume1/apps/civilpm
   # Copia app.py y la carpeta static/ a /volume1/apps/civilpm/
   ```

5. **Instala Flask:**
   ```bash
   pip3 install flask
   ```

6. **Ejecuta la aplicación:**
   ```bash
   cd /volume1/apps/civilpm
   python3 app.py
   ```

7. **Para que se ejecute al iniciar el NAS**, crea una tarea programada:
   - Panel de Control → Programador de Tareas → Crear → Tarea Activada
   - Evento: Inicio
   - Script: `cd /volume1/apps/civilpm && python3 app.py &`

---

## Acceso desde la Red Local

Una vez ejecutándose, cualquier computadora o dispositivo conectado
a la misma red puede acceder a:

```
http://<IP-DEL-NAS>:5100
```

Por ejemplo: `http://192.168.1.50:5100`

Para encontrar la IP de tu NAS:
- Abre Synology DSM → Panel de Control → Red → Interfaz de Red
- O desde la computadora: `ping <nombre-del-NAS>`

---

## Estructura de Archivos

```
civilpm/
├── app.py              ← Servidor Flask (backend)
├── static/
│   └── index.html      ← Interfaz web (frontend)
├── civilpm.db           ← Base de datos SQLite (se crea automáticamente)
├── Dockerfile           ← (Opcional, para Docker)
└── README.md            ← Este archivo
```

---

## Primer Uso

1. Abre `http://<IP-DEL-NAS>:5100` en cualquier navegador.
2. La primera cuenta que crees será la de **Administrador**.
3. El admin puede resetear contraseñas de otros usuarios.
4. Todos los demás usuarios se registran normalmente.

---

## Notas Técnicas

- **Base de datos:** SQLite con WAL mode (soporta múltiples lectores simultáneos).
- **Seguridad:** Contraseñas hasheadas con SHA-256. Adecuado para uso en red local.
- **Puerto:** 5100 por defecto. Puedes cambiarlo editando la última línea de `app.py`.
- **Backup:** Para respaldar, simplemente copia el archivo `civilpm.db`.
