# Sistema de Estacionamiento Inteligente

Sistema web para la gestión de accesos vehiculares mediante códigos QR dinámicos.

## Roles
- **Usuario:** Consulta información de su vehículo y genera hasta 2 QR de acceso por día.
- **Seguridad:** Escanea códigos QR vía cámara web o lector USB para registrar entradas y salidas.
- **Administrador:** Visualiza el historial completo de movimientos con datos de usuario y vehículo.

## Requisitos
- Python 3.x
- Flask
- QRCode
- Pillow

## Instalación y Uso
1. Instalar dependencias:
   ```bash
   pip install -r requirements.txt
   ```
2. Inicializar la base de datos:
   ```bash
   python init_db.py
   ```
3. Ejecutar la aplicación:
   ```bash
   python app.py
   ```
4. Acceder en el navegador a: `http://localhost:5000`

## Estructura del Proyecto
- `app.py`: Servidor Flask y lógica de negocio.
- `init_db.py`: Configuración inicial de la base de datos SQLite.
- `templates/`: Vistas HTML.
- `static/`: Estilos CSS y scripts JS.
- `parking_system.db`: Base de datos (se genera al ejecutar init_db).
