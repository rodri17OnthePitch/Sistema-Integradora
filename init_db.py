import sqlite3
import os

DB_PATH = 'parking_system.db'

def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH) 
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Tabla de Usuarios con el nuevo campo 'role'
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL -- admin, seguridad, alumno, maestro
        )
    ''')

    # Tabla de Vehículos
    cursor.execute('''
        CREATE TABLE vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            plate TEXT UNIQUE NOT NULL,
            type TEXT,
            model TEXT,
            year INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Tabla de QR Codes
    cursor.execute('''
        CREATE TABLE qr_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Tabla de Logs
    cursor.execute('''
        CREATE TABLE access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            qr_id INTEGER,
            type TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (qr_id) REFERENCES qr_codes (id)
        )
    ''')

    # --- DATOS SINTÉTICOS CON ROLES ---
    # Formato: (id, nombre, correo, contraseña, rol)
    users_data = [
        (1, 'Estudiante Juan', 'alumno@u.edu', 'pass123', 'alumno'),
        (2, 'Profe Maria', 'maestra@u.edu', 'profe456', 'maestro'),
        (3, 'Admin Sistema', 'admin@u.edu', 'root789', 'admin'),
        (4, 'Guardia Pedro', 'seguridad@u.edu', 'vigila000', 'seguridad')
    ]
    
    # Registramos vehículos solo para los usuarios que los necesitan (alumno, maestro, admin)
    vehicles_data = [
        (1, 'ABC123', 'Sedan', 'Toyota Corolla', 2022),
        (2, 'XYZ789', 'SUV', 'Honda CR-V', 2020),
        (3, 'LMN456', 'Hatchback', 'Mazda 3', 2023)
    ]

    cursor.executemany('INSERT INTO users VALUES (?,?,?,?,?)', users_data)
    cursor.executemany('INSERT INTO vehicles (user_id, plate, type, model, year) VALUES (?,?,?,?,?)', vehicles_data)

    conn.commit()
    conn.close()
    print("Base de datos creada con roles: alumno, maestro, admin y seguridad.")

if __name__ == '__main__':
    init_db()