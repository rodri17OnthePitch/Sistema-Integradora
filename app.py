import os
import sqlite3
import qrcode
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, send_file, url_for, session, redirect, flash
from io import BytesIO
app = Flask(__name__)
app.secret_key = 'mi_llave_secreta_muy_segura' # Necesario para usar session
DB_PATH = 'parking_system.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role_selected = request.form.get('role')

        conn = get_db_connection()
        # Buscamos al usuario que coincida con correo, pass y rol
        user = conn.execute(
            'SELECT * FROM users WHERE email = ? AND password = ? AND role = ?',
            (email, password, role_selected)
        ).fetchone()
        conn.close()

        if user:
            # Guardamos datos en la sesión
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['user_name'] = user['name']

            # Redirección según el rol
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'seguridad':
                return redirect(url_for('security_dashboard'))
            else: # Alumno o Maestro
                return redirect(url_for('user_dashboard', user_id=user['id']))
        else:
            flash('Credenciales incorrectas o tipo de cuenta no coincide.', 'error')
            
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# --- RUTAS DE USUARIO ---
@app.route('/user/<int:user_id>')
def user_dashboard(user_id):
    if 'user_id' not in session or session['user_id'] != user_id:
        return redirect(url_for('index'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user['role'] == 'seguridad':
        conn.close()
        return redirect('/security')
    elif user['role'] == 'admin':
        conn.close()
        return redirect('/admin')
    vehicle = conn.execute('SELECT * FROM vehicles WHERE user_id = ?', (user_id,)).fetchone()
    today = datetime.now().strftime('%Y-%m-%d')
    codes_today = conn.execute(
        "SELECT count(*) as count FROM qr_codes WHERE user_id = ? AND date(created_at) = ?", 
        (user_id, today)
    ).fetchone()['count']
    
    logs = conn.execute('''
        SELECT al.*, q.token 
        FROM access_logs al 
        JOIN qr_codes q ON al.qr_id = q.id 
        WHERE q.user_id = ? 
        ORDER BY al.timestamp DESC
    ''', (user_id,)).fetchall()
    
    conn.close()
    return render_template('user.html', user=user, vehicle=vehicle, codes_today=codes_today, logs=logs)

@app.route('/generate_qr/<int:user_id>', methods=['POST'])
def generate_qr(user_id):
    conn = get_db_connection()
    
    # 1. Verificar límite diario
    today = datetime.now().strftime('%Y-%m-%d')
    count = conn.execute(
        "SELECT count(*) as count FROM qr_codes WHERE user_id = ? AND date(created_at) = ?", 
        (user_id, today)
    ).fetchone()['count']
    
    if count >= 2:
        conn.close()
        return jsonify({'error': 'Límite de 2 códigos por día alcanzado.'}), 400
    
    # 2. Obtener la placa del vehículo para el QR
    vehicle = conn.execute('SELECT plate FROM vehicles WHERE user_id = ?', (user_id,)).fetchone()
    if not vehicle:
        conn.close()
        return jsonify({'error': 'No hay vehículo registrado para este usuario.'}), 404

    # 3. Crear token basado en PLACA + TIMESTAMP (para que sea único por sesión)
    # Ejemplo: ABC123-20260318-1
    timestamp_str = datetime.now().strftime('%Y%m%d%H%M%S')
    token = f"{vehicle['plate']}-{timestamp_str}"
    
    conn.execute('INSERT INTO qr_codes (user_id, token) VALUES (?, ?)', (user_id, token))
    conn.commit()
    conn.close()
    
    return jsonify({'token': token})

@app.route('/qr_image/<token>')
def qr_image(token):
    # El QR ahora contiene la información de la placa codificada en el token
    img = qrcode.make(token)
    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

# --- SECURITY ROUTES ---
@app.route('/security')
def security_dashboard():
    return render_template('security.html')
@app.route('/scan', methods=['POST'])
def scan_qr():
    if 'role' not in session or session['role'] != 'seguridad':
        return jsonify({'error': 'No autorizado'}), 403

    token = request.json.get('token')
    conn = get_db_connection()
    
    query = '''
        SELECT q.id as qr_id, q.created_at, q.user_id, 
               u.name, v.plate, v.model
        FROM qr_codes q
        JOIN users u ON q.user_id = u.id
        JOIN vehicles v ON u.id = v.user_id
        WHERE q.token = ?
    '''
    qr_data = conn.execute(query, (token,)).fetchone()
    
    if not qr_data:
        conn.close()
        return jsonify({'status': 'CÓDIGO NO ENCONTRADO', 'error': True}), 404
    
    # Validación de tiempo (24 horas)
    created_at = datetime.strptime(qr_data['created_at'].split('.')[0], '%Y-%m-%d %H:%M:%S')
    
    # Inicializamos variables de respuesta
    status = ""
    is_error = False

    if datetime.now() > created_at + timedelta(hours=24):
        status = 'CÓDIGO EXPIRADO: Han pasado más de 24 horas'
        is_error = True
    else:
        # Lógica de Logs
        logs = conn.execute('SELECT type FROM access_logs WHERE qr_id = ?', (qr_data['qr_id'],)).fetchall()
        log_types = [l['type'] for l in logs]
        
        if len(log_types) == 0:
            status = 'ENTRADA REGISTRADA'
            conn.execute('INSERT INTO access_logs (qr_id, type) VALUES (?, ?)', (qr_data['qr_id'], 'ENTRY'))
            conn.commit()
        elif len(log_types) == 1 and 'ENTRY' in log_types:
            status = 'SALIDA REGISTRADA'
            conn.execute('INSERT INTO access_logs (qr_id, type) VALUES (?, ?)', (qr_data['qr_id'], 'EXIT'))
            conn.commit()
        else:
            status = 'CÓDIGO INVÁLIDO: Uso completo (Entrada/Salida)'
            is_error = True

    conn.close()
    
    return jsonify({
        'status': status,
        'is_error': is_error,
        'user': qr_data['name'],
        'plate': qr_data['plate'],
        'model': qr_data['model']
    })
# --- ADMIN ROUTES ---
@app.route('/admin')
def admin_dashboard():
    conn = get_db_connection()
    # Join everything for the final report
    reports = conn.execute('''
        SELECT u.name, v.plate, v.model, al.type, al.timestamp
        FROM access_logs al
        JOIN qr_codes q ON al.qr_id = q.id
        JOIN users u ON q.user_id = u.id
        JOIN vehicles v ON u.id = v.user_id
        ORDER BY al.timestamp DESC
    ''').fetchall()
    conn.close()
    return render_template('admin.html', reports=reports)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
