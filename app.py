from flask import Flask, request, jsonify
import bcrypt
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)

#SE NECESITA ENRUTAR 1 X 1 DE FROMA TRANSACCIONAL

# Ruta para renderizar el formulario HTML
def formulario():
    return render_template ('login.html')
# Función para crear la conexión con la base de datos
def create_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",  # Cambia esto si tu base de datos está en otro servidor
            user="root",  # Cambia el usuario si es necesario
            password="",  # Cambia la contraseña si es necesario
            database="stockapp"  # Nombre de la base de datos
        )
        return conn, None
    except Error as e:
        return None, f"Error de conexión: {str(e)}"

# Ruta para registrar un nuevo usuario (vendedor o admin)
@app.route('/registro', methods=['POST'])
def registrar_usuario():
    data = request.get_json()
    usuario = data.get('usuario')
    contrasena = data.get('contrasena')
    nombre = data.get('nombre')
    rol = data.get('rol', 'vendedor')  # Por defecto, rol 'vendedor'

    if not usuario or not contrasena or not nombre:
        return jsonify({"error": "Faltan datos para registrar el usuario"}), 400

    # Comprobar si el nombre de usuario ya existe en la base de datos
    conn, error = create_connection()
    if not conn:
        return jsonify({"error": error}), 500

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE usuario = %s", (usuario,))
        usuario_db = cursor.fetchone()
        if usuario_db:
            return jsonify({"error": "El usuario ya está registrado"}), 409  # 409 Conflict

        # Hashear la contraseña antes de guardarla
        hashed_password = bcrypt.hashpw(contrasena.encode('utf-8'), bcrypt.gensalt())

        # Insertar el nuevo usuario en la base de datos
        cursor.execute("""
            INSERT INTO usuarios (usuario, contrasena, nombre, rol)
            VALUES (%s, %s, %s, %s)
        """, (usuario, hashed_password, nombre, rol))
        conn.commit()

        return jsonify({"message": "Usuario registrado exitosamente"}), 201
    except Error as e:
        return jsonify({"error": f"Error en la base de datos: {str(e)}"}), 500
    finally:
        conn.close()

# Ruta para hacer login (autenticación)
@app.route('/login', methods=['POST'])
def login_usuario():
    data = request.get_json()
    usuario = data.get('usuario')  # 'usuario' en vez de 'username'
    contrasena = data.get('contrasena')  # 'contrasena' en vez de 'password'

    if not usuario or not contrasena:
        return jsonify({"error": "Faltan datos para iniciar sesión"}), 400

    conn, error = create_connection()
    if not conn:
        return jsonify({"error": error}), 500

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios WHERE usuario = %s", (usuario,))
        usuario_db = cursor.fetchone()
        
        if usuario_db and bcrypt.checkpw(contrasena.encode('utf-8'), usuario_db['contrasena'].encode('utf-8')):
            # Login exitoso
            return jsonify({
                "message": "Login exitoso",
                "usuario": usuario_db['usuario'],
                "nombre": usuario_db['nombre'],
                "rol": usuario_db['rol']
            }), 200
        else:
            return jsonify({"error": "Usuario o contraseña incorrectos"}), 401  # Unauthorized
    except Error as e:
        return jsonify({"error": f"Error en la base de datos: {str(e)}"}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)
