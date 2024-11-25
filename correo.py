from flask import Flask, render_template, request, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

#SE NECESITA ENRUTAR 1 X 1 DE FROMA TRANSACCIONAL

# Ruta para renderizar el formulario HTML
@app.route('/')
def formulario():
    return render_template('detalle_venta.html')

# Ruta para manejar el envío del formulario
@app.route('/send-email', methods=['POST'])
def send_email():
    try:
        # Obtener datos del formulario
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Configuración del correo
        sender_email = ''  # Correo desde donde se enviará
        receiver_email = ''  # Correo destino
        password = ''  # Contraseña del correo

        # Crear mensaje
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = 'Mensaje de Contacto'

        # Cuerpo del mensaje
        body = f"Nombre: {name}\nCorreo: {email}\nMensaje: {message}"
        msg.attach(MIMEText(body, 'plain'))

        # Conectar al servidor SMTP
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, password)

        # Enviar correo
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()

        # Respuesta JSON para el cliente
        return jsonify({'success': True})

    except Exception as e:
        print(str(e))
        return jsonify({'success': False})

if __name__ == '__main__':
    app.run(debug=True)
