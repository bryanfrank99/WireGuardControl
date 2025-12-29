from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
import routeros_api
import os
import secrets
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

import sys

if getattr(sys, 'frozen', False):
    # Ejecutándose como bundle (PyInstaller)
    template_folder = os.path.join(sys._MEIPASS, 'templates')
    static_folder = os.path.join(sys._MEIPASS, 'static')
    app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
else:
    # Ejecutándose normal
    app = Flask(__name__)

app.secret_key = secrets.token_hex(16)  # Necesario para sesiones

VERSION = "1.2"

@app.context_processor
def inject_version():
    return dict(version=VERSION)

def format_bytes(size):
    power = 2**10
    n = 0
    power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

@app.template_filter('human_bytes')
def human_bytes_filter(s):
    try:
        if s is None: return "0 B"
        return format_bytes(int(s))
    except:
        return "0 B"

# Helpers para conexión
def generate_wg_keys():
    """Genera un par de claves Private/Public de WireGuard (Curve25519)."""
    private_key = x25519.X25519PrivateKey.generate()
    
    # Serializar Private Key a bytes y luego b64
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_b64 = base64.b64encode(private_bytes).decode('utf-8')
    
    # Derivar Public Key
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    public_b64 = base64.b64encode(public_bytes).decode('utf-8')
    
    return private_b64, public_b64



# Helpers para conexión
def get_api_connection():
    if 'host' not in session:
        return None
    
    try:
        host = session['host']
        port = 8728 # Default API port
        
        if ':' in host:
            host_parts = host.split(':')
            host = host_parts[0]
            try:
                port = int(host_parts[1])
            except ValueError:
                pass # Use default if not valid
        
        connection = routeros_api.RouterOsApiPool(
            host,
            username=session['username'],
            password=session['password'],
            port=port,
            plaintext_login=True # A veces necesario para versiones viejas o config específica
        )
        api = connection.get_api()
        return api
    except Exception as e:
        print(f"Error de conexión: {e}")
        return None

# ... (Rutas de login, logout, index, add_peer, delete_peer se mantienen igual) ...

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['host'] = request.form.get('host')
        session['username'] = request.form.get('username')
        session['password'] = request.form.get('password')
        
        # Verificar conexión
        api = get_api_connection()
        if api:
            return redirect(url_for('index'))
        else:
            session.clear()
            return render_template('login.html', error="No se pudo conectar al Router. Verifique IP/Credenciales y que el servicio API esté activo.")
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'host' not in session:
        return redirect(url_for('login'))
    
    api = get_api_connection()
    if not api:
        return redirect(url_for('login'))
        
    filtered_peers = []
    try:
        # Obtener lista de peers
        peers_resource = api.get_resource('/interface/wireguard/peers')
        all_peers = peers_resource.get()
        
        # Filtrar: solo mostrar peers que tengan metadatos (comentario)
        for peer in all_peers:
            if peer.get('comment'):
                filtered_peers.append(peer)
                
    except Exception as e:
        flash(f"Error al obtener peers: {str(e)}")

    new_peer_id = session.pop('new_peer_id', None)
    return render_template('index.html', peers=filtered_peers, new_peer_id=new_peer_id)

@app.route('/add_peer', methods=['POST'])
def add_peer():
    if 'host' not in session:
        return redirect(url_for('login'))
        
    api = get_api_connection()
    if not api:
        return redirect(url_for('login'))

    # Obtener datos del form
    interface = 'wg-server' # Hardcoded as per requirement
    name = request.form.get('name') # Este será el comentario
    allowed_address = request.form.get('allowed_address')
    
    # Generar claves automáticamente
    _, public_key = generate_wg_keys() # Private key descartada (se generará nueva al descargar)
    
    if allowed_address and name:
        try:
            peers_resource = api.get_resource('/interface/wireguard/peers')
            new_peer = peers_resource.add(
                interface=interface,
                public_key=public_key,
                allowed_address=allowed_address,
                comment=name # Guardamos el nombre como comentario
            )
            
            # Intentar obtener ID
            new_id = new_peer.get('id') if isinstance(new_peer, dict) else getattr(new_peer, 'id', None)
            
            # Si no devuelve el objeto (depende versión lib), buscamos por comentario
            if not new_id:
                 # Pequeño delay o reintento podría ser necesario, pero probamos directo
                 created_peers = peers_resource.get(comment=name)
                 if created_peers:
                     new_id = created_peers[0].get('id')
            
            if new_id:
                session['new_peer_id'] = new_id
                
            flash("Peer añadido correctamente. Descargando configuración...")
        except Exception as e:
            flash(f"Error al añadir peer: {str(e)}")
    else:
        flash("Faltan datos requeridos (Nombre o IP)")
            
    return redirect(url_for('index'))

@app.route('/delete_peer', methods=['POST'])
def delete_peer():
    if 'host' not in session:
        return redirect(url_for('login'))
        
    peer_id = request.form.get('peer_id')
    if peer_id:
        try:
            api = get_api_connection()
            peers_resource = api.get_resource('/interface/wireguard/peers')
            peers_resource.remove(id=peer_id)
            flash("Peer eliminado")
        except Exception as e:
            flash(f"Error al eliminar: {str(e)}")
            
    return redirect(url_for('index'))

@app.route('/toggle_peer', methods=['POST'])
def toggle_peer():
    if 'host' not in session:
        return redirect(url_for('login'))
        
    peer_id = request.form.get('peer_id')
    current_status = request.form.get('current_status') # 'true' (disabled) or 'false' (enabled)
    
    if peer_id:
        try:
            api = get_api_connection()
            peers_resource = api.get_resource('/interface/wireguard/peers')
            
            # Si disabled='true', queremos activarlo (disabled='false')
            new_status = 'false' if current_status == 'true' else 'true'
            
            peers_resource.set(id=peer_id, disabled=new_status)
            flash(f"Peer {'activado' if new_status == 'false' else 'desactivado'} correctamente")
        except Exception as e:
            flash(f"Error al cambiar estado: {str(e)}")
            
    return redirect(url_for('index'))

@app.route('/download_peer/<peer_id>')
def download_peer(peer_id):
    if 'host' not in session:
        return redirect(url_for('login'))
    
    api = get_api_connection()
    if not api:
        return redirect(url_for('login'))
    
    mode = request.args.get('mode', 'lite') # 'lite' or 'full'
        
    try:
        # 1. Obtener datos del Peer
        peers_resource = api.get_resource('/interface/wireguard/peers')
        peer = peers_resource.get(id=peer_id)
        if not peer:
            flash("Peer no encontrado")
            return redirect(url_for('index'))
        
        peer_data = peer[0]
        
        # 2. Key Generation (Only for Full Mode)
        client_private_key = None
        if mode == 'full':
            new_private_key, new_public_key = generate_wg_keys()
            client_private_key = new_private_key
            # Update RouterOS with new Public Key
            peers_resource.set(id=peer_id, public_key=new_public_key)
            # Update peer_data locally to reflect changes if needed
            peer_data['public-key'] = new_public_key
        
        # 3. Obtener datos del Servidor
        interface_resource = api.get_resource('/interface/wireguard')
        server_interface_name = peer_data.get('interface', 'wg-server')
        server_interfaces = interface_resource.get(name=server_interface_name)
        
        if not server_interfaces:
            server_interfaces = interface_resource.get()
            
        if not server_interfaces:
            flash("No se encontró la interfaz del servidor")
            return redirect(url_for('index'))
            
        server_data = server_interfaces[0]
        
        # 4. Construir Configuración
        client_address = peer_data.get('allowed-address', '').split(',')[0]
        server_pub_key = server_data.get('public-key', 'UNKNOWN')
        server_port = server_data.get('listen-port', '51820')
        endpoint_ip = session.get('host', '').split(':')[0]
        
        config_content = ""
        
        if mode == 'full':
             config_content += f"""[Interface]
PrivateKey = {client_private_key}
"""

        config_content += f"""Address = {client_address}
DNS = 94.140.14.14, 94.140.15.15

[Peer]
PublicKey = {server_pub_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {endpoint_ip}:{server_port}
"""
        
        # 5. Descarga
        filename_suffix = "-FULL" if mode == 'full' else "-LITE"
        filename = f"wg-{peer_data.get('comment', 'client').replace(' ', '_')}{filename_suffix}.conf"
        
        return Response(
            config_content,
            mimetype="text/plain",
            headers={"Content-Disposition": f"attachment;filename={filename}"}
        )

    except Exception as e:
        flash(f"Error al generar configuración: {str(e)}")
        return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(debug=True, port=5000)
