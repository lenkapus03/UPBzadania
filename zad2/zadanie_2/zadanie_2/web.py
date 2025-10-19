import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, Response, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import struct

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'

db = SQLAlchemy(app)

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela
    - public_key: verejny kluc pouzivatela

    Poznamka: mozete si lubovolne upravit tabulku podla vlastnych potrieb
'''
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    public_key = db.Column(db.String(1200), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


with app.app_context():
    db.create_all()

def generate_rsa_keypair():
    """Generate new RSA keypair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_aes_symetric_key():
    """Generate new AES symetric key"""
    return os.urandom(32)  # 32 bytes = 256 bits

def generate_aes_IV():
    """Generate new AES IV (initialization vector)"""
    return os.urandom(12)

def serialize_private_key(private_key):
    """Serialize a private key"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(public_key):
    """Serialize a public key (no encryption needed)"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data):
    """Deserialize a PEM-encoded public key"""
    return serialization.load_pem_public_key(pem_data)


def create_user(username: str, public_key_bytes):
    """Create new user or update public key if user already exists"""
    user = User.query.filter_by(username=username).first()
    if user:
        # User exists → update public key
        user.public_key = public_key_bytes.decode()
    else:
        # User does not exist → create new
        user = User(username=username, public_key=public_key_bytes.decode())
        db.session.add(user)
    db.session.commit()
    return user


@app.route('/api/users', methods=['GET'])
def list_users():
    """Return all users in the database - testing purposes"""
    users = User.query.all()
    result = []
    for u in users:
        result.append({
            "id": u.id,
            "username": u.username,
            "public_key": u.public_key
        })
    return jsonify(result)


'''
    API request na generovanie klucoveho paru pre pozuivatela <user>
    - user: meno pouzivatela, pre ktoreho sa ma vygenerovat klucovy par
    - API volanie musi vygenerovat klucovy par pre pozuivatela <user> a verejny kluc ulozit do databazy
    - API volanie musi vratit privatny kluc pouzivatela <user> (v binarnom formate)

    ukazka: curl 127.0.0.1:1337/api/gen/ubp --output ubp.key
'''
@app.route('/api/gen/<user>', methods=['GET'])
def generate_keypair(user):
    # 1. Generate RSA keypair
    private_key, public_key = generate_rsa_keypair()

    # 2. Serialize keys
    private_pem = serialize_private_key(private_key)  # no password
    public_pem = serialize_public_key(public_key)

    # 3. Store public key in database along with username
    create_user(user, public_pem)

    # 4. Return private key in binary form for download
    return Response(
        private_pem,
        content_type='application/octet-stream',
        headers={"Content-Disposition": f"attachment; filename={user}.key"}
    )

'''
    API request na zasifrovanie suboru pre pouzivatela <user>
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/ubp -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted.bin
'''
@app.route('/api/encrypt/<user>', methods=['POST'])
def encrypt_file(user):
    # 1. Načíta obsah súboru
    file_content = request.data
    if not file_content:
        return jsonify({'error': 'No file content provided'}), 400

    # 2. Načíta verejný kľúč používateľa z databázy
    user_record = User.query.filter_by(username=user).first()
    if not user_record:
        return jsonify({'error': f'User {user} not found'}), 404

    # 3. Deserializuje verejný kľúč z PEM formátu
    public_key = deserialize_public_key(user_record.public_key.encode())

    # 4. Vygeneruje náhodný 256-bitový symetrický kľúč pre AES
    symmetric_key = generate_aes_symetric_key()

    # 5. Vygeneruj náhodný IV (initialization vector) pre AES
    iv = generate_aes_IV()

    # 6. Zašifruj obsah súboru pomocou AES-256 v GCM móde
    encryptor  = Cipher(
        algorithms.AES(symmetric_key),
        modes.GCM(iv),
    ).encryptor()
    ciphertext = encryptor.update(file_content) + encryptor.finalize()
    tag = encryptor.tag  # Authentication tag

    # 7. Zašifruj symetrický kľúč verejným RSA kľúčom používateľa
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 8. Vytvor výsledný formát súboru:
    # [dĺžka zašifrovaného kľúča (4 byty)] + [zašifrovaný kľúč] + [IV (12 bytov)] + [tag(16B)] + [zašifrovaný obsah]
    encrypted_key_length = struct.pack('<I', len(encrypted_key))  # 4 byty, little-endian

    result = encrypted_key_length + encrypted_key + iv + tag + ciphertext

    # 9. Vráť zašifrovaný súbor
    return Response(
        result,
        content_type='application/octet-stream',
        headers={"Content-Disposition": f"attachment; filename=encrypted.bin"}
    )


'''
    API request na desifrovanie
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted.bin" -F "key=@ubp.key" --output decrypted.pdf
'''
@app.route('/api/decrypt', methods=['POST'])
def decrypt_file():
    # 1. Načítaj zašifrovaný súbor a privátny kľúč z multipart požiadavky
    encrypted_file = request.files.get('file')
    key = request.files.get('key')
    if not encrypted_file or not key:
        return jsonify({'error': 'Missing file or key parameter'}), 400

    # 2. Načítaj obsah zašifrovaného súboru
    encrypted_data = encrypted_file.read()
    if len(encrypted_data) < 4:
        return jsonify({'error': 'Invalid encrypted file format'}), 400

    # 3. Deserializuj privátny kľúč z PEM formátu
    private_key = serialization.load_pem_private_key(
        key.read(),
        password=None
    )

    # 4. Parsuj formát zašifrovaného súboru
    try:
        # Prečítaj dĺžku zašifrovaného symetrického kľúča (prvé 4 byty)
        offset = 0
        encrypted_key_length = struct.unpack('<I', encrypted_data[offset:offset + 4])[0]
        offset += 4

        # Prečítaj zašifrovaný symetrický kľúč
        encrypted_symmetric_key = encrypted_data[offset:offset + encrypted_key_length]
        offset += encrypted_key_length

        # Prečítaj IV (12 bytov)
        iv = encrypted_data[offset:offset + 12]
        offset += 12

        # Prečítaj authentication tag (16 bytov)
        tag = encrypted_data[offset:offset + 16]
        offset += 16

        # Zvyšok je zašifrovaný obsah súboru
        ciphertext = encrypted_data[offset:]

    except Exception as e:
        return jsonify({'error': f'Failed to parse encrypted file: {str(e)}'}), 400

    # 5. Dešifruj symetrický kľúč pomocou privátneho RSA kľúča
    try:
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        return jsonify({'error': f'Failed to decrypt symmetric key: {str(e)}'}), 400

    # 6. Dešifruj obsah súboru pomocou AES-256-GCM
    try:
        decryptor = Cipher(
            algorithms.AES(symmetric_key),
            modes.GCM(iv, tag),
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    except Exception as e:
        return jsonify(
            {'error': f'Failed to decrypt file content. Possible integrity check failure: {str(e)}'}), 400

    # 7. Vráť dešifrovaný súbor
    return Response(
        plaintext,
        content_type='application/octet-stream',
        headers={"Content-Disposition": "attachment; filename=decrypted.pdf"}
    )


'''
    API request na podpisanie dokumentu
    - vstup: subor ktory sa ma podpisat a privatny kluc

    ukazka: curl -X POST 127.0.0.1:1337/api/sign -F "file=@document.pdf" -F "key=@ubp.key" --output signature.bin
'''
@app.route('/api/sign', methods=['POST'])
def sign_file():
    file = request.files.get('file')
    key = request.files.get('key')

    # Chybaju parametre
    if not file or not key:
        return jsonify({'error': 'Missing file or key parameter'}), 400

    # Precitame subor a deserializujeme privatny kluc
    file_data = file.read()
    private_key = serialization.load_pem_private_key(key.read(), password=None)

    # Skusime vytvorit podpis
    try:
        signature = private_key.sign(
            file_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception as e:
        return jsonify({'error': f'Failed to sign file: {str(e)}'}), 400


    return Response(
        signature,
        content_type='application/octet-stream',
        headers={"Content-Disposition": "attachment; filename=signature.bin"}
    )


'''
    API request na overenie podpisu pre pouzivatela <user>
    - vstup: digitalny podpis a subor

    ukazka: curl -X POST 127.0.0.1:1337/api/verify/upb -F "file=@document.pdf" -F "signature=@signature.bin" --output signature.bin
'''
@app.route('/api/verify/<user>', methods=['POST'])
def verify_signature(user):
    file = request.files.get('file')
    signature = request.files.get('signature')

    if not file or not signature:
        return jsonify({'error': 'Missing file or signature parameter'}), 400

    file_data = file.read()
    signature_data = signature.read()

    user_record = User.query.filter_by(username=user).first()
    if not user_record:
        return jsonify({'error': f'User {user} not found'}), 404

    public_key = deserialize_public_key(user_record.public_key.encode())

    try:
        public_key = public_key.verify(
            signature_data,
            file_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        verified = True
    except Exception:
        verified = False

    return jsonify({'verified': verified})



'''
    API request na zasifrovanie suboru pre pouzivatela <user> (verzia s kontrolou integrity)
    user: meno pouzivatela, ktoremu sa ma subor zasifrovat
    vstup: subor, ktory sa ma zasifrovat

    ukazka: curl -X POST 127.0.0.1:1337/api/encrypt/ubp -H "Content-Type: application/octet-stream" --data-binary @file.pdf --output encrypted_file.bin
'''
@app.route('/api/encrypt2/<user>', methods=['POST'])
def encrypt_file2(user):
    # 1. Načíta obsah súboru
    file_content = request.data
    if not file_content:
        return jsonify({'error': 'No file content provided'}), 400

    # 2. Načíta verejný kľúč používateľa z DB
    user_record = User.query.filter_by(username=user).first()
    if not user_record:
        return jsonify({'error': f'User {user} not found'}), 404

    # 3. Deserializuje verejný kľúč
    public_key = deserialize_public_key(user_record.public_key.encode())

    # 4. Vygeneruje náhodný 256-bitový symetrický kľúč pre AES
    symmetric_key = generate_aes_symetric_key()  # očakáva 32 bytov

    # 5. Vygeneruj náhodný IV (12 bytov vhodných pre GCM)
    iv = generate_aes_IV()  # očakáva 12 bytov

    # 6. Zašifruj obsah pomocou AES-256-GCM a použijeme AAD = zašifrovaný sym. kľúč (po jeho RSA-šifrovaní)
    #    Aby sme AAD mali, najprv zašifrujeme symetrický kľúč pomocou RSA (public_key).
    try:
        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        return jsonify({'error': f'Failed to encrypt symmetric key with RSA: {str(e)}'}), 500

    # 7. AES-GCM: použijeme zašifrovaný sym. kľúč ako AAD (to väzní integritu medzi časťami)
    encryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.GCM(iv),
    ).encryptor()

    # pridať AAD
    encryptor.authenticate_additional_data(encrypted_key)

    ciphertext = encryptor.update(file_content) + encryptor.finalize()
    tag = encryptor.tag

    # 8. Skomponuj výstup: [4B length] + [encrypted_key] + [IV(12)] + [tag(16)] + [ciphertext]
    encrypted_key_length = struct.pack('<I', len(encrypted_key))
    result = encrypted_key_length + encrypted_key + iv + tag + ciphertext

    # 9. Vráť binárny výsledok
    return Response(
        result,
        content_type='application/octet-stream',
        headers={"Content-Disposition": f"attachment; filename=encrypted2.bin"}
    )


'''
    API request na desifrovanie (verzia s kontrolou integrity)
    - vstup: zasifrovany subor ktory sa ma desifrovat a privatny kluc pouzivatela

    ukazka: curl -X POST 127.0.0.1:1337/api/decrypt -F "file=@encypted_file.bin" -F "key=@ubp.key" --output decrypted_file.pdf
'''
@app.route('/api/decrypt2', methods=['POST'])
def decrypt_file2():
    # 1. Načítaj zasifrovaný subor a privátny kľúč z multipart požiadavky
    encrypted_file = request.files.get('file')
    key = request.files.get('key')
    if not encrypted_file or not key:
        return jsonify({'error': 'Missing file or key parameter'}), 400

    # 2. Načítaj obsah zašifrovaného súboru
    encrypted_data = encrypted_file.read()
    if len(encrypted_data) < 4:
        return jsonify({'error': 'Invalid encrypted file format'}), 400

    # 3. Deserializuj privátny kľúč z PEM formátu
    try:
        private_key = serialization.load_pem_private_key(
            key.read(),
            password=None
        )
    except Exception as e:
        return jsonify({'error': f'Failed to load private key: {str(e)}'}), 400

    # 4. Parsuj formát súboru
    try:
        offset = 0
        encrypted_key_length = struct.unpack('<I', encrypted_data[offset:offset + 4])[0]
        offset += 4

        encrypted_symmetric_key = encrypted_data[offset:offset + encrypted_key_length]
        offset += encrypted_key_length

        iv = encrypted_data[offset:offset + 12]
        offset += 12

        tag = encrypted_data[offset:offset + 16]
        offset += 16

        ciphertext = encrypted_data[offset:]
    except Exception as e:
        return jsonify({'error': f'Failed to parse encrypted file: {str(e)}'}), 400

    # 5. Dešifruj symetrický kľúč pomocou RSA privátneho kľúča
    try:
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        # Ak sa nezda decrypt sym. kľúča => nie je možné pokračovať
        return jsonify({'error': f'Failed to decrypt symmetric key: {str(e)}'}), 400

    # 6. Dešifruj obsah AES-GCM a použijeme AAD = encrypted_symmetric_key (to kontroluje integritu)
    try:
        decryptor = Cipher(
            algorithms.AES(symmetric_key),
            modes.GCM(iv, tag),
        ).decryptor()

        # pridať AAD rovnaký ako pri šifrovaní (v encrypt2 sme použili encrypted_key ako AAD)
        decryptor.authenticate_additional_data(encrypted_symmetric_key)

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    except Exception as e:
        # Tu typicky dostaneme chybu pri finalize() ak tag nepasuje => integrita porušená
        return jsonify({'error': f'Integrity check failed during decryption: {str(e)}'}), 400

    # 7. Vráť dešifrovaný obsah
    return Response(
        plaintext,
        content_type='application/octet-stream',
        headers={"Content-Disposition": "attachment; filename=decrypted2.bin"}
    )



if __name__ == '__main__':
    app.run(port=1337)