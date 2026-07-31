import os
import zipfile
import tempfile
import struct
import pkcs11
from pkcs11 import KeyType, ObjectClass, Mechanism
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"ENCA3"

def _get_keys(session):
    pub_keys = list(session.get_objects({
        pkcs11.Attribute.CLASS: ObjectClass.PUBLIC_KEY,
        pkcs11.Attribute.KEY_TYPE: KeyType.RSA
    }))
    priv_keys = list(session.get_objects({
        pkcs11.Attribute.CLASS: ObjectClass.PRIVATE_KEY,
        pkcs11.Attribute.KEY_TYPE: KeyType.RSA
    }))
    if not pub_keys or not priv_keys:
        raise Exception("Chaves RSA não encontradas no Token.")
    return pub_keys[0], priv_keys[0]

def encrypt_path(input_path: str, output_path: str, pkcs11_lib: str, pin: str):
    is_dir = os.path.isdir(input_path)
    target_path = input_path
    temp_zip = None

    if is_dir:
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
        with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(input_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(input_path))
                    zf.write(file_path, arcname)
        target_path = temp_zip

    lib = pkcs11.lib(pkcs11_lib)
    token = next(lib.get_tokens())
    
    with token.open(user_pin=pin) as session:
        pub_key, _ = _get_keys(session)
        
        # Gerar chave AES-256
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        
        with open(target_path, 'rb') as f:
            plaintext = f.read()
            
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Encriptar chave AES com RSA Pública do Token
        encrypted_aes_key = pub_key.encrypt(aes_key, mechanism=Mechanism.RSA_PKCS)
        
        with open(output_path, 'wb') as f:
            f.write(MAGIC)
            f.write(struct.pack('>B', 1 if is_dir else 0))
            f.write(struct.pack('>H', len(encrypted_aes_key)))
            f.write(encrypted_aes_key)
            f.write(nonce)
            f.write(ciphertext)
            
    if temp_zip and os.path.exists(temp_zip):
        os.remove(temp_zip)

def decrypt_path(input_path: str, output_dir: str, pkcs11_lib: str, pin: str) -> str:
    lib = pkcs11.lib(pkcs11_lib)
    token = next(lib.get_tokens())
    
    with token.open(user_pin=pin) as session:
        _, priv_key = _get_keys(session)
        
        with open(input_path, 'rb') as f:
            magic = f.read(5)
            if magic != MAGIC:
                raise Exception("Arquivo não é um cofre EncryptA3 válido.")
                
            is_dir = struct.unpack('>B', f.read(1))[0] == 1
            key_len = struct.unpack('>H', f.read(2))[0]
            encrypted_aes_key = f.read(key_len)
            nonce = f.read(12)
            ciphertext = f.read()
            
        # Decifrar chave AES com RSA Privada
        aes_key = priv_key.decrypt(encrypted_aes_key, mechanism=Mechanism.RSA_PKCS)
        
        # Decifrar arquivo
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        base_name = os.path.basename(input_path).replace('.cofre', '')
        
        if is_dir:
            temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
            with open(temp_zip, 'wb') as f:
                f.write(plaintext)
            
            out_folder = os.path.join(output_dir, base_name)
            os.makedirs(out_folder, exist_ok=True)
            with zipfile.ZipFile(temp_zip, 'r') as zf:
                zf.extractall(out_folder)
            
            os.remove(temp_zip)
            return out_folder
        else:
            out_file = os.path.join(output_dir, base_name)
            with open(out_file, 'wb') as f:
                f.write(plaintext)
            return out_file
