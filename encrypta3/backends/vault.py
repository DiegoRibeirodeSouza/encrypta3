import os
import zipfile
import tempfile
import struct
import pkcs11
from pkcs11 import KeyType, ObjectClass, Mechanism
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import math
import shutil

try:
    from argon2.low_level import hash_secret_raw, Type as ArgonType
except ImportError:
    pass

def _secure_wipe(path: str):
    if not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        with open(path, 'r+b') as f:
            f.write(os.urandom(size))
    except Exception:
        pass
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


MAGIC = b"ENCA4"
CHUNK_SIZE = 64 * 1024

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

def auto_discover_pkcs11() -> str:
    common_paths = [
        "/usr/lib/safesign-private/libaetpkss.so.3",
        "/usr/lib/libaetpkss.so.3",
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib/libeTPkcs11.so",
        "/usr/lib/x86_64-linux-gnu/libeToken.so",
        "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
    ]
    for p in common_paths:
        if os.path.exists(p):
            return p
    return None

def encrypt_path(input_path: str, output_path: str, pkcs11_lib: str, pin: str, recovery_password: str = None, wipe_original: bool = False):
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

    aes_key = AESGCM.generate_key(bit_length=256)
    
    encrypted_aes_key_token = b""
    if pin:
        if not pkcs11_lib:
            pkcs11_lib = auto_discover_pkcs11()
            if not pkcs11_lib:
                raise Exception("Driver PKCS#11 não encontrado. Especifique manualmente.")
        lib = pkcs11.lib(pkcs11_lib)
        try:
            token = next(lib.get_tokens())
        except StopIteration:
            raise Exception("Nenhum Token A3 detectado. Verifique se ele está conectado na porta USB.")
        with token.open(user_pin=pin) as session:
            pub_key, _ = _get_keys(session)
            try:
                encrypted_aes_key_token = pub_key.encrypt(aes_key, mechanism=Mechanism.RSA_PKCS_OAEP)
            except (pkcs11.exceptions.MechanismInvalid, pkcs11.exceptions.DataInvalid):
                encrypted_aes_key_token = pub_key.encrypt(aes_key, mechanism=Mechanism.RSA_PKCS)

    has_pwd = 1 if recovery_password else 0
    salt = b""
    encrypted_aes_key_pwd = b""
    nonce_pwd = b""
    
    if has_pwd:
        salt = os.urandom(16)
        derived_key = hash_secret_raw(
            secret=recovery_password.encode('utf-8'),
            salt=salt,
            time_cost=3, memory_cost=65536, parallelism=4,
            hash_len=32, type=ArgonType.ID
        )
        aesgcm_pwd = AESGCM(derived_key)
        nonce_pwd = os.urandom(12)
        encrypted_aes_key_pwd = aesgcm_pwd.encrypt(nonce_pwd, aes_key, None)

    aesgcm_file = AESGCM(aes_key)
    nonce_file = os.urandom(12)
    
    with open(output_path, 'wb') as f_out:
        f_out.write(MAGIC)
        f_out.write(struct.pack('>B', 1 if is_dir else 0))
        f_out.write(struct.pack('>B', has_pwd))
        
        f_out.write(struct.pack('>H', len(encrypted_aes_key_token)))
        if encrypted_aes_key_token:
            f_out.write(encrypted_aes_key_token)
            
        if has_pwd:
            f_out.write(salt)
            f_out.write(nonce_pwd)
            f_out.write(struct.pack('>H', len(encrypted_aes_key_pwd)))
            f_out.write(encrypted_aes_key_pwd)
            
        f_out.write(nonce_file)
        
        target_size = os.path.getsize(target_path)
        total_chunks = math.ceil(target_size / CHUNK_SIZE) if target_size > 0 else 0
        f_out.write(struct.pack('>I', total_chunks))
        
        chunk_idx = 0
        with open(target_path, 'rb') as f_in:
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                current_nonce = nonce_file[:8] + struct.pack('>I', chunk_idx)
                enc_chunk = aesgcm_file.encrypt(current_nonce, chunk, None)
                f_out.write(struct.pack('>I', len(enc_chunk)))
                f_out.write(enc_chunk)
                chunk_idx += 1
                
    if temp_zip and os.path.exists(temp_zip):
        _secure_wipe(temp_zip)

    if wipe_original:
        if is_dir:
            for root, dirs, files in os.walk(input_path, topdown=False):
                for name in files:
                    _secure_wipe(os.path.join(root, name))
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except OSError:
                        pass
            try:
                os.rmdir(input_path)
            except OSError:
                pass
        else:
            _secure_wipe(input_path)

def decrypt_path(input_path: str, output_dir: str, pkcs11_lib: str = None, pin: str = None, recovery_password: str = None) -> str:
    with open(input_path, 'rb') as f:
        magic = f.read(5)
        if magic != MAGIC:
            raise Exception("Arquivo não é um cofre EncryptA4 válido.")
            
        is_dir = struct.unpack('>B', f.read(1))[0] == 1
        has_pwd = struct.unpack('>B', f.read(1))[0] == 1
        
        key_len = struct.unpack('>H', f.read(2))[0]
        encrypted_aes_key_token = f.read(key_len) if key_len > 0 else b""
        
        salt = b""
        nonce_pwd = b""
        encrypted_aes_key_pwd = b""
        if has_pwd:
            salt = f.read(16)
            nonce_pwd = f.read(12)
            pwd_key_len = struct.unpack('>H', f.read(2))[0]
            encrypted_aes_key_pwd = f.read(pwd_key_len)
            
        nonce_file = f.read(12)
        
        total_chunks = struct.unpack('>I', f.read(4))[0]
        
        aes_key = None
        
        if pin and encrypted_aes_key_token:
            if not pkcs11_lib:
                pkcs11_lib = auto_discover_pkcs11()
            lib = pkcs11.lib(pkcs11_lib)
            try:
                token = next(lib.get_tokens())
            except StopIteration:
                raise Exception("Nenhum Token A3 detectado. Verifique se ele está conectado na porta USB.")
            with token.open(user_pin=pin) as session:
                _, priv_key = _get_keys(session)
                aes_key = priv_key.decrypt(encrypted_aes_key_token, mechanism=Mechanism.RSA_PKCS)
        elif recovery_password and has_pwd:
            derived_key = hash_secret_raw(
                secret=recovery_password.encode('utf-8'),
                salt=salt,
                time_cost=3, memory_cost=65536, parallelism=4,
                hash_len=32, type=ArgonType.ID
            )
            aesgcm_pwd = AESGCM(derived_key)
            aes_key = aesgcm_pwd.decrypt(nonce_pwd, encrypted_aes_key_pwd, None)
        else:
            raise Exception("Nenhum método de decriptação válido fornecido (PIN do Token ou Senha).")

        aesgcm_file = AESGCM(aes_key)
        
        base_name = os.path.basename(input_path).replace('.ea3', '')
        
        temp_out = None
        if is_dir:
            temp_out = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
            out_target = temp_out
        else:
            out_target = os.path.join(output_dir, base_name)
            
        with open(out_target, 'wb') as f_out:
            for chunk_idx in range(total_chunks):
                len_bytes = f.read(4)
                if not len_bytes or len(len_bytes) < 4:
                    raise Exception("Arquivo truncado ou corrompido! Blocos ausentes.")
                chunk_len = struct.unpack('>I', len_bytes)[0]
                enc_chunk = f.read(chunk_len)
                if len(enc_chunk) < chunk_len:
                    raise Exception("Arquivo truncado ou corrompido! Dados ausentes no bloco.")
                
                current_nonce = nonce_file[:8] + struct.pack('>I', chunk_idx)
                plaintext_chunk = aesgcm_file.decrypt(current_nonce, enc_chunk, None)
                f_out.write(plaintext_chunk)
                
    if is_dir and temp_out:
        out_folder = os.path.join(output_dir, base_name)
        os.makedirs(out_folder, exist_ok=True)
        with zipfile.ZipFile(temp_out, 'r') as zf:
            zf.extractall(out_folder)
        _secure_wipe(temp_out)
        return out_folder
        
    return out_target
