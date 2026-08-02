import os
import zipfile
import tempfile
import struct
import pkcs11
from pkcs11 import KeyType, ObjectClass, Mechanism
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import math
import shutil
import unicodedata
import io

try:
    from argon2.low_level import hash_secret_raw, Type as ArgonType
except ImportError:
    pass

try:
    from reedsolo import RSCodec
except ImportError:
    pass

try:
    from nacl.secret import SecretBox
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
MAGIC_ENCA5 = b"ENCA5"
MAGIC_ENCA6 = b"ENCA6"
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

def get_nonce(base_nonce, idx, length):
    return (int.from_bytes(base_nonce, 'big') + idx).to_bytes(length, 'big')

def encrypt_path(input_path: str, output_path: str, pkcs11_lib: str, pin: str, recovery_password: str = None, wipe_original: bool = False, stealth_mode: bool = False, pim: int = 1):
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

    aes_key = os.urandom(32)
    xsalsa_key = os.urandom(32)
    combined_keys = aes_key + xsalsa_key
    
    encrypted_keys_token = b""
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
                encrypted_keys_token = pub_key.encrypt(combined_keys, mechanism=Mechanism.RSA_PKCS_OAEP)
            except (pkcs11.exceptions.MechanismInvalid, pkcs11.exceptions.DataInvalid):
                encrypted_keys_token = pub_key.encrypt(combined_keys, mechanism=Mechanism.RSA_PKCS)

    has_pwd = 1 if recovery_password else 0
    salt = b""
    encrypted_keys_pwd = b""
    nonce_pwd = b""
    
    if has_pwd:
        recovery_password = unicodedata.normalize('NFC', recovery_password)
        salt = os.urandom(16)
        time_cost = 3 * max(1, pim)
        derived_key = hash_secret_raw(
            secret=recovery_password.encode('utf-8'),
            salt=salt,
            time_cost=time_cost, memory_cost=65536, parallelism=4,
            hash_len=32, type=ArgonType.ID
        )
        aesgcm_pwd = AESGCM(derived_key)
        nonce_pwd = os.urandom(12)
        encrypted_keys_pwd = aesgcm_pwd.encrypt(nonce_pwd, combined_keys, MAGIC_ENCA6)

    aesgcm_file = AESGCM(aes_key)
    box = SecretBox(xsalsa_key)
    
    nonce_aes = os.urandom(12)
    nonce_xsalsa = os.urandom(24)
    
    header_bytes = bytearray()
    
    target_size = os.path.getsize(target_path)
    total_chunks = math.ceil(target_size / CHUNK_SIZE) if target_size > 0 else 0
    
    if stealth_mode:
        header_bytes.extend(os.urandom(5))
    else:
        header_bytes.extend(MAGIC_ENCA6)
        
    header_bytes.extend(struct.pack('>B', 1 if is_dir else 0))
    header_bytes.extend(struct.pack('>B', has_pwd))
    
    if has_pwd:
        header_bytes.extend(salt)
        header_bytes.extend(struct.pack('>H', pim))
        header_bytes.extend(nonce_pwd)
        header_bytes.extend(encrypted_keys_pwd.ljust(80, b'\x00'))
    else:
        header_bytes.extend(os.urandom(16))
        header_bytes.extend(struct.pack('>H', 1))
        header_bytes.extend(os.urandom(12))
        header_bytes.extend(os.urandom(80))
        
    header_bytes.extend(nonce_aes)
    header_bytes.extend(nonce_xsalsa)
    header_bytes.extend(struct.pack('>I', total_chunks))
    header_bytes.extend(encrypted_keys_token.ljust(256, b'\x00'))

    if len(header_bytes) > 512:
        raise Exception("O cabeçalho gerado é grande demais.")
        
    header_bytes = header_bytes.ljust(512, b'\x00')
    rsc = RSCodec(32)
    encoded_header = rsc.encode(header_bytes)
    
    with open(output_path, 'wb') as f_out:
        f_out.write(encoded_header)
        
        chunk_idx = 0
        with open(target_path, 'rb') as f_in:
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                n_aes = get_nonce(nonce_aes, chunk_idx, 12)
                n_xs = get_nonce(nonce_xsalsa, chunk_idx, 24)
                
                c1 = aesgcm_file.encrypt(n_aes, chunk, bytes(header_bytes))
                c2 = box.encrypt(c1, n_xs).ciphertext
                
                f_out.write(struct.pack('>I', len(c2)))
                f_out.write(c2)
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
        magic_check = f.read(5)
        f.seek(0)
        
        is_enca6 = False
        is_enca5 = False
        is_enca4 = False
        is_stealth = False
        
        if magic_check == MAGIC_ENCA6:
            is_enca6 = True
            encoded_header = f.read(608)
        elif magic_check == MAGIC_ENCA5:
            is_enca5 = True
            encoded_header = f.read(608)
        elif magic_check == MAGIC:
            is_enca4 = True
            f.read(5)
        else:
            is_stealth = True
            encoded_header = f.read(608)
            
        if is_enca4:
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
            aad = None
        else:
            if len(encoded_header) < 608:
                raise Exception("Arquivo corrompido ou não é um cofre válido.")
            rsc = RSCodec(32)
            try:
                header_bytes_decoded = rsc.decode(encoded_header)[0]
            except Exception:
                raise Exception("Falha de integridade no cabeçalho (Bit rot irreparável ou não é um cofre Stealth válido).")
            aad = bytes(header_bytes_decoded)
            hb = io.BytesIO(header_bytes_decoded)
            
            actual_magic = hb.read(5)
            if is_stealth:
                if actual_magic == MAGIC_ENCA6:
                    is_enca6 = True
                elif actual_magic == MAGIC_ENCA5:
                    is_enca5 = True
                else:
                    if actual_magic[0] in (0, 1) and actual_magic[1] in (0, 1):
                        is_enca5 = True
                    else:
                        is_enca6 = True 
                        
            if is_enca6:
                is_dir = struct.unpack('>B', hb.read(1))[0] == 1
                has_pwd = struct.unpack('>B', hb.read(1))[0] == 1
                salt = b""
                pim = 1
                nonce_pwd = b""
                encrypted_keys_pwd = b""
                if has_pwd:
                    salt = hb.read(16)
                    pim = struct.unpack('>H', hb.read(2))[0]
                    nonce_pwd = hb.read(12)
                    encrypted_keys_pwd = hb.read(80)
                else:
                    hb.read(16+2+12+80)
                nonce_aes = hb.read(12)
                nonce_xsalsa = hb.read(24)
                total_chunks = struct.unpack('>I', hb.read(4))[0]
                encrypted_keys_token = hb.read(256)
            elif is_enca5:
                hb.seek(0)
                is_dir = struct.unpack('>B', hb.read(1))[0] == 1
                has_pwd = struct.unpack('>B', hb.read(1))[0] == 1
                key_len = struct.unpack('>H', hb.read(2))[0]
                encrypted_aes_key_token = hb.read(key_len) if key_len > 0 else b""
                salt = b""
                nonce_pwd = b""
                encrypted_aes_key_pwd = b""
                if has_pwd:
                    salt = hb.read(16)
                    nonce_pwd = hb.read(12)
                    pwd_key_len = struct.unpack('>H', hb.read(2))[0]
                    encrypted_aes_key_pwd = hb.read(pwd_key_len)
                nonce_file = hb.read(12)
                total_chunks = struct.unpack('>I', hb.read(4))[0]

        aes_key = None
        xsalsa_key = None
        
        if is_enca6:
            combined_keys = b''
            if pin:
                if not pkcs11_lib:
                    pkcs11_lib = auto_discover_pkcs11()
                lib = pkcs11.lib(pkcs11_lib)
                try:
                    token = next(lib.get_tokens())
                except StopIteration:
                    raise Exception("Nenhum Token A3 detectado. Verifique se ele está conectado na porta USB.")
                with token.open(user_pin=pin) as session:
                    _, priv_key = _get_keys(session)
                    try:
                        combined_keys = priv_key.decrypt(encrypted_keys_token, mechanism=Mechanism.RSA_PKCS_OAEP)
                    except:
                        combined_keys = priv_key.decrypt(encrypted_keys_token, mechanism=Mechanism.RSA_PKCS)
            elif recovery_password and has_pwd:
                recovery_password = unicodedata.normalize('NFC', recovery_password)
                time_cost = 3 * max(1, pim)
                derived_key = hash_secret_raw(
                    secret=recovery_password.encode('utf-8'),
                    salt=salt,
                    time_cost=time_cost, memory_cost=65536, parallelism=4,
                    hash_len=32, type=ArgonType.ID
                )
                aesgcm_pwd = AESGCM(derived_key)
                combined_keys = aesgcm_pwd.decrypt(nonce_pwd, encrypted_keys_pwd.rstrip(b'\x00'), MAGIC_ENCA6)
            else:
                raise Exception("Nenhum método de decriptação válido fornecido (PIN do Token ou Senha).")
                
            aes_key = combined_keys[:32]
            xsalsa_key = combined_keys[32:64]
            aesgcm_file = AESGCM(aes_key)
            box = SecretBox(xsalsa_key)
        else:
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
                    try:
                        aes_key = priv_key.decrypt(encrypted_aes_key_token, mechanism=Mechanism.RSA_PKCS_OAEP)
                    except:
                        aes_key = priv_key.decrypt(encrypted_aes_key_token, mechanism=Mechanism.RSA_PKCS)
            elif recovery_password and has_pwd:
                recovery_password = unicodedata.normalize('NFC', recovery_password)
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
        if is_stealth and not input_path.endswith('.ea3'): 
            base_name += "_decrypted"
        
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
                
                if is_enca6:
                    n_aes = get_nonce(nonce_aes, chunk_idx, 12)
                    n_xs = get_nonce(nonce_xsalsa, chunk_idx, 24)
                    c1 = box.decrypt(enc_chunk, n_xs)
                    plaintext_chunk = aesgcm_file.decrypt(n_aes, c1, aad)
                else:
                    current_nonce = nonce_file[:8] + struct.pack('>I', chunk_idx)
                    plaintext_chunk = aesgcm_file.decrypt(current_nonce, enc_chunk, aad if is_enca5 else None)

                f_out.write(plaintext_chunk)
                    
    if is_dir and temp_out:
        out_folder = os.path.join(output_dir, base_name)
        os.makedirs(out_folder, exist_ok=True)
        with zipfile.ZipFile(temp_out, 'r') as zf:
            zf.extractall(out_folder)
        _secure_wipe(temp_out)
        return out_folder
        
    return out_target

def is_vault(filepath: str) -> bool:
    if not os.path.isfile(filepath):
        return False
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(5)
            if magic in (MAGIC, MAGIC_ENCA5, MAGIC_ENCA6):
                return True
            
            f.seek(0)
            encoded_header = f.read(608)
            if len(encoded_header) < 608:
                return False
                
            from reedsolo import RSCodec
            rsc = RSCodec(32)
            try:
                rsc.decode(encoded_header)
                return True
            except Exception:
                return False
    except Exception:
        return False
