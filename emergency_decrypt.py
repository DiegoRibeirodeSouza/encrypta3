#!/usr/bin/env python3
"""
---------------------------------------------------------
EncryptA3 - Emergency Decrypt Script (Disaster Recovery)
---------------------------------------------------------
Este script é uma ferramenta minimalista e independente de sobrevivência.
Ele não depende da interface gráfica ou do resto do código do aplicativo.
Guarde-o em um local seguro (ou impresso em papel).

Dependências necessárias para rodar no futuro:
pip install cryptography pynacl argon2-cffi reedsolo python-pkcs11

Uso:
python3 emergency_decrypt.py /caminho/para/arquivo.ea3 /caminho/destino
---------------------------------------------------------
"""

import sys
import os
import io
import struct
import tempfile
import zipfile
import math
import getpass
import unicodedata

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from nacl.secret import SecretBox
    from argon2.low_level import hash_secret_raw, Type as ArgonType
    from reedsolo import RSCodec
    import pkcs11
    from pkcs11 import KeyType, ObjectClass, Mechanism
except ImportError as e:
    print(f"Erro: Dependência ausente. Por favor, instale: {e.name}")
    print("Execute: pip install cryptography pynacl argon2-cffi reedsolo python-pkcs11")
    sys.exit(1)

MAGIC = b"ENCA4"
MAGIC_ENCA5 = b"ENCA5"
MAGIC_ENCA6 = b"ENCA6"

def get_nonce(base_nonce, idx, length):
    return (int.from_bytes(base_nonce, 'big') + idx).to_bytes(length, 'big')

def auto_discover_pkcs11() -> str:
    paths = [
        "/usr/lib/safesign-private/libaetpkss.so.3",
        "/usr/lib/libaetpkss.so.3",
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib/libeTPkcs11.so",
        "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
    ]
    for p in paths:
        if os.path.exists(p): return p
    return None

def emergency_decrypt(input_path: str, output_dir: str):
    if not os.path.exists(input_path):
        print("Arquivo de entrada não encontrado.")
        return

    print("--- EncryptA3 Disaster Recovery ---")
    print("1. Usar Token A3 (Hardware)")
    print("2. Usar Senha de Recuperação (Software)")
    escolha = input("Digite 1 ou 2: ").strip()

    pin = None
    pwd = None
    if escolha == '1':
        pin = getpass.getpass("Digite o PIN do Token: ")
    elif escolha == '2':
        pwd = getpass.getpass("Digite a Senha de Recuperação: ")
    else:
        print("Opção inválida.")
        return

    with open(input_path, 'rb') as f:
        magic_check = f.read(5)
        f.seek(0)
        
        is_stealth = False
        if magic_check == MAGIC_ENCA6:
            encoded_header = f.read(608)
        elif magic_check in (MAGIC, MAGIC_ENCA5):
            print("Erro: Formatos antigos não suportados neste script.")
            return
        else:
            is_stealth = True
            encoded_header = f.read(608)
            
        rsc = RSCodec(32)
        try:
            header_bytes_decoded = rsc.decode(encoded_header)[0]
        except Exception:
            print("Erro: Falha de integridade no cabeçalho. Arquivo corrompido.")
            return
            
        aad = bytes(header_bytes_decoded)
        hb = io.BytesIO(header_bytes_decoded)
        
        hb.read(5) # Magic
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

        combined_keys = b''
        
        if pin:
            lib_path = auto_discover_pkcs11()
            if not lib_path:
                lib_path = input("Driver PKCS11 não encontrado. Digite o caminho (/usr/lib/...): ")
            lib = pkcs11.lib(lib_path)
            token = next(lib.get_tokens())
            with token.open(user_pin=pin) as session:
                priv_keys = list(session.get_objects({
                    pkcs11.Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                    pkcs11.Attribute.KEY_TYPE: KeyType.RSA
                }))
                if not priv_keys:
                    print("Erro: Chave privada não encontrada no token.")
                    return
                try:
                    combined_keys = priv_keys[0].decrypt(encrypted_keys_token, mechanism=Mechanism.RSA_PKCS_OAEP)
                except Exception:
                    combined_keys = priv_keys[0].decrypt(encrypted_keys_token, mechanism=Mechanism.RSA_PKCS)
                    
        elif pwd and has_pwd:
            pwd = unicodedata.normalize('NFC', pwd)
            derived_key = hash_secret_raw(
                secret=pwd.encode('utf-8'), salt=salt,
                time_cost=3 * max(1, pim), memory_cost=65536, parallelism=4,
                hash_len=32, type=ArgonType.ID
            )
            aesgcm_pwd = AESGCM(derived_key)
            combined_keys = aesgcm_pwd.decrypt(nonce_pwd, encrypted_keys_pwd, MAGIC_ENCA6)
        else:
            print("Erro: Arquivo não possui senha de recuperação configurada, ou dados inválidos.")
            return
            
        aes_key = combined_keys[:32]
        xsalsa_key = combined_keys[32:64]
        aesgcm_file = AESGCM(aes_key)
        box = SecretBox(xsalsa_key)
        
        base_name = os.path.basename(input_path).replace('.ea3', '')
        if is_stealth and not input_path.endswith('.ea3'): 
            base_name += "_decrypted"
            
        temp_out = None
        if is_dir:
            temp_out = tempfile.NamedTemporaryFile(delete=False, suffix=".zip").name
            out_target = temp_out
        else:
            out_target = os.path.join(output_dir, base_name)
            
        print(f"Decifrando {total_chunks} blocos...")
        with open(out_target, 'wb') as f_out:
            for chunk_idx in range(total_chunks):
                len_bytes = f.read(4)
                if not len_bytes: break
                chunk_len = struct.unpack('>I', len_bytes)[0]
                enc_chunk = f.read(chunk_len)
                
                c1 = box.decrypt(enc_chunk, get_nonce(nonce_xsalsa, chunk_idx, 24))
                plaintext = aesgcm_file.decrypt(get_nonce(nonce_aes, chunk_idx, 12), c1, aad)
                f_out.write(plaintext)
                
    if is_dir and temp_out:
        out_folder = os.path.join(output_dir, base_name)
        os.makedirs(out_folder, exist_ok=True)
        with zipfile.ZipFile(temp_out, 'r') as zf:
            zf.extractall(out_folder)
        os.remove(temp_out)
        print(f"Sucesso! Pasta extraída em: {out_folder}")
    else:
        print(f"Sucesso! Arquivo extraído em: {out_target}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Uso: python3 {sys.argv[0]} <arquivo.ea3> <pasta_destino>")
        sys.exit(1)
    emergency_decrypt(sys.argv[1], sys.argv[2])
