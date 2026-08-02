import sys
import struct

if len(sys.argv) < 2:
    print("Uso: python inspect_vault.py <arquivo.ea3>")
    sys.exit(1)

file_path = sys.argv[1]

with open(file_path, 'rb') as f:
    header = f.read(5)
    print(f"=== Inspeção de Segurança ===")
    print(f"Cabeçalho Mágico: {header}")
    if header != b'ENCA4':
        print("Não é um cofre válido da versão 2.")
        sys.exit(1)
        
    is_dir = struct.unpack('>B', f.read(1))[0]
    print(f"Tipo: {'Pasta ZIP' if is_dir else 'Arquivo Simples'}")
    
    has_pwd = struct.unpack('>B', f.read(1))[0]
    print(f"Possui Senha de Emergência (Argon2)? {'SIM' if has_pwd else 'NÃO'}")
    
    token_len = struct.unpack('>H', f.read(2))[0]
    print(f"Tamanho do Bloco Criptografado pelo Token A3 (RSA-2048): {token_len} bytes")
    token_enc_key = f.read(token_len)
    
    if has_pwd:
        salt = f.read(16)
        print(f"Salt da Senha de Emergência (16 bytes): {salt.hex()}")
        nonce_pwd = f.read(12)
        print(f"Nonce da Senha de Emergência (12 bytes): {nonce_pwd.hex()}")
        pwd_len = struct.unpack('>H', f.read(2))[0]
        print(f"Tamanho do Bloco Criptografado pela Senha: {pwd_len} bytes")
        pwd_enc_key = f.read(pwd_len)
        
    nonce_file = f.read(12)
    print(f"Nonce Principal do Arquivo (AES-GCM): {nonce_file.hex()}")
    
    print("\n[!] A partir daqui, 100% dos dados são a carga útil encriptada por AES-256-GCM (Nível Militar).")
    print("[!] Os dados estão divididos em blocos de 64KB, cada um com sua própria assinatura criptográfica inviolável.")
    print("[!] Qualquer modificação de 1 único byte no arquivo acusará falha na checagem de integridade (MAC) e abortará a leitura.")
    
    chunk_len_bytes = f.read(4)
    if chunk_len_bytes:
        chunk_len = struct.unpack('>I', chunk_len_bytes)[0]
        print(f"\nTamanho do Primeiro Bloco Encriptado (dados + MAC): {chunk_len} bytes")
        print(f"Amostra dos primeiros 50 bytes desse bloco (totalmente ininteligíveis):\n{f.read(50)}")
