#!/usr/bin/env python3
import sys
import os
import subprocess
from encrypta3.backends import vault
import pkcs11

def ask_question(text):
    try:
        subprocess.run(
            ['zenity', '--question', '--title=Cofre EncryptA3', f'--text={text}'],
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False

def get_password(text):
    try:
        result = subprocess.run(
            ['zenity', '--password', '--title=Cofre EncryptA3', f'--text={text}'],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None

def show_message(text, is_error=False):
    msg_type = '--error' if is_error else '--info'
    subprocess.run(['zenity', msg_type, '--title=EncryptA3', f'--text={text}'])

def main():
    if len(sys.argv) < 2:
        return
        
    paths = sys.argv[1:]
    if not paths:
        return

    # Check if we are encrypting or decrypting based on the first file
    # We assume batch operations share the same action type
    is_encrypting = not paths[0].endswith('.ea3')

    pkcs11_lib = vault.auto_discover_pkcs11()

    pin = None
    recovery_password = None

    if is_encrypting:
        pin = get_password("Insira o PIN do Token A3 (SafeSign):")
        if not pin:
            return
            
        use_recovery = ask_question("Deseja configurar uma Senha de Emergência para esses arquivos? (Recomendado caso perca o Token A3)")
        if use_recovery:
            recovery_password = get_password("Digite a Senha de Emergência:")
            if not recovery_password:
                return
    else:
        # Decrypting
        use_token = ask_question("Deseja usar o Token A3 para destrancar?\n(Clique em 'Não' para usar a Senha de Emergência)")
        if use_token:
            if not pkcs11_lib:
                show_message("Driver PKCS#11 não encontrado no sistema.", True)
                return
            pin = get_password("Insira o PIN do Token A3:")
            if not pin:
                return
        else:
            recovery_password = get_password("Digite a Senha de Emergência usada neste cofre:")
            if not recovery_password:
                return

    success_msgs = []
    error_msgs = []

    for target in paths:
        if not os.path.exists(target):
            continue

        is_cofre = target.endswith('.ea3')
        filename = os.path.basename(target)

        try:
            if not is_cofre:
                out_path = target + '.ea3'
                vault.encrypt_path(target, out_path, pkcs11_lib, pin, recovery_password)
                success_msgs.append(f"🔒 Trancado: {filename}.ea3")
            else:
                out_dir = os.path.dirname(target)
                res_path = vault.decrypt_path(target, out_dir, pkcs11_lib, pin, recovery_password)
                success_msgs.append(f"🔓 Destrancado: {os.path.basename(res_path)}")
        except pkcs11.exceptions.PinIncorrect:
            show_message("PIN Incorreto! Cuidado com o limite de tentativas do Token.", True)
            return
        except Exception as e:
            error_msgs.append(f"Erro em {filename}: {str(e)}")

    final_msg = ""
    if success_msgs:
        final_msg += "Operações concluídas:\n" + "\n".join(success_msgs)
    if error_msgs:
        final_msg += "\n\nFalhas:\n" + "\n".join(error_msgs)

    if success_msgs or error_msgs:
        show_message(final_msg, is_error=bool(error_msgs and not success_msgs))

if __name__ == '__main__':
    main()
