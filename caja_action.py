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

def get_text(text):
    try:
        result = subprocess.run(
            ['zenity', '--entry', '--title=Cofre EncryptA3', f'--text={text}'],
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
    is_encrypting = not vault.is_vault(paths[0])

    pkcs11_lib = vault.auto_discover_pkcs11()

    pin = None
    recovery_password = None

    if is_encrypting:
        pin = get_password("Insira o PIN do Token A3 (SafeSign):")
        if not pin:
            return
            
        use_recovery = ask_question("Deseja configurar uma Senha de Emergência para esses arquivos? (Recomendado caso perca o Token A3)")
        pim = 1
        if use_recovery:
            recovery_password = get_password("Digite a Senha de Emergência:")
            if not recovery_password:
                return
                
            pim_str = get_text("Digite o Nível de Paranoia PIM (1 = Padrão, 10 = Demorado):")
            try:
                pim = int(pim_str) if pim_str else 1
            except ValueError:
                pim = 1
                
        stealth_mode = ask_question("Deseja ativar o Modo Furtivo (Sem assinatura ENCA)?")
        stealth_ext = ".ea3"
        if stealth_mode:
            ext = get_text("Qual extensão falsa você deseja usar? (Ex: .mp4, .dat) ou cancele para não usar extensão.")
            if ext is not None:
                stealth_ext = ext
            else:
                stealth_ext = ""
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

        is_cofre = vault.is_vault(target)
        filename = os.path.basename(target)

        try:
            if not is_cofre:
                out_path = target + stealth_ext
                vault.encrypt_path(target, out_path, pkcs11_lib, pin, recovery_password, stealth_mode=stealth_mode, pim=pim)
                success_msgs.append(f"🔒 Trancado: {os.path.basename(out_path)}")
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
