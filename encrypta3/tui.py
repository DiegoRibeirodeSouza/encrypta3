import os
import time
from rich.console import Console
import questionary
from encrypta3.backends import vault
import pkcs11

console = Console()

def run():
    console.print("\n[bold blue]=== Bem-vindo ao EncryptA3 (Cofre ICP-Brasil) ===[/bold blue]\n")
    
    while True:
        target = questionary.path("Cole ou digite o caminho do arquivo ou pasta:").ask()
        if not target:
            break
            
        target = target.strip().strip("'").strip('"')
        
        if not os.path.exists(target):
            console.print("[red]Caminho inválido.[/red]\n")
            continue
            
        is_cofre = vault.is_vault(target)
        
        if is_cofre:
            action = "Destrancar (Descriptografar)"
        else:
            action = "Trancar (Criptografar)"
            
        action_choice = questionary.select(
            f"O que deseja fazer com '{os.path.basename(target)}'?",
            choices=[action, "Cancelar"]
        ).ask()
        
        if action_choice == "Cancelar":
            console.print("")
            continue
            
        pkcs11_lib = vault.auto_discover_pkcs11()
        
        pin = None
        recovery_password = None
        
        if action == "Trancar (Criptografar)":
            if not pkcs11_lib:
                console.print("[yellow]Aviso: Nenhum driver PKCS#11 (Smartcard) foi detectado automaticamente no sistema.[/yellow]")
                pkcs11_lib = questionary.text("Por favor, informe o caminho do driver (ex: /usr/lib/libaetpkss.so.3):").ask()
                
            pin = questionary.password("Digite o PIN (senha) do seu Token A3:").ask()
            if not pin:
                console.print("")
                continue
                
            usar_senha = questionary.confirm("Deseja configurar uma Senha de Emergência (Recomendado caso perca o Token)?").ask()
            pim = 1
            if usar_senha:
                recovery_password = questionary.password("Digite a Senha de Emergência:").ask()
                pim_str = questionary.text("Digite o Nível de Paranoia PIM (1 = Padrão, 10 = Demorado):", default="1").ask()
                try:
                    pim = int(pim_str)
                except ValueError:
                    pim = 1
                
            wipe_original_choice = questionary.confirm("Deseja destruir o arquivo/pasta original de forma segura (Wipe) após trancar?").ask()
            
            stealth_mode_choice = questionary.confirm("Deseja ativar o Modo Furtivo (Negabilidade Plausível - sem assinatura ENCA)?").ask()
            stealth_ext = ".ea3"
            if stealth_mode_choice:
                stealth_ext = questionary.text("Qual extensão disfarçada deseja usar? (Ex: .mp4, .dat) ou deixe em branco para nenhuma:").ask()
                
            console.print(f"\n[yellow]Acessando Token A3 e processando criptografia...[/yellow]")
        else:
            wipe_original_choice = False
            # Decryption
            metodo = questionary.select(
                "Como deseja abrir este cofre?",
                choices=["Usar Token A3", "Usar Senha de Emergência"]
            ).ask()
            
            if metodo == "Usar Token A3":
                if not pkcs11_lib:
                    console.print("[yellow]Aviso: Nenhum driver PKCS#11 foi detectado automaticamente.[/yellow]")
                    pkcs11_lib = questionary.text("Informe o caminho do driver:").ask()
                pin = questionary.password("Digite o PIN do Token A3:").ask()
                if not pin:
                    continue
            else:
                recovery_password = questionary.password("Digite a Senha de Emergência:").ask()
                if not recovery_password:
                    continue
            
            console.print(f"\n[yellow]Processando decriptação...[/yellow]")
            
        start_time = time.time()
        
        try:
            if action == "Trancar (Criptografar)":
                out_path = target + stealth_ext
                vault.encrypt_path(target, out_path, pkcs11_lib, pin, recovery_password, wipe_original=wipe_original_choice, stealth_mode=stealth_mode_choice, pim=pim)
                console.print(f"\n[bold green]Sucesso![/bold green] Arquivo trancado gerado: [bold]{out_path}[/bold]")
            else:
                out_dir = os.path.dirname(target)
                res_path = vault.decrypt_path(target, out_dir, pkcs11_lib, pin, recovery_password)
                console.print(f"\n[bold green]Sucesso![/bold green] Arquivo/Pasta destrancado em: [bold]{res_path}[/bold]")
                
            console.print(f"Tempo de execução: {time.time() - start_time:.2f}s")
        except pkcs11.exceptions.PinIncorrect:
            console.print("\n[bold red]Erro:[/bold red] PIN Incorreto! Cuidado com o limite de tentativas.")
        except Exception as e:
            import traceback
            console.print("\n[bold red]Traceback completo do erro:[/bold red]")
            traceback.print_exc()
            console.print(f"\n[bold red]Falha na operação:[/bold red] {e}")
            
        console.print("")
        
        continuar = questionary.confirm("Deseja realizar mais alguma operação em outro arquivo?").ask()
        if not continuar:
            break
        console.print("\n" + "-"*50 + "\n")

if __name__ == '__main__':
    run()
