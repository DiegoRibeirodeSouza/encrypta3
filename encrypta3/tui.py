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
            
        is_cofre = target.endswith('.cofre')
        
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
            
        pkcs11_lib = '/usr/lib/safesign-private/libaetpkss.so.3'
        if not os.path.exists(pkcs11_lib):
            console.print(f"[red]Módulo PKCS#11 não encontrado em {pkcs11_lib}[/red]\n")
            continue
            
        pin = questionary.password("Digite o PIN (senha) do seu Token A3:").ask()
        if not pin:
            console.print("")
            continue
            
        console.print(f"\n[yellow]Acessando Token A3 e processando criptografia (Ação: {action})...[/yellow]")
        start_time = time.time()
        
        try:
            if action == "Trancar (Criptografar)":
                out_path = target + '.cofre'
                vault.encrypt_path(target, out_path, pkcs11_lib, pin)
                console.print(f"\n[bold green]Sucesso![/bold green] Arquivo trancado gerado: [bold]{out_path}[/bold]")
            else:
                out_dir = os.path.dirname(target)
                res_path = vault.decrypt_path(target, out_dir, pkcs11_lib, pin)
                console.print(f"\n[bold green]Sucesso![/bold green] Arquivo/Pasta destrancado em: [bold]{res_path}[/bold]")
                
            console.print(f"Tempo de execução: {time.time() - start_time:.2f}s")
        except pkcs11.exceptions.PinIncorrect:
            console.print("\n[bold red]Erro:[/bold red] PIN Incorreto! Cuidado com o limite de tentativas.")
        except Exception as e:
            console.print(f"\n[bold red]Falha na operação:[/bold red] {e}")
            
        console.print("")
        
        continuar = questionary.confirm("Deseja realizar mais alguma operação em outro arquivo?").ask()
        if not continuar:
            break
        console.print("\n" + "-"*50 + "\n")

if __name__ == '__main__':
    run()
