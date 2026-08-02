<p align="center">
  <img src="icon.png" alt="EncryptA3 Icon" width="128"/>
</p>

# EncryptA3 (Cofre ICP-Brasil) 🔒

O **EncryptA3** é uma ferramenta de altíssima segurança projetada para garantir o sigilo absoluto de documentos e pastas sensíveis utilizando **Criptografia Híbrida**. Ele atua tanto como um utilitário de terminal (TUI) quanto como uma **Extensão Nativa do Gerenciador de Arquivos (Caja)**.

Ao invés de depender de senhas fracas que podem ser vazadas, o EncryptA3 utiliza o hardware criptográfico do seu **Token A3 (Padrão ICP-Brasil OAB/e-CPF)** para trancar e destrancar uma chave de grau militar (AES-GCM).

## 🚀 Como Funciona a Criptografia Híbrida?
1. **Trancar (Criptografar):** O sistema gera uma chave simétrica descartável super-rápida (AES-256) e criptografa seu documento ou pasta em milissegundos. Em seguida, a **Chave Pública** (RSA) do seu Token A3 é usada para "trancar" essa chave AES. O resultado é um arquivo selado com a extensão `.ea3`.
2. **Destrancar (Decifrar):** Para abrir o cofre, você insere seu Token A3 na porta USB e digita seu PIN. A sua **Chave Privada** (que nunca sai do chip físico) destranca a chave AES interna, recuperando instantaneamente seus documentos originais.

Mesmo se o seu computador for roubado, invadido ou hackeado, os arquivos estarão matematicamente inacessíveis sem a presença física do seu Token A3 e da sua senha.

## ✨ Funcionalidades
- **Criptografia de Pastas e Arquivos:** Se você arrastar uma pasta inteira, o sistema compacta, cifra e gera um arquivo `.ea3` único.
- **Prevenção contra Truncamento (AAD):** O sistema bloqueia corrupções parciais no pacote final através do algoritmo AES-GCM.
- **Wipe Opcional:** Você pode escolher destruir o arquivo original (*secure wipe*) após trancá-lo com sucesso, mitigando recuperações do documento desprotegido. 
  > ⚠️ **Aviso de Segurança:** Em SSDs modernos com *wear-leveling*, a técnica de sobrescrever o arquivo (wipe) não garante 100% de exclusão física dos dados originais.
- **Streaming Criptográfico de Alta Performance:** Suporte para arquivos gigantes (Gigabytes ou Terabytes) com baixíssimo consumo de memória RAM, processando dados em blocos.
- **Senha Mestra de Emergência (Cold Storage):** Possibilidade de cadastrar uma senha ultra-segura (protegida pelo algoritmo Argon2) como plano de contingência caso o Token A3 seja fisicamente perdido ou danificado.
- **Auto-Detecção de Drivers PKCS#11:** Não é mais necessário configurar o caminho do driver do Smartcard manualmente no Linux (detecção automática para SafeSign, OpenSC, eTPkcs11, etc).
- **Integração Nativa com o Desktop (Caja):** Tranque e destranque arquivos diretamente pelo menu principal de clique-direito do seu gerenciador de arquivos (Caja/MATE), sem precisar abrir o terminal.
- **Interface TUI Elegante:** Interface interativa baseada em terminal (com bibliotecas `rich` e `questionary`), suporte a arrastar-e-soltar e fluxos contínuos de operação.

## 🛠️ Requisitos
- Linux (testado em Ubuntu/GNOME/MATE)
- Python 3.10+
- Driver PKCS#11 Instalado (Ex: SafeSign `libaetpkss.so.3`)
- Token A3 (OAB, e-CPF, e-CNPJ) conectado.

## 💻 Instalação

```bash
# Clone o diretório e entre na pasta
cd ~/Documentos/encrypta3

# Crie e ative o ambiente virtual
python3 -m venv venv
source venv/bin/activate

# Instale as dependências
pip install .
```

### Habilitando a Extensão no Gerenciador de Arquivos (Caja)
Para que a opção de trancar/destrancar apareça no botão direito do mouse, copie a extensão para a pasta do Caja:
```bash
mkdir -p ~/.local/share/caja-python/extensions/
cp caja_action.py ~/.local/share/caja-python/extensions/
caja -q  # Reinicia o Caja para aplicar as mudanças
```

## ▶️ Como Usar

### Via Interface Gráfica (Caja)
A forma mais prática de utilizar o EncryptA3 no dia a dia é direto pelo seu gerenciador de arquivos:
1. Navegue até o arquivo ou pasta que deseja proteger.
2. Clique com o **botão direito** do mouse sobre o arquivo.
3. No menu principal, clique na opção relacionada ao Cofre A3.
4. Uma caixa segura nativa do Debian aparecerá. Digite o seu PIN e pronto! 

*Nota: Ao criptografar um documento pela interface gráfica, o sistema também perguntará se você quer configurar a Senha de Emergência para formar uma co-assinatura (Token + Argon2).*

### Via Terminal (TUI)
Pelo terminal, com o ambiente virtual ativado, basta rodar:
```bash
encrypta3
```
A interface interativa solicitará o caminho do arquivo (você pode apenas arrastar o arquivo do seu gerenciador e soltar na tela preta) e guiará você pelo resto do processo.

## 🔍 Inspeção e Auditoria
Caso precise validar os metadados de um arquivo criptografado (como descobrir se o arquivo exige senha de emergência ou é diretório) sem precisar inserir a senha ou o token, você pode auditar o cabeçalho usando o inspetor de cofres:
```bash
python3 inspect_vault.py arquivo.ea3
```

---
*Desenvolvido por Diego Ribeiro de Souza.*
