# EncryptA3 (Cofre ICP-Brasil) 🔒

O **EncryptA3** é uma ferramenta de terminal (TUI) de altíssima segurança projetada para garantir o sigilo absoluto de documentos e pastas sensíveis utilizando **Criptografia Híbrida**.

Ao invés de depender de senhas fracas que podem ser vazadas, o EncryptA3 utiliza o hardware criptográfico do seu **Token A3 (Padrão ICP-Brasil OAB/e-CPF)** para trancar e destrancar uma chave de grau militar (AES-GCM).

## 🚀 Como Funciona a Criptografia Híbrida?
1. **Trancar (Criptografar):** O sistema gera uma chave simétrica descartável super-rápida (AES-256) e criptografa seu documento ou pasta em milissegundos. Em seguida, a **Chave Pública** (RSA) do seu Token A3 é usada para "trancar" essa chave AES. O resultado é um arquivo selado com a extensão `.cofre`.
2. **Destrancar (Decifrar):** Para abrir o cofre, você insere seu Token A3 na porta USB e digita seu PIN. A sua **Chave Privada** (que nunca sai do chip físico) destranca a chave AES interna, recuperando instantaneamente seus documentos originais.

Mesmo se o seu computador for roubado, invadido ou hackeado, os arquivos estarão matematicamente inacessíveis sem a presença física do seu Token A3 e da sua senha.

## ✨ Funcionalidades
- **Criptografia de Pastas e Arquivos:** Se você arrastar uma pasta inteira, o sistema compacta, cifra e gera um arquivo `.cofre` único, não deixando rastros no disco de arquivos temporários descriptografados.
- **Interface TUI Elegante:** Interface interativa baseada em terminal (com bibliotecas `rich` e `questionary`), suporte a arrastar-e-soltar e fluxos contínuos de operação.
- **Validação Automática:** Diferencia inteligentemente o que precisa ser cifrado ou decifrado com base na extensão `.cofre`.

## 🛠️ Requisitos
- Linux (testado em Ubuntu/GNOME)
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

## ▶️ Como Usar
Se você criou um atalho na Área de Trabalho, basta dar um **duplo clique** no ícone de Cofre.

Pelo terminal, com o ambiente virtual ativado, basta rodar:
```bash
encrypta3
```
Ou:
```bash
python3 -m encrypta3
```

A interface interativa solicitará o caminho do arquivo (você pode apenas arrastar o arquivo do seu gerenciador e soltar na tela preta) e guiará você pelo resto do processo.

---
*Desenvolvido por Diego Ribeiro de Souza.*
