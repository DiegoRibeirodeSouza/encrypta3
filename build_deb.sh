#!/bin/bash

# Script de Construção do Pacote Debian para o EncryptA3
set -e

echo "=> Iniciando empacotamento Debian para o EncryptA3..."

PKG_NAME="encrypta3"
PKG_VERSION="1.0"
PKG_ARCH="all"
PKG_DIR="${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}"

echo "=> Limpando builds anteriores..."
rm -rf "$PKG_DIR"
rm -f "${PKG_DIR}.deb"

echo "=> Criando estrutura de pastas..."
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/opt/encrypta3"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/caja-python/extensions"
mkdir -p "$PKG_DIR/usr/share/applications"
mkdir -p "$PKG_DIR/usr/share/pixmaps"

echo "=> Copiando arquivos do aplicativo..."
# O código fonte vai para /opt/encrypta3
cp -r encrypta3 "$PKG_DIR/opt/encrypta3/"
cp pyproject.toml "$PKG_DIR/opt/encrypta3/"
cp caja_action.py "$PKG_DIR/opt/encrypta3/"
cp icon.png "$PKG_DIR/opt/encrypta3/" || echo "Aviso: icon.png não encontrado localmente."

# Instalando extensão do Caja
cp caja_action.py "$PKG_DIR/usr/share/caja-python/extensions/encrypta3_caja.py"

# Ícone global
cp icon.png "$PKG_DIR/usr/share/pixmaps/encrypta3.png" || echo "Aviso: icon.png não será empacotado nos pixmaps."

echo "=> Criando os arquivos de controle Debian..."

cat <<EOF > "$PKG_DIR/DEBIAN/control"
Package: $PKG_NAME
Version: $PKG_VERSION
Architecture: $PKG_ARCH
Maintainer: EncryptA3 Team <diego@example.com>
Depends: python3, python3-venv, python3-pip, python-caja | python3-caja
Description: EncryptA3 - Cofre ICP-Brasil
 Um cofre criptográfico com suporte a Token A3 e cifras em cascata.
EOF

# Script Pós-instalação (roda no computador do usuário como root durante a instalação)
cat <<'EOF' > "$PKG_DIR/DEBIAN/postinst"
#!/bin/bash
set -e

echo "=> Configurando o ambiente do EncryptA3..."

# Cria ambiente virtual em /opt/encrypta3/venv
python3 -m venv /opt/encrypta3/venv

# Atualiza o PIP e instala as dependências
/opt/encrypta3/venv/bin/pip install --upgrade pip
/opt/encrypta3/venv/bin/pip install /opt/encrypta3/

# Tenta reiniciar o gerenciador de arquivos Caja
pkill -f caja || true

echo "=> Instalação do EncryptA3 concluída com sucesso!"
exit 0
EOF

# Script Pré-remoção (roda ao desinstalar)
cat <<'EOF' > "$PKG_DIR/DEBIAN/prerm"
#!/bin/bash
set -e

echo "=> Removendo o ambiente do EncryptA3..."
rm -rf /opt/encrypta3/venv
exit 0
EOF

echo "=> Criando o atalho executável global..."
cat <<'EOF' > "$PKG_DIR/usr/bin/encrypta3"
#!/bin/bash
# Invoca o ambiente virtual isolado da aplicação
exec /opt/encrypta3/venv/bin/python3 -m encrypta3 "$@"
EOF

echo "=> Criando atalho no Menu Iniciar (.desktop)..."
cat <<'EOF' > "$PKG_DIR/usr/share/applications/encrypta3.desktop"
[Desktop Entry]
Name=EncryptA3 (Cofre A3)
Comment=Tranque e destranque arquivos com seu Token A3 ou Senha
Exec=encrypta3
Icon=encrypta3
Terminal=true
Type=Application
Categories=Utility;Security;
EOF

echo "=> Ajustando permissões padrão do pacote Linux..."
chmod 755 "$PKG_DIR/DEBIAN/postinst"
chmod 755 "$PKG_DIR/DEBIAN/prerm"
chmod 755 "$PKG_DIR/usr/bin/encrypta3"
# O script caja_action.py precisa ter permissão de leitura
chmod 644 "$PKG_DIR/usr/share/caja-python/extensions/encrypta3_caja.py"
chmod 644 "$PKG_DIR/usr/share/applications/encrypta3.desktop"
chmod 644 "$PKG_DIR/usr/share/pixmaps/encrypta3.png" || true

echo "=> Construindo o pacote .deb (dpkg-deb)..."
dpkg-deb --build "$PKG_DIR"

echo "=> Limpando a estrutura temporária..."
rm -rf "$PKG_DIR"

echo "=========================================================================="
echo "SUCESSO! O pacote Debian '${PKG_DIR}.deb' foi gerado!"
echo "Para instalar no sistema, rode:"
echo "sudo apt install ./${PKG_DIR}.deb"
echo "=========================================================================="
