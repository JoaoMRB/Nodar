#!/bin/sh
# Instala os hooks locais que bloqueiam commits e pushes com valores reais da rede.
# Os hooks ficam em .git/hooks (locais, nunca fazem parte do repositório).
#
# Uso:  sh tools/privacy-guard/install.sh
#
# Nota de robustez: o hook captura a saída do verificador e só depois a imprime, ignorando erros de escrita. Se a
# saída do git for fechada a meio (uma ferramenta que lê só parte dela), o commit continua bloqueado: um hook que
# morre ao escrever deixaria passar o commit em silêncio.

root=$(git rev-parse --show-toplevel) || exit 1
hooks="$root/.git/hooks"

write_hook() { # $1 = nome do hook, $2 = modo do verificador
    cat > "$hooks/$1" <<EOF
#!/bin/sh
trap '' PIPE
out=\$(sh "\$(git rev-parse --show-toplevel)/tools/privacy-guard/scan.sh" $2 2>&1)
code=\$?
printf '%s\n' "\$out" >&2 2>/dev/null || true
exit \$code
EOF
    chmod +x "$hooks/$1"
}

write_hook pre-commit staged
write_hook pre-push push
chmod +x "$root/tools/privacy-guard/scan.sh"
echo "Hooks instalados: pre-commit e pre-push."
