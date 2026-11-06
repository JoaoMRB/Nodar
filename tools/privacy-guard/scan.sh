#!/bin/sh
# Verifica se o que está para ir para o repositório contém valores REAIS da tua rede.
# Lê a lista de %LOCALAPPDATA%\Nodar\private-denylist.txt (ver build-denylist.ps1). Fica fora do repositório.
#
# Uso:  scan.sh staged     o que está preparado para o próximo commit (usado pelo hook pre-commit)
#       scan.sh push       os commits que ainda não estão no remoto (usado pelo hook pre-push)
#       scan.sh all        o repositório inteiro: ficheiros atuais e todo o histórico
#
# Nunca imprime o valor encontrado, só o ficheiro e a linha, para não o repetir em registos.

mode="${1:-staged}"

deny="${NODAR_PRIVATE_DENYLIST:-}"
if [ -z "$deny" ] && [ -n "$LOCALAPPDATA" ]; then
    base=$(cygpath -u "$LOCALAPPDATA" 2>/dev/null || echo "$LOCALAPPDATA")
    deny="$base/Nodar/private-denylist.txt"
fi

if [ ! -s "$deny" ]; then
    echo "AVISO: a proteção de privacidade está INATIVA (falta a lista de valores reais)."
    echo "       Gera-a com: powershell -File tools/privacy-guard/build-denylist.ps1"
    exit 0
fi

hits=$(mktemp 2>/dev/null || echo "/tmp/privacy-hits.$$")
trap 'rm -f "$hits"' EXIT
: > "$hits"

# Ficheiros de uma árvore de commit: "ficheiro:linha"
scan_tree() { # $1 = commit
    git grep -I -n -F -i -f "$deny" "$1" 2>/dev/null | cut -d: -f2,3 | cut -d: -f1,2 >> "$hits"
}

scan_message() { # $1 = commit
    git log -1 --format=%B "$1" | grep -q -F -i -f "$deny" && echo "(mensagem de commit)" >> "$hits"
}

case "$mode" in
staged)
    for file in $(git diff --cached --name-only --diff-filter=ACMR); do
        git show ":$file" 2>/dev/null | grep -I -n -F -i -f "$deny" 2>/dev/null | cut -d: -f1 | while read -r line; do
            echo "$file:$line" >> "$hits"
        done
    done
    ;;
push)
    for commit in $(git rev-list HEAD --not --remotes 2>/dev/null); do
        scan_tree "$commit"
        scan_message "$commit"
    done
    ;;
all)
    for commit in $(git rev-list HEAD); do
        scan_tree "$commit"
        scan_message "$commit"
    done
    ;;
*)
    echo "uso: scan.sh staged|push|all"
    exit 2
    ;;
esac

if [ -s "$hits" ]; then
    echo "BLOQUEADO: foram encontrados valores reais da tua rede (o valor não é mostrado):"
    sort "$hits" | uniq -c | sort -rn | awk '{ n=$1; $1=""; sub(/^ /,""); if (n>1) printf "  - %s  (em %d versões)\n", $0, n; else printf "  - %s\n", $0 }'
    echo ""
    echo "Troca esses valores por exemplos inventados (ex.: AA:BB:CC:00:00:01) antes de continuar."
    echo "Se já os reviste e os aceitas, acrescenta-os a private-allow.txt (ver tools/privacy-guard/README.md)."
    exit 1
fi
echo "Privacidade: nenhum valor real encontrado ($mode)."
exit 0
