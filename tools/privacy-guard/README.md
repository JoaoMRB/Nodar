# Proteção de privacidade

O Nodar vê a tua rede (MACs, nomes de dispositivos, o que escreves nas notas). Nada disto pode acabar no
repositório, nem por acidente num teste ou num exemplo copiado de uma rede real.

Esta pasta tem uma proteção **local**:

1. `build-denylist.ps1` lê os teus ficheiros de dados (`%LOCALAPPDATA%\Nodar\*.json`) e cria
   `%LOCALAPPDATA%\Nodar\private-denylist.txt`, **fora do repositório**, com os valores reais.
2. `scan.sh` procura esses valores no que vai ser commitado (`staged`), no que vai ser enviado (`push`) ou em tudo
   (`all`). Nunca imprime o valor encontrado, só o ficheiro e a linha.
3. `install.sh` instala os hooks `pre-commit` e `pre-push` em `.git/hooks` (locais, não fazem parte do repositório).

```sh
powershell -File tools/privacy-guard/build-denylist.ps1   # gera a lista (repete depois de scans novos)
sh tools/privacy-guard/install.sh                          # instala os hooks
sh tools/privacy-guard/scan.sh all                         # verifica o repositório inteiro e o histórico
```

Nenhum ficheiro desta pasta contém valores reais: a lista fica só no teu PC.

Nos testes e no modo demonstração usa sempre valores inventados (por exemplo `AA:BB:CC:00:00:01`).
