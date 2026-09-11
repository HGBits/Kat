# KAT

Gerenciador de arquivos criptografados com GPG e nomes ofuscados.

O KAT armazena os arquivos em `.sweet/` usando nomes aleatórios (`Talko.kat`, `Nirev.kat`, etc.). O nome original fica apenas no índice criptografado `.kat-index.gpg`.

## Requisitos

* Bash
* GPG
* Git
* `tar`, `gzip`, `sha256sum`

## Instalação

```bash
chmod +x kat.sh
sudo cp kat.sh /usr/local/bin/kat
```

## Uso

Inicializar com uma chave GPG:

```bash
kat init seu@email.com
```

Criptografar:

```bash
kat enc arquivo.txt
kat enc pasta/
```

Criptografar e remover o original:

```bash
kat enc --rm arquivo.txt
```

Listar:

```bash
kat list
kat find documento
```

Descriptografar:

```bash
kat dec documento.txt
kat dec Talko
```

Editar:

```bash
kat edit documento.txt
```

Renomear:

```bash
kat mv documento.txt novo-nome.txt
```

Copiar:

```bash
kat cp documento.txt backup.txt
```

Remover:

```bash
kat rm documento.txt
```

Verificar integridade:

```bash
kat verify documento.txt
kat check
```

Buscar dentro dos arquivos:

```bash
kat grep "termo"
```

Ver a árvore do cofre:

```bash
kat tree
```

Trocar as chaves:

```bash
kat rekey nova-chave@email.com
```

Migrar para criptografia simétrica:

```bash
kat rekey --symmetric
```

Git:

```bash
kat git status
kat git log
```

Ajuda:

```bash
kat help
```

## Segurança

* Conteúdo armazenado em `.sweet/*.kat` é criptografado com GPG/AES256.
* Nomes reais não aparecem no sistema de arquivos.
* O índice também é criptografado.
* Cada item possui um hash SHA-256 para verificação de integridade.
* `KAT_SIGNING_KEY` pode ser usada para assinar e verificar `.gpg-id`.
* `kat rekey` valida e recifra o cofre antes de substituir os arquivos definitivos.

### Estrutura

```text
.sweet/
├── .gpg-id
├── .gpg-id.sig
├── .kat-index.gpg
├── .git/
└── *.kat
```

O `.git/` é opcional e é criado pelo `kat init`.

## Atenção

KAT protege o conteúdo e os nomes dos arquivos, mas não esconde metadados como quantidade, tamanho e timestamps dos arquivos.

Operações que precisam acessar o conteúdo em claro utilizam arquivos temporários em `/tmp`.

`--rm` remove o arquivo original, mas não garante apagamento físico seguro.

## Licença

Este projeto é disponibilizado sob [GPLv3+](https://github.com/HGBits/Kat/blob/main/LICENSE)
