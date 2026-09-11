#!/usr/bin/env bash
#
# KAT - Gerenciador Seguro de Arquivos no diretório 'sweet'
#
# Nomes de arquivo ficam ofuscados (codinomes aleatórios pronunciáveis)
# em disco; o mapeamento codinome -> nome real fica só no índice cifrado
# ('.kat-index.gpg'), no mesmo espírito do pass-secrets.
#

set -euo pipefail

TARGET_DIR=".sweet"
GPG_ID_FILE="$TARGET_DIR/.gpg-id"
GPG_SIG_FILE="${GPG_ID_FILE}.sig"
INDEX_FILE="$TARGET_DIR/.kat-index.gpg"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    cat << EOF
KAT - Gerenciamento e criptografia de arquivos com nomes ofuscados em '$TARGET_DIR'.

USO:
    kat init <gpg-id...>                     Inicializa com chaves GPG públicas
    kat enc [-r|--rm] <arquivo1> [arq2...]   Criptografa arquivos/pastas (nome vira codinome aleatório)
    kat dec <termo|codinome...>              Descriptografa item(ns) pelo nome original ou codinome
    kat list [filtro]                        Lista os itens (codinome + nome original), opcionalmente filtrado
    kat find <termo>                         Busca por nome original no índice
    kat edit <termo|codinome>                Edita arquivo de texto em RAM e re-criptografa
    kat mv <termo|codinome> <novo_nome>      Renomeia a entrada no índice (não move o arquivo cifrado)
    kat rm <termo|codinome...>               Remove item(ns) cifrado(s) e sua entrada no índice
    kat verify <termo|codinome>              Verifica integridade (hash) de um item, sem extrair nada
    kat check                                Verifica a integridade de todos os itens
    kat tree                                  Mostra a árvore real do diretório '$TARGET_DIR' (só os codinomes em disco, como 'pass list')
    kat cp <termo|codinome> <novo_nome>      Duplica um item cifrado sob um novo nome lógico (mesmo blob, novo codinome)
    kat grep <termo>                         Busca o termo DENTRO do conteúdo dos itens (decifra tudo temporariamente pra buscar)
    kat rekey <novo-gpg-id...>               Recifra o cofre inteiro pra chave(s) nova(s)
    kat rekey --symmetric                    Recifra o cofre inteiro pra modo simétrico (passphrase)
    kat git <comandos_git...>                Executa comandos git no diretório '$TARGET_DIR'
    kat help                                 Exibe esta mensagem de ajuda

OPÇÕES DE CRIPTOGRAFIA:
    -r, --rm    Remove o arquivo original após criptografar com sucesso.

CONTROLE DE VERSÃO:
    'kat init' cria um repositório git em '$TARGET_DIR' (se ainda não existir).
    'enc', 'edit', 'mv', 'rm', 'cp' e 'rekey' fazem commit automático das
    mudanças. Se não houver repo git, essas operações continuam funcionando
    normalmente, só avisam que o commit foi pulado.

ASSINATURA DO .gpg-id (opcional, via variável de ambiente KAT_SIGNING_KEY):
    Se KAT_SIGNING_KEY estiver definida (fingerprint/e-mail de uma chave sua),
    'kat init' e 'kat rekey' assinam '.gpg-id' (gera '.gpg-id.sig'), e toda
    operação que for cifrar algo verifica essa assinatura antes. '.gpg-id'
    adulterado sem a assinatura bater faz o kat abortar antes de cifrar
    qualquer coisa pra chave errada. Com KAT_SIGNING_KEY definida, os commits
    automáticos do git também saem assinados (git commit -S).

SOBRE OS NOMES:
    O nome real de cada item só existe dentro do índice cifrado
    ('$INDEX_FILE'). Em disco você só vê codinomes, tipo 'Talko.kat'
    ou 'Nirev.kat' — inclusive no histórico do 'kat git'.
EOF
}

init_storage() {
    if [[ ! -d "$TARGET_DIR" ]]; then
        mkdir -p "$TARGET_DIR"
        chmod 700 "$TARGET_DIR"
        echo -e "${YELLOW}[KAT] Criando diretório '$TARGET_DIR' (permissão 700).${NC}"
    fi
}

get_gpg_recipients() {
    if [[ -f "$GPG_ID_FILE" ]]; then
        local recipients=()
        while IFS= read -r id || [[ -n "$id" ]]; do
            id="${id%%#*}"
            id="${id// /}"
            [[ -n "$id" ]] && recipients+=("-r" "$id")
        done < "$GPG_ID_FILE"

        if [[ ${#recipients[@]} -gt 0 ]]; then
            printf '%s\n' "${recipients[@]}"
            return 0
        fi
    fi
    return 1
}

# Assina '.gpg-id' com KAT_SIGNING_KEY (se configurada). Sem essa variável,
# o kat funciona igual a antes (sem assinatura, sem verificação).
sign_gpg_id() {
    [[ -z "${KAT_SIGNING_KEY:-}" ]] && return 0
    [[ ! -f "$GPG_ID_FILE" ]] && { rm -f "$GPG_SIG_FILE"; return 0; }
    if ! gpg --batch --yes --local-user "$KAT_SIGNING_KEY" --detach-sign -o "$GPG_SIG_FILE" "$GPG_ID_FILE" 2>/dev/null; then
        echo -e "${RED}[ERRO] Falha ao assinar '$GPG_ID_FILE' com a chave '$KAT_SIGNING_KEY'.${NC}" >&2
        exit 1
    fi
    chmod 600 "$GPG_SIG_FILE"
}

# Verifica a assinatura do '.gpg-id' ANTES de ele ser usado pra cifrar algo
# novo. Protege contra um '.gpg-id' adulterado (destinatário trocado por
# alguém com acesso de escrita a '$TARGET_DIR') redirecionando cifragens
# futuras pra uma chave que não é a sua. Mesmo modelo de ameaça do
# 'verify_file()' do pass-secrets: só entra em ação no caminho de escrita.
#
# IMPORTANTE: esta função é chamada diretamente (nunca dentro de "$(...)").
# 'exit' dentro de uma substituição de comando só mata a subshell da
# substituição, não o script — isso já foi um bug real aqui: a verificação
# falhava, o 'exit 1' morria na subshell, e o chamador lia isso como "sem
# destinatários" e caía pro modo simétrico silenciosamente, cifrando mesmo
# assim. Testado e confirmado antes desta correção.
verify_gpg_id() {
    [[ ! -f "$GPG_ID_FILE" ]] && return 0
    if [[ -z "${KAT_SIGNING_KEY:-}" && ! -f "$GPG_SIG_FILE" ]]; then
        return 0
    fi
    if [[ ! -f "$GPG_SIG_FILE" ]]; then
        echo -e "${RED}[ERRO DE SEGURANÇA] KAT_SIGNING_KEY está configurada, mas '$GPG_SIG_FILE' não existe. Recusando usar um '.gpg-id' sem assinatura. Rode 'kat init'/'kat rekey' de novo pra gerar a assinatura.${NC}" >&2
        exit 1
    fi
    if ! gpg --batch --verify "$GPG_SIG_FILE" "$GPG_ID_FILE" 2>/dev/null; then
        echo -e "${RED}[ERRO DE SEGURANÇA] Assinatura de '$GPG_ID_FILE' é INVÁLIDA. O arquivo pode ter sido adulterado (destinatário trocado). Abortando antes de cifrar qualquer coisa.${NC}" >&2
        exit 1
    fi
}

# Monta as opções de criptografia (assimétrico se houver .gpg-id, senão simétrico).
# Recebe o NOME da variável de array a preencher (nameref), evita duplicar a lógica.
build_gpg_encrypt_opts() {
    local -n _out_arr="$1"
    verify_gpg_id
    _out_arr=("--cipher-algo" "AES256")
    local recipients_raw
    if recipients_raw=$(get_gpg_recipients); then
        while IFS= read -r arg; do _out_arr+=("$arg"); done <<< "$recipients_raw"
        _out_arr+=("--encrypt")
    else
        _out_arr+=("--symmetric")
    fi
}

# ---------------------------------------------------------------------------
# Índice cifrado: cada linha é  codinome<TAB>tipo<TAB>nome_original<TAB>sha256
# ---------------------------------------------------------------------------

index_load() {
    if [[ -f "$INDEX_FILE" ]]; then
        if ! gpg -d -o - "$INDEX_FILE" 2>/dev/null; then
            echo -e "${RED}[ERRO] Falha ao descriptografar o índice '$INDEX_FILE'. Abortando.${NC}" >&2
            exit 1
        fi
    fi
}

index_save() {
    local content="$1"
    init_storage
    local -a gpg_opts
    build_gpg_encrypt_opts gpg_opts

    local tmp
    tmp=$(mktemp -p /tmp kat_index.XXXXXX)
    chmod 600 "$tmp"
    printf '%s\n' "$content" | sed '/^$/d' > "$tmp"

    if gpg "${gpg_opts[@]}" -o "${INDEX_FILE}.new" "$tmp"; then
        mv "${INDEX_FILE}.new" "$INDEX_FILE"
        chmod 600 "$INDEX_FILE"
        rm -f "$tmp"
    else
        rm -f "${INDEX_FILE}.new" "$tmp"
        echo -e "${RED}[ERRO] Falha ao salvar o índice cifrado.${NC}" >&2
        exit 1
    fi
}

# Gera um codinome pronunciável (2-3 sílabas consoante+vogal), ex: "Talko".
_kat_codename() {
    local consoantes=(b c d f g h j k l m n p r s t v z)
    local vogais=(a e i o u)
    local syl_count=$(( (RANDOM % 2) + 2 ))
    local word="" i
    for ((i = 0; i < syl_count; i++)); do
        word+="${consoantes[$((RANDOM % ${#consoantes[@]}))]}"
        word+="${vogais[$((RANDOM % ${#vogais[@]}))]}"
    done
    echo "${word^}"
}

# Gera um codinome que ainda não existe no índice fornecido.
kat_free_codename() {
    local index_content="$1"
    local candidate tries=0
    while true; do
        candidate=$(_kat_codename)
        if ! printf '%s\n' "$index_content" | cut -f1 | grep -qxF "$candidate"; then
            echo "$candidate"
            return 0
        fi
        tries=$((tries + 1))
        if [[ $tries -gt 200 ]]; then
            echo -e "${RED}[ERRO] Não foi possível gerar um codinome único.${NC}" >&2
            return 1
        fi
    done
}

# Resolve um termo (codinome exato OU substring case-insensitive do nome
# original) para UMA linha do índice. Se ambíguo, lista candidatos e falha.
resolve_entry() {
    local index_content="$1" query="$2"
    local exact
    exact=$(printf '%s\n' "$index_content" | awk -F'\t' -v q="$query" '$1==q {print}')
    if [[ -n "$exact" ]]; then
        printf '%s\n' "$exact"
        return 0
    fi

    local q_lower matches count
    q_lower=$(tr '[:upper:]' '[:lower:]' <<< "$query")
    matches=$(printf '%s\n' "$index_content" | awk -F'\t' -v q="$q_lower" '{ l=tolower($3); if (index(l,q) > 0) print }')
    count=$(printf '%s\n' "$matches" | grep -c .)

    if [[ "$count" -eq 0 ]]; then
        echo -e "${RED}[ERRO] Nenhuma entrada encontrada para '${query}'.${NC}" >&2
        return 1
    elif [[ "$count" -gt 1 ]]; then
        echo -e "${YELLOW}[AVISO] Múltiplas entradas correspondem a '${query}'. Especifique o codinome:${NC}" >&2
        printf '%s\n' "$matches" | awk -F'\t' '{printf "  %-12s [%s] %s\n", $1, $2, $3}' >&2
        return 1
    else
        printf '%s\n' "$matches"
        return 0
    fi
}

# ---------------------------------------------------------------------------
# Comandos
# ---------------------------------------------------------------------------

cmd_init() {
    [[ $# -eq 0 ]] && { echo -e "${RED}[ERRO] Informe o GPG ID ou e-mail.${NC}" >&2; exit 1; }
    init_storage
    : > "$GPG_ID_FILE"
    for gpg_id in "$@"; do
        echo "$gpg_id" >> "$GPG_ID_FILE"
    done
    chmod 600 "$GPG_ID_FILE"
    sign_gpg_id
    echo -e "${GREEN}[SUCESSO] Armazenamento inicializado para as chaves fornecidas.${NC}"

    if [[ ! -d "$TARGET_DIR/.git" ]]; then
        if git -C "$TARGET_DIR" init -q; then
            echo -e "${GREEN}[KAT] Repositório git inicializado em '$TARGET_DIR'.${NC}"
        else
            echo -e "${YELLOW}[AVISO] Não foi possível inicializar git em '$TARGET_DIR'.${NC}" >&2
        fi
    fi
    check_git_identity || true
    kat_git_autocommit "kat: init (.gpg-id)"
}

cmd_encrypt() {
    local remove_original=false
    if [[ "${1:-}" == "-r" || "${1:-}" == "--rm" ]]; then
        remove_original=true
        shift
    fi
    [[ $# -eq 0 ]] && { echo -e "${RED}[ERRO] Nenhum arquivo fornecido para criptografar.${NC}" >&2; exit 1; }

    init_storage
    local -a gpg_opts
    build_gpg_encrypt_opts gpg_opts

    local working_index
    working_index=$(index_load)
    local -a added_codenames=()

    local target
    for target in "$@"; do
        if [[ ! -e "$target" ]]; then
            echo -e "${RED}[AVISO] '$target' não existe. Pulando...${NC}" >&2
            continue
        fi

        local base_name codename tipo original_hash enc_ok
        base_name=$(basename "$target")
        if ! codename=$(kat_free_codename "$working_index"); then
            continue
        fi
        local output_file="$TARGET_DIR/${codename}.kat"

        echo -e "${BLUE}[KAT] Criptografando '${target}'...${NC}"

        if [[ -d "$target" ]]; then
            tipo="dir"
            local tmp_tar
            tmp_tar=$(mktemp -p /tmp kat_tar.XXXXXX)
            if ! tar -czf "$tmp_tar" -C "$(dirname "$target")" "$base_name"; then
                echo -e "${RED}[ERRO] Falha ao compactar '$target'.${NC}" >&2
                rm -f "$tmp_tar"
                continue
            fi
            original_hash=$(sha256sum "$tmp_tar" | awk '{print $1}')
            if gpg "${gpg_opts[@]}" -o "$output_file" "$tmp_tar"; then
                enc_ok=true
            else
                enc_ok=false
            fi
            rm -f "$tmp_tar"
        else
            tipo="file"
            original_hash=$(sha256sum "$target" | awk '{print $1}')
            if gpg "${gpg_opts[@]}" -o "$output_file" "$target"; then
                enc_ok=true
            else
                enc_ok=false
            fi
        fi

        if [[ "$enc_ok" == true ]]; then
            chmod 600 "$output_file"
            echo -e "${GREEN}[SUCESSO] '${target}' → ${codename}.kat${NC}"
            local new_line
            new_line=$(printf '%s\t%s\t%s\t%s' "$codename" "$tipo" "$base_name" "$original_hash")
            if [[ -n "$working_index" ]]; then
                working_index="${working_index}"$'\n'"${new_line}"
            else
                working_index="$new_line"
            fi
            added_codenames+=("$codename")
            if $remove_original; then
                rm -rf "$target"
                echo -e "${YELLOW}[KAT] Original '$target' removido.${NC}"
            fi
        else
            echo -e "${RED}[ERRO] Falha ao criptografar '$target'.${NC}" >&2
            rm -f "$output_file"
        fi
    done

    if [[ ${#added_codenames[@]} -gt 0 ]]; then
        index_save "$working_index"
        kat_git_autocommit "kat: enc ${added_codenames[*]}"
    fi
}

cmd_decrypt() {
    [[ $# -eq 0 ]] && { echo -e "${RED}[ERRO] Informe termo(s) ou codinome(s) para descriptografar.${NC}" >&2; exit 1; }
    init_storage
    local index_content
    index_content=$(index_load)

    local query
    for query in "$@"; do
        local entry
        if ! entry=$(resolve_entry "$index_content" "$query"); then
            continue
        fi
        local codename tipo nome hash
        IFS=$'\t' read -r codename tipo nome hash <<< "$entry"
        local enc_file="$TARGET_DIR/${codename}.kat"

        if [[ ! -f "$enc_file" ]]; then
            echo -e "${RED}[ERRO] Índice aponta para '$enc_file', mas o arquivo não existe.${NC}" >&2
            continue
        fi

        local tmp_dir tmp_plain
        tmp_dir=$(mktemp -d -p /tmp kat_dec.XXXXXX)
        chmod 700 "$tmp_dir"
        tmp_plain="$tmp_dir/plain"

        echo -e "${BLUE}[KAT] Descriptografando '${nome}' (${codename})...${NC}"
        if ! gpg -d -o "$tmp_plain" "$enc_file"; then
            echo -e "${RED}[ERRO] Falha ao descriptografar '${enc_file}'.${NC}" >&2
            rm -rf "$tmp_dir"
            continue
        fi

        local calc_hash
        calc_hash=$(sha256sum "$tmp_plain" | awk '{print $1}')
        if [[ -n "$hash" && "$calc_hash" != "$hash" ]]; then
            echo -e "${RED}[AVISO DE INTEGRIDADE] Hash de '${nome}' não confere (esperado ${hash}, obtido ${calc_hash}). Pode estar corrompido.${NC}" >&2
        fi

        if [[ "$tipo" == "dir" ]]; then
            if [[ -e "$nome" ]]; then
                echo -e "${YELLOW}[AVISO] '${nome}' já existe aqui; a extração pode mesclar/sobrescrever.${NC}"
            fi
            tar -xzf "$tmp_plain"
            echo -e "${GREEN}[SUCESSO] Pasta '${nome}' restaurada.${NC}"
        else
            local dest="$nome"
            if [[ -e "$dest" ]]; then
                dest="${nome}.dec"
                echo -e "${YELLOW}[AVISO] '${nome}' já existe aqui. Salvando como '${dest}'.${NC}"
            fi
            mv "$tmp_plain" "$dest"
            echo -e "${GREEN}[SUCESSO] Arquivo restaurado: ${dest}${NC}"
        fi
        rm -rf "$tmp_dir"
    done
}

cmd_list() {
    local filtro="${1:-}"
    init_storage
    local index_content
    index_content=$(index_load)

    if [[ -z "$index_content" ]]; then
        echo -e "${YELLOW}[KAT] Nenhum item armazenado ainda.${NC}"
        return 0
    fi

    echo -e "${BLUE}CODINOME     TIPO   NOME ORIGINAL${NC}"
    local filtro_lower
    filtro_lower=$(tr '[:upper:]' '[:lower:]' <<< "$filtro")
    printf '%s\n' "$index_content" | awk -F'\t' -v filtro="$filtro_lower" '
        { l = tolower($3) }
        filtro == "" || index(l, filtro) > 0 { printf "%-12s %-6s %s\n", $1, $2, $3 }
    '
}

cmd_edit() {
    local query="${1:-}"
    [[ -z "$query" ]] && { echo -e "${RED}[ERRO] Informe o termo ou codinome do item a editar.${NC}" >&2; exit 1; }
    init_storage
    local index_content
    index_content=$(index_load)

    local entry
    if ! entry=$(resolve_entry "$index_content" "$query"); then
        exit 1
    fi
    local codename tipo nome hash
    IFS=$'\t' read -r codename tipo nome hash <<< "$entry"

    if [[ "$tipo" != "file" ]]; then
        echo -e "${RED}[ERRO] '${nome}' é uma pasta compactada; 'kat edit' só funciona em arquivos.${NC}" >&2
        exit 1
    fi

    local enc_file="$TARGET_DIR/${codename}.kat"
    local tmp_dir
    tmp_dir=$(mktemp -d -p /tmp kat_edit.XXXXXX)
    chmod 700 "$tmp_dir"
    local tmp_file="$tmp_dir/$nome"
    trap 'rm -rf "${tmp_dir:-}"' EXIT

    if ! gpg -d -o "$tmp_file" "$enc_file"; then
        echo -e "${RED}[ERRO] Falha ao descriptografar '${enc_file}'.${NC}" >&2
        exit 1
    fi

    # Sem aspas de propósito: $EDITOR pode ter argumentos ("code --wait",
    # "emacsclient -t"), e isso precisa de word-splitting pra funcionar.
    ${EDITOR:-vim} "$tmp_file"

    local new_hash
    new_hash=$(sha256sum "$tmp_file" | awk '{print $1}')

    local -a gpg_opts
    build_gpg_encrypt_opts gpg_opts

    if ! gpg "${gpg_opts[@]}" -o "${enc_file}.tmp" "$tmp_file"; then
        echo -e "${RED}[ERRO] Falha ao re-criptografar '${nome}'.${NC}" >&2
        rm -f "${enc_file}.tmp"
        exit 1
    fi
    mv "${enc_file}.tmp" "$enc_file"
    chmod 600 "$enc_file"

    local updated_index
    updated_index=$(printf '%s\n' "$index_content" | awk -F'\t' -v OFS='\t' -v cn="$codename" -v nh="$new_hash" '$1==cn {$4=nh} {print}')
    index_save "$updated_index"
    kat_git_autocommit "kat: edit ${codename}"

    echo -e "${GREEN}[SUCESSO] '${nome}' re-criptografado e índice atualizado.${NC}"
}

cmd_mv() {
    local query="${1:-}" novo_nome="${2:-}"
    [[ -z "$query" || -z "$novo_nome" ]] && { echo -e "${RED}[ERRO] Uso: kat mv <termo|codinome> <novo_nome_logico>${NC}" >&2; exit 1; }
    init_storage
    local index_content
    index_content=$(index_load)

    local entry
    if ! entry=$(resolve_entry "$index_content" "$query"); then
        exit 1
    fi
    local codename tipo nome hash
    IFS=$'\t' read -r codename tipo nome hash <<< "$entry"

    local updated_index
    updated_index=$(printf '%s\n' "$index_content" | awk -F'\t' -v OFS='\t' -v cn="$codename" -v nn="$novo_nome" '$1==cn {$3=nn} {print}')
    index_save "$updated_index"
    kat_git_autocommit "kat: mv ${codename}"
    echo -e "${GREEN}[SUCESSO] '${nome}' renomeado para '${novo_nome}' no índice (codinome '${codename}' não muda).${NC}"
}

cmd_rm() {
    [[ $# -eq 0 ]] && { echo -e "${RED}[ERRO] Informe termo(s) ou codinome(s) para remover.${NC}" >&2; exit 1; }
    init_storage
    local index_content
    index_content=$(index_load)

    local query
    local -a removed=()
    for query in "$@"; do
        local entry
        if ! entry=$(resolve_entry "$index_content" "$query"); then
            continue
        fi
        local codename tipo nome hash
        IFS=$'\t' read -r codename tipo nome hash <<< "$entry"
        echo -e "${YELLOW}[KAT] Removendo '${nome}' (${codename}.kat)...${NC}"
        rm -f "$TARGET_DIR/${codename}.kat"
        removed+=("$codename")
    done

    if [[ ${#removed[@]} -gt 0 ]]; then
        local updated_index="$index_content"
        local cn
        for cn in "${removed[@]}"; do
            updated_index=$(printf '%s\n' "$updated_index" | awk -F'\t' -v cn="$cn" '$1!=cn {print}')
        done
        index_save "$updated_index"
        kat_git_autocommit "kat: rm ${removed[*]}"
        echo -e "${GREEN}[SUCESSO] Índice atualizado.${NC}"
    fi
}

verify_one() {
    local index_content="$1" query="$2"
    local entry
    if ! entry=$(resolve_entry "$index_content" "$query"); then
        return 1
    fi
    local codename tipo nome hash
    IFS=$'\t' read -r codename tipo nome hash <<< "$entry"
    local enc_file="$TARGET_DIR/${codename}.kat"

    if [[ ! -f "$enc_file" ]]; then
        echo -e "${RED}[ERRO] '${enc_file}' não existe (índice inconsistente).${NC}" >&2
        return 1
    fi

    local tmp
    tmp=$(mktemp -p /tmp kat_verify.XXXXXX)
    if ! gpg -d -o "$tmp" "$enc_file" 2>/dev/null; then
        echo -e "${RED}[FALHA] '${nome}' (${codename}): não foi possível descriptografar.${NC}"
        rm -f "$tmp"
        return 1
    fi

    local calc
    calc=$(sha256sum "$tmp" | awk '{print $1}')
    rm -f "$tmp"

    if [[ -z "$hash" ]]; then
        echo -e "${YELLOW}[SEM HASH] '${nome}' (${codename}): índice sem hash registrado, não dá pra verificar.${NC}"
        return 0
    elif [[ "$calc" == "$hash" ]]; then
        echo -e "${GREEN}[OK] '${nome}' (${codename}): íntegro.${NC}"
        return 0
    else
        echo -e "${RED}[CORROMPIDO] '${nome}' (${codename}): hash não confere.${NC}"
        return 1
    fi
}

cmd_verify() {
    local query="${1:-}"
    [[ -z "$query" ]] && { echo -e "${RED}[ERRO] Informe termo ou codinome para verificar.${NC}" >&2; exit 1; }
    init_storage
    local index_content
    index_content=$(index_load)
    verify_one "$index_content" "$query"
}

cmd_check() {
    init_storage
    local index_content
    index_content=$(index_load)
    if [[ -z "$index_content" ]]; then
        echo -e "${YELLOW}[KAT] Nenhum item armazenado ainda.${NC}"
        return 0
    fi

    local ok=0 fail=0 codename
    while IFS=$'\t' read -r codename _ _ _; do
        [[ -z "$codename" ]] && continue
        if verify_one "$index_content" "$codename"; then
            ok=$((ok + 1))
        else
            fail=$((fail + 1))
        fi
    done <<< "$index_content"

    echo -e "${BLUE}[KAT] Verificação completa: ${GREEN}${ok} ok${NC}, ${RED}${fail} falha(s)${NC}."
}

cmd_cp() {
    local query="${1:-}" novo_nome="${2:-}"
    [[ -z "$query" || -z "$novo_nome" ]] && { echo -e "${RED}[ERRO] Uso: kat cp <termo|codinome> <novo_nome>${NC}" >&2; exit 1; }
    init_storage
    local index_content
    index_content=$(index_load)

    local entry
    if ! entry=$(resolve_entry "$index_content" "$query"); then
        exit 1
    fi
    local codename tipo nome hash
    IFS=$'\t' read -r codename tipo nome hash <<< "$entry"

    local new_codename
    if ! new_codename=$(kat_free_codename "$index_content"); then
        exit 1
    fi

    # Copia o blob cifrado como está — mesmo conteúdo, mesmo hash, só muda
    # o nome lógico no índice. Não precisa decifrar/recifrar nada.
    cp "$TARGET_DIR/${codename}.kat" "$TARGET_DIR/${new_codename}.kat"
    chmod 600 "$TARGET_DIR/${new_codename}.kat"

    local new_line
    new_line=$(printf '%s\t%s\t%s\t%s' "$new_codename" "$tipo" "$novo_nome" "$hash")
    local updated_index="${index_content}"$'\n'"${new_line}"
    index_save "$updated_index"
    kat_git_autocommit "kat: cp ${codename} -> ${new_codename}"
    echo -e "${GREEN}[SUCESSO] '${nome}' copiado como '${novo_nome}' (${new_codename}.kat).${NC}"
}

cmd_grep() {
    local pattern="${1:-}"
    [[ -z "$pattern" ]] && { echo -e "${RED}[ERRO] Informe o termo/padrão de busca.${NC}" >&2; exit 1; }
    init_storage
    local index_content
    index_content=$(index_load)
    if [[ -z "$index_content" ]]; then
        echo -e "${YELLOW}[KAT] Nenhum item armazenado ainda.${NC}"
        return 0
    fi

    local codename tipo nome hash found_any=false
    while IFS=$'\t' read -r codename tipo nome hash; do
        [[ -z "$codename" ]] && continue
        local enc_file="$TARGET_DIR/${codename}.kat"
        local tmp_dir
        tmp_dir=$(mktemp -d -p /tmp kat_grep.XXXXXX)
        chmod 700 "$tmp_dir"

        if [[ "$tipo" == "dir" ]]; then
            local tmp_tar="$tmp_dir/archive.tar.gz"
            if gpg -d -o "$tmp_tar" "$enc_file" 2>/dev/null; then
                mkdir -p "$tmp_dir/extract"
                if tar -xzf "$tmp_tar" -C "$tmp_dir/extract" 2>/dev/null; then
                    local matches
                    matches=$(grep -rIn -e "$pattern" "$tmp_dir/extract" 2>/dev/null | sed "s#^${tmp_dir}/extract/##" || true)
                    if [[ -n "$matches" ]]; then
                        found_any=true
                        echo -e "${GREEN}${nome}/ (${codename}):${NC}"
                        printf '%s\n' "$matches" | sed 's/^/  /'
                    fi
                fi
            else
                echo -e "${RED}[AVISO] Não consegui abrir '${nome}' (${codename}) pra buscar dentro.${NC}" >&2
            fi
        else
            local tmp_file="$tmp_dir/plain"
            if gpg -d -o "$tmp_file" "$enc_file" 2>/dev/null; then
                if grep -Il -e "$pattern" "$tmp_file" >/dev/null 2>&1; then
                    found_any=true
                    echo -e "${GREEN}${nome} (${codename}):${NC}"
                    grep -n -e "$pattern" "$tmp_file" | sed 's/^/  /'
                fi
            else
                echo -e "${RED}[AVISO] Não consegui abrir '${nome}' (${codename}) pra buscar dentro.${NC}" >&2
            fi
        fi
        rm -rf "$tmp_dir"
    done <<< "$index_content"

    if ! $found_any; then
        echo -e "${YELLOW}[KAT] Nenhuma ocorrência de '${pattern}' encontrada.${NC}"
    fi
}

# Recifra TODO o cofre pra uma chave/config nova. Só troca o '.gpg-id' (e a
# assinatura) depois que TUDO já foi decifrado, verificado (hash) e
# recifrado com sucesso — se algo falhar no meio, nada em disco é tocado
# além dos arquivos de trabalho em /tmp.
cmd_rekey() {
    init_storage
    local -a new_opts=("--cipher-algo" "AES256")
    local -a new_gpg_id_lines=()
    local going_symmetric=false

    if [[ "${1:-}" == "--symmetric" ]]; then
        going_symmetric=true
        new_opts+=("--symmetric")
    else
        [[ $# -eq 0 ]] && { echo -e "${RED}[ERRO] Uso: kat rekey <novo-gpg-id...> | kat rekey --symmetric${NC}" >&2; exit 1; }
        local rid
        for rid in "$@"; do
            new_opts+=("-r" "$rid")
            new_gpg_id_lines+=("$rid")
        done
        new_opts+=("--encrypt")
    fi

    local index_content
    index_content=$(index_load)

    if [[ -z "$index_content" ]]; then
        echo -e "${YELLOW}[KAT] Cofre vazio, só trocando a configuração de chave.${NC}"
    fi

    local staging
    staging=$(mktemp -d -p /tmp kat_rekey.XXXXXX)
    chmod 700 "$staging"

    # 1) Decifra e VERIFICA (hash) tudo antes de mexer em qualquer coisa.
    local codename tipo nome hash
    local -a items=()
    while IFS=$'\t' read -r codename tipo nome hash; do
        [[ -z "$codename" ]] && continue
        local enc_file="$TARGET_DIR/${codename}.kat"
        if [[ ! -f "$enc_file" ]]; then
            echo -e "${RED}[ERRO] '${enc_file}' não existe (índice inconsistente). Abortando rekey sem tocar em nada.${NC}" >&2
            rm -rf "$staging"
            exit 1
        fi
        local plain="$staging/$codename"
        if ! gpg -d -o "$plain" "$enc_file" 2>/dev/null; then
            echo -e "${RED}[ERRO] Falha ao decifrar '${nome}' (${codename}). Abortando rekey sem tocar em nada.${NC}" >&2
            rm -rf "$staging"
            exit 1
        fi
        local calc
        calc=$(sha256sum "$plain" | awk '{print $1}')
        if [[ -n "$hash" && "$calc" != "$hash" ]]; then
            echo -e "${RED}[ERRO] Hash de '${nome}' (${codename}) não confere ANTES do rekey. Abortando pra não recifrar dado já corrompido.${NC}" >&2
            rm -rf "$staging"
            exit 1
        fi
        items+=("$codename")
    done <<< "$index_content"

    echo -e "${BLUE}[KAT] ${#items[@]} item(ns) decifrados e verificados. Recifrando...${NC}"

    # 2) Recifra cada item na config NOVA, em arquivo separado (.rekey) —
    # os '.kat' reais só são substituídos depois que TODOS derem certo.
    local cn
    for cn in "${items[@]}"; do
        if ! gpg "${new_opts[@]}" -o "$TARGET_DIR/${cn}.kat.rekey" "$staging/$cn"; then
            echo -e "${RED}[ERRO] Falha ao recifrar '${cn}' com a config nova. Abortando — nenhum '.kat' definitivo foi trocado ainda.${NC}" >&2
            rm -f "$TARGET_DIR"/*.kat.rekey
            rm -rf "$staging"
            exit 1
        fi
    done

    # 3) Ponto de não-retorno: troca os arquivos e a config de chave.
    for cn in "${items[@]}"; do
        mv "$TARGET_DIR/${cn}.kat.rekey" "$TARGET_DIR/${cn}.kat"
        chmod 600 "$TARGET_DIR/${cn}.kat"
    done
    rm -rf "$staging"

    if $going_symmetric; then
        rm -f "$GPG_ID_FILE" "$GPG_SIG_FILE"
    else
        printf '%s\n' "${new_gpg_id_lines[@]}" > "$GPG_ID_FILE"
        chmod 600 "$GPG_ID_FILE"
        sign_gpg_id
    fi

    # 4) Índice também precisa ser recifrado com a config nova.
    index_save "$index_content"
    kat_git_autocommit "kat: rekey (${#items[@]} item(ns))"

    echo -e "${GREEN}[SUCESSO] Rekey completo: ${#items[@]} item(ns) recifrados.${NC}"
}

cmd_git() {
    init_storage
    git -C "$TARGET_DIR" "$@"
}

# Commit automático das mudanças em '$TARGET_DIR' (enc/edit/mv/rm/init).
# Nunca derruba o script: se não houver repo, ou o commit falhar (ex.: sem
# user.name/user.email configurado), só avisa e segue.
# Confere se git tem como assinar o commit em nome de alguém (local OU
# global — 'git config' já resolve essa precedência sozinho). Só avisa; não
# aborta o 'kat init', porque tudo o resto (gpg-id, cifragem) funciona sem
# git de qualquer jeito.
check_git_identity() {
    if [[ ! -d "$TARGET_DIR/.git" ]]; then
        return 0
    fi
    local name email
    name=$(git -C "$TARGET_DIR" config user.name 2>/dev/null || true)
    email=$(git -C "$TARGET_DIR" config user.email 2>/dev/null || true)
    if [[ -z "$name" || -z "$email" ]]; then
        echo -e "${YELLOW}[AVISO] git user.name/user.email não configurados (nem local, nem global) para '$TARGET_DIR'. Os commits automáticos de 'enc'/'edit'/'mv'/'rm'/'cp'/'rekey' vão falhar até você rodar:${NC}" >&2
        echo -e "${YELLOW}    git -C '$TARGET_DIR' config user.name \"Seu Nome\"${NC}" >&2
        echo -e "${YELLOW}    git -C '$TARGET_DIR' config user.email \"seu@email\"${NC}" >&2
        return 1
    fi
    return 0
}

kat_git_autocommit() {
    local message="$1"
    if [[ ! -d "$TARGET_DIR/.git" ]]; then
        echo -e "${YELLOW}[KAT] (sem controle de versão: rode 'kat init' com uma chave, ou 'kat git init' manualmente, pra ativar commits automáticos)${NC}" >&2
        return 0
    fi
    if ! git -C "$TARGET_DIR" add -A; then
        echo -e "${YELLOW}[AVISO] 'git add' falhou em '$TARGET_DIR'; commit automático pulado.${NC}" >&2
        return 0
    fi
    if git -C "$TARGET_DIR" diff --cached --quiet; then
        return 0
    fi
    local -a commit_opts=(-q -m "$message")
    [[ -n "${KAT_SIGNING_KEY:-}" ]] && commit_opts+=("-S${KAT_SIGNING_KEY}")
    if git -C "$TARGET_DIR" commit "${commit_opts[@]}"; then
        echo -e "${BLUE}[KAT] git commit: ${message}${NC}"
    else
        echo -e "${YELLOW}[AVISO] 'git commit' falhou em '$TARGET_DIR' (user.name/user.email configurados? KAT_SIGNING_KEY válida?). Mudanças ficaram staged.${NC}" >&2
    fi
    return 0
}

# Renderizador de árvore próprio (fallback quando o binário 'tree' não existe).
# Recebe a lista de caminhos (um por linha, diretórios terminando em '/').
_kat_render_tree() {
    local paths="$1"
    local -A children=()
    local -A is_dir=()
    # bash não aceita "" como chave de array associativo (erro "bad array
    # subscript"); usamos uma sentinela pra representar a raiz da árvore.
    local root_key="@kat-tree-root@"

    _kat_tree_add_path() {
        local path="$1" isdir=0
        [[ "$path" == */ ]] && { isdir=1; path="${path%/}"; }
        [[ -z "$path" ]] && return
        local -a parts
        IFS='/' read -ra parts <<< "$path"
        local cur="$root_key" parent i
        for ((i = 0; i < ${#parts[@]}; i++)); do
            local part="${parts[$i]}"
            [[ -z "$part" ]] && continue
            parent="$cur"
            if [[ "$cur" == "$root_key" ]]; then cur="$part"; else cur="$cur/$part"; fi
            if [[ ",${children[$parent]:-}," != *",$cur,"* ]]; then
                children["$parent"]="${children[$parent]:-},$cur"
            fi
            if [[ $i -lt $((${#parts[@]} - 1)) || $isdir -eq 1 ]]; then
                is_dir["$cur"]=1
            fi
        done
    }

    _kat_tree_print() {
        local parent="$1" prefix="$2"
        local list="${children[$parent]:-}"
        list="${list#,}"
        [[ -z "$list" ]] && return
        local sorted
        sorted=$(tr ',' '\n' <<< "$list" | sort)
        local total
        total=$(printf '%s\n' "$sorted" | grep -c .)
        local idx=0 kid
        while IFS= read -r kid; do
            [[ -z "$kid" ]] && continue
            idx=$((idx + 1))
            local base="${kid##*/}"
            local connector="├── " newprefix="${prefix}│   "
            if [[ $idx -eq $total ]]; then
                connector="└── "
                newprefix="${prefix}    "
            fi
            if [[ -n "${is_dir[$kid]:-}" ]]; then
                echo "${prefix}${connector}${base}/"
            else
                echo "${prefix}${connector}${base}"
            fi
            _kat_tree_print "$kid" "$newprefix"
        done <<< "$sorted"
    }

    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        _kat_tree_add_path "$line"
    done <<< "$paths"

    _kat_tree_print "$root_key" ""
}

cmd_tree() {
    init_storage
    echo -e "${BLUE}${TARGET_DIR}/${NC}"

    # Só o que existe de verdade em disco (codinomes) — nenhum gpg envolvido,
    # igual ao 'pass list': mostra a árvore do store, não o conteúdo cifrado.
    local -a paths_arr=()
    local entry rel
    while IFS= read -r -d '' entry; do
        rel="${entry#"$TARGET_DIR"/}"
        case "$rel" in
            .gpg-id|.kat-index.gpg|.git|.git/*) continue ;;
        esac
        if [[ -d "$entry" ]]; then
            paths_arr+=("${rel}/")
        else
            paths_arr+=("$rel")
        fi
    done < <(find "$TARGET_DIR" -mindepth 1 -print0)

    if [[ ${#paths_arr[@]} -eq 0 ]]; then
        echo -e "${YELLOW}[KAT] Vazio.${NC}"
        return 0
    fi

    local paths
    paths=$(printf '%s\n' "${paths_arr[@]}" | sort)
    if command -v tree >/dev/null 2>&1; then
        printf '%s\n' "$paths" | tree --fromfile -
    else
        _kat_render_tree "$paths"
    fi
}

COMMAND="${1:-}"
shift 2>/dev/null || true

case "$COMMAND" in
    init) cmd_init "$@" ;;
    enc|encrypt) cmd_encrypt "$@" ;;
    dec|decrypt) cmd_decrypt "$@" ;;
    list|ls) cmd_list "${1:-}" ;;
    find)
        [[ -z "${1:-}" ]] && { echo -e "${RED}[ERRO] Informe um termo de busca.${NC}" >&2; exit 1; }
        cmd_list "$1"
        ;;
    edit) cmd_edit "${1:-}" ;;
    mv) cmd_mv "${1:-}" "${2:-}" ;;
    rm) cmd_rm "$@" ;;
    verify) cmd_verify "${1:-}" ;;
    check) cmd_check ;;
    tree) cmd_tree ;;
    cp|copy) cmd_cp "${1:-}" "${2:-}" ;;
    grep) cmd_grep "${1:-}" ;;
    rekey) cmd_rekey "$@" ;;
    git) cmd_git "$@" ;;
    help|-h|--help|"") usage ;;
    *) echo -e "${RED}[ERRO] Comando desconhecido: $COMMAND${NC}" >&2; usage; exit 1 ;;
esac
