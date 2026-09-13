#!/usr/bin/env bash
# Shared launcher logic; .env is data, never executable shell input.
load_credentials() {
  local line key value
  SANDBOX_USER=; SANDBOX_PASSWORD=
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) return 1 ;; esac
    key=${line%%=*}; value=${line#*=}
    case "$key" in
      SANDBOX_USER)
        [ -z "$SANDBOX_USER" ] || return 1
        [[ "$value" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
        SANDBOX_USER=$value ;;
      SANDBOX_PASSWORD)
        [ -z "$SANDBOX_PASSWORD" ] || return 1
        [[ "$value" =~ ^[A-Za-z0-9_+./:@%-]+$ ]] || return 1
        SANDBOX_PASSWORD=$value ;;
      *) return 1 ;;
    esac
  done < "$1"
  [ -n "$SANDBOX_USER" ] && [ -n "$SANDBOX_PASSWORD" ] || return 1
  # Export to ensure Compose uses the same credentials the launcher displays,
  # even if the caller had conflicting environment variables.
  export SANDBOX_USER SANDBOX_PASSWORD
}

desktop_ready() {
  local code
  code=$(curl --disable -ks --noproxy '*' --max-time 3 -o /dev/null -w '%{http_code}' \
    https://127.0.0.1:3011/) || return 1
  # Confirm authentication is required, then prove the credentials work.
  [ "$code" = 401 ] || return 1
  code=$(printf 'user = "%s:%s"\n' "$SANDBOX_USER" "$SANDBOX_PASSWORD" | \
    curl --disable --config - -ks --noproxy '*' --max-time 3 -o /dev/null -w '%{http_code}' \
      https://127.0.0.1:3011/) || return 1
  [ "$code" = 200 ]
}
