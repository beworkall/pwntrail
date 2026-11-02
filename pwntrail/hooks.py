"""Shell hooks injected into the recorded shell.

The hooks never write to disk themselves. They print invisible OSC markers
(ESC ] 7777 ; ... BEL) around each command; the pty recorder sees them in the
output stream, strips them, and slices the output per command. That keeps the
shell fast: no python process is spawned per command, except for the scope
check, and only when the command line looks like it contains a host.
"""

from __future__ import annotations

# Cheap pre-filter: only call the scope checker when the line contains something
# that looks like an IP or a domain.
PREFILTER = r"[0-9]+\.[0-9]+\.[0-9]+|[A-Za-z0-9_-]+\.[A-Za-z]{2,}"

BASH_RC = r'''
# ---- PwnTrail recorded session (bash) ----
if [ -f "$HOME/.bashrc" ]; then . "$HOME/.bashrc"; fi

# every command must land in history so we can read it back
set -o history
HISTCONTROL=
HISTIGNORE=

__pt_prefix=$'\[\e[1;31m\]●\[\e[0m\] \[\e[2m\]pwntrail:'"$PWNTRAIL_CASE"$'\[\e[0m\] '
__pt_rx='__PREFILTER__'
__pt_armed=0
__pt_running=0
__pt_hnum=
__pt_last_ec=0

__pt_osc() { printf '\033]7777;%s\007' "$1"; }
__pt_b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

# keep any DEBUG trap the user already had (bash-preexec, starship, ...)
__pt_prev_debug=$(trap -p DEBUG)
__pt_prev_debug=${__pt_prev_debug#trap -- \'}
__pt_prev_debug=${__pt_prev_debug%\' DEBUG}
__pt_prev_debug=${__pt_prev_debug//\'\\\'\'/\'}

__pt_debug() {
  local __pt_rc=0
  if [[ $__pt_armed == 1 && -z ${COMP_LINE-} ]]; then
    local h; h=$(HISTTIMEFORMAT= builtin history 1)
    if [[ $h =~ ^\ *([0-9]+)\*?\ +(.*)$ && ${BASH_REMATCH[1]} != "$__pt_hnum" ]]; then
      __pt_armed=0
      __pt_hnum=${BASH_REMATCH[1]}
      local cmd=${BASH_REMATCH[2]}
      if [[ $cmd =~ $__pt_rx ]]; then
        if ! "$PWNTRAIL_PY" -m pwntrail _check -- "$cmd" </dev/tty >/dev/tty 2>&1; then
          __pt_armed=1
          return 1
        fi
      fi
      __pt_running=1
      __pt_osc "S;$(__pt_b64 "$cmd");$(__pt_b64 "$PWD")"
    fi
  fi
  if [[ -n $__pt_prev_debug ]]; then eval "$__pt_prev_debug"; fi
  return $__pt_rc
}

__pt_ec() { __pt_last_ec=$?; }
__pt_precmd() {
  if [[ $__pt_running == 1 ]]; then
    __pt_osc "E;$__pt_last_ec"
    __pt_running=0
  fi
  local h; h=$(HISTTIMEFORMAT= builtin history 1)
  [[ $h =~ ^\ *([0-9]+) ]] && __pt_hnum=${BASH_REMATCH[1]}
  [[ $PS1 == "$__pt_prefix"* ]] || PS1="$__pt_prefix$PS1"
  __pt_armed=1
}

if [[ $(declare -p PROMPT_COMMAND 2>/dev/null) == "declare -a"* ]]; then
  PROMPT_COMMAND=(__pt_ec "${PROMPT_COMMAND[@]}" __pt_precmd)
else
  PROMPT_COMMAND="__pt_ec;${PROMPT_COMMAND:+$PROMPT_COMMAND;}__pt_precmd"
fi
shopt -s extdebug
trap '__pt_debug' DEBUG
printf '\033[1;31m●\033[0m PwnTrail is recording case \033[1m%s\033[0m. Type \033[1mexit\033[0m or run \033[1mpwntrail stop\033[0m to finish.\n' "$PWNTRAIL_CASE"
'''

ZSH_ENV = r'''
# ---- PwnTrail recorded session (zsh env) ----
__pt_zdotdir=$ZDOTDIR
ZDOTDIR=${PWNTRAIL_ORIG_ZDOTDIR:-$HOME}
[[ -f $ZDOTDIR/.zshenv ]] && source "$ZDOTDIR/.zshenv"
ZDOTDIR=$__pt_zdotdir
'''

ZSH_RC = r'''
# ---- PwnTrail recorded session (zsh) ----
ZDOTDIR=${PWNTRAIL_ORIG_ZDOTDIR:-$HOME}
[[ -f $ZDOTDIR/.zshrc ]] && source "$ZDOTDIR/.zshrc"
[[ -z $PWNTRAIL_ORIG_ZDOTDIR ]] && unset ZDOTDIR

typeset -g __pt_prefix="%B%F{red}●%f%b %F{8}pwntrail:${PWNTRAIL_CASE}%f "
typeset -g __pt_rx='__PREFILTER__'
typeset -g __pt_running=0

__pt_osc() { printf '\033]7777;%s\007' "$1" }
__pt_b64() { printf '%s' "$1" | base64 | tr -d '\n' }

__pt_preexec() {
  __pt_running=1
  __pt_osc "S;$(__pt_b64 "$1");$(__pt_b64 "$PWD")"
}
__pt_precmd() {
  local ec=$?
  if [[ $__pt_running == 1 ]]; then
    __pt_osc "E;$ec"
    __pt_running=0
  fi
  [[ $PROMPT == "$__pt_prefix"* ]] || PROMPT="${__pt_prefix}${PROMPT}"
  # stay first in line so we always see the real exit code
  if [[ ${precmd_functions[1]} != __pt_precmd ]]; then
    precmd_functions=(__pt_precmd ${precmd_functions:#__pt_precmd})
  fi
}
autoload -Uz add-zsh-hook
add-zsh-hook preexec __pt_preexec
precmd_functions=(__pt_precmd ${precmd_functions:#__pt_precmd})

# scope guard: runs before the line is accepted, so a "no" really stops it
zle -A accept-line __pt_orig_accept_line 2>/dev/null
__pt_accept_line() {
  if [[ -n $BUFFER && $BUFFER =~ $__pt_rx ]]; then
    zle -I
    if ! "$PWNTRAIL_PY" -m pwntrail _check -- "$BUFFER" </dev/tty >/dev/tty 2>&1; then
      print -s -- "$BUFFER"   # keep it in history so you can fix it with the up arrow
      BUFFER=""
      zle reset-prompt
      return 0
    fi
  fi
  zle __pt_orig_accept_line
}
zle -N accept-line __pt_accept_line

print -P "%B%F{red}●%f%b PwnTrail is recording case %B${PWNTRAIL_CASE}%b. Type %Bexit%b or run %Bpwntrail stop%b to finish."
'''


def bash_rc() -> str:
    return BASH_RC.replace("__PREFILTER__", PREFILTER)


def zsh_rc() -> str:
    return ZSH_RC.replace("__PREFILTER__", PREFILTER)
