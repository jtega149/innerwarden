#!/usr/bin/env bash
set -euo pipefail

trap 'printf "\nCanceled by user.\n"; exit 130' INT TERM

if ! command -v gum >/dev/null 2>&1; then
  echo "gum is not installed. Run: brew install gum"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN_DIR="$ROOT_DIR/docs/internal/setup"
mkdir -p "$PLAN_DIR"

TS="$(date +%Y%m%d-%H%M%S)"
PLAN_FILE="$PLAN_DIR/plan-$TS.md"

detect_theme() {
  local mode="${IW_WIZARD_THEME:-auto}"
  local bg=""

  if [[ "$mode" == "auto" && -n "${COLORFGBG:-}" ]]; then
    bg="${COLORFGBG##*;}"
    if [[ "$bg" =~ ^[0-9]+$ ]]; then
      if (( bg >= 7 )); then
        mode="light"
      else
        mode="dark"
      fi
    fi
  fi

  if [[ "$mode" != "light" && "$mode" != "dark" ]]; then
    mode="dark"
  fi

  echo "$mode"
}

THEME="$(detect_theme)"
USE_COLOR=1
if [[ -n "${NO_COLOR:-}" ]]; then
  USE_COLOR=0
fi

if [[ "$THEME" == "light" ]]; then
  FG_MAIN=16
  FG_MUTED=238
  FG_ACCENT=20
  FG_OK=22
  FG_WARN=124
  FG_BORDER=20
else
  FG_MAIN=255
  FG_MUTED=250
  FG_ACCENT=81
  FG_OK=84
  FG_WARN=214
  FG_BORDER=81
fi

style_line() {
  local text="$1"
  local color="${2:-}"
  local extra="${3:-}"

  if (( USE_COLOR == 1 )) && [[ -n "$color" ]]; then
    if [[ -n "$extra" ]]; then
      gum style --foreground "$color" "$extra" "$text"
    else
      gum style --foreground "$color" "$text"
    fi
  else
    if [[ -n "$extra" ]]; then
      gum style "$extra" "$text"
    else
      gum style "$text"
    fi
  fi
}

render_header() {
  clear

  if (( USE_COLOR == 1 )); then
    gum style --border rounded --margin "1 2" --padding "1 2" \
      --border-foreground "$FG_BORDER" --foreground "$FG_MAIN" --bold \
$'INNERWARDEN SETUP WIZARD\nInteractive setup planner (no project deps).'
  else
    gum style --border rounded --margin "1 2" --padding "1 2" --bold \
$'INNERWARDEN SETUP WIZARD\nInteractive setup planner (no project deps).'
  fi
}

selection_has() {
  local option="$1"
  printf '%s\n' "${PROTECTIONS}" | grep -Fxq "${option}"
}

prompt_required_input() {
  local header="$1"
  local placeholder="$2"
  local value=""
  local trimmed=""

  while true; do
    if ! value="$(gum input --header "${header}" --placeholder "${placeholder}")"; then
      printf "\nCanceled by user.\n"
      exit 130
    fi

    trimmed="$(printf '%s' "${value}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"

    if [[ "${trimmed}" == "back" ]]; then
      printf '%s' "__BACK__"
      return 0
    fi

    if [[ -n "${trimmed}" ]]; then
      printf '%s' "${trimmed}"
      return 0
    fi

    style_line "This field is required. Type a value or 'back' to return." "$FG_WARN"
  done

}

EXPERIENCE="Simple"
PROTECTIONS=""
SEVERITY="High + Critical (system default)"
APPLY_MODE=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
SLACK_WEBHOOK_URL=""
WEBHOOK_URL=""
TELEGRAM_SELECTED="false"
SLACK_SELECTED="false"
WEBHOOK_SELECTED="false"
WIZARD_STEP=1

while true; do
  while (( WIZARD_STEP <= 2 )); do
    case "$WIZARD_STEP" in
      1)
        PROTECTIONS_ERROR=""
        while true; do
          render_header
          style_line "[1/2] Interaction Channels" "$FG_MUTED"
          style_line "Progress: step 1 of 2" "$FG_MUTED"
          style_line "Use space to toggle [x]. Enter opens confirmation." "$FG_MUTED"
          style_line "Block-IP stays enabled by default." "$FG_MUTED"
          style_line "Choose how you want to interact with InnerWarden:" "$FG_MUTED"
          style_line "  - Telegram alerts: real-time alerts on your phone." "$FG_MUTED"
          style_line "  - Slack alerts: notifications in your team channel." "$FG_MUTED"
          style_line "  - Webhook alerts: integrations (PagerDuty/Opsgenie/custom)." "$FG_MUTED"
          echo ""
          if [[ -n "$PROTECTIONS_ERROR" ]]; then
            style_line "$PROTECTIONS_ERROR" "$FG_WARN"
          fi

          PROTECTIONS_SELECTED_CSV=""
          if [[ -n "${PROTECTIONS//[$'\n\r\t ']/}" ]]; then
            PROTECTIONS_SELECTED_CSV="$(printf '%s\n' "$PROTECTIONS" | sed '/^[[:space:]]*$/d' | paste -sd, -)"
          fi

          CHOOSE_ARGS=(
            --no-limit
            --show-help
            --selected-prefix "[x] "
            --unselected-prefix "[ ] "
            --header "Select interaction channels (you can skip)"
          )
          PROTECTION_OPTIONS=(
            "Telegram alerts"
            "Slack alerts"
            "Webhook alerts"
          )
          if [[ -n "$PROTECTIONS_SELECTED_CSV" ]]; then
            CHOOSE_ARGS+=(--selected="$PROTECTIONS_SELECTED_CSV")
          fi

          PROTECTIONS="$(gum choose "${CHOOSE_ARGS[@]}" "${PROTECTION_OPTIONS[@]}")"

          if [[ -z "${PROTECTIONS//[$'\n\r\t ']/}" ]]; then
            PROTECTIONS_LIST="  - none (defaults only)"
          else
            PROTECTIONS_LIST="$(printf '%s\n' "$PROTECTIONS" | sed '/^[[:space:]]*$/d' | sed 's/^/  - /')"
          fi

          render_header
          style_line "[1/2] Interaction Channels" "$FG_MUTED"
          style_line "Progress: step 1 of 2" "$FG_MUTED"
          style_line "Selected channels:" "$FG_ACCENT"
          printf "%s\n" "$PROTECTIONS_LIST"
          echo ""

          STEP1_ACTION="$(gum choose "Continue" "Edit selections" --header "Confirm channel selections")"
          if [[ "$STEP1_ACTION" == "Continue" ]]; then
            if selection_has "Telegram alerts"; then
              TELEGRAM_SELECTED="true"
              render_header
              style_line "[1/2] Channels" "$FG_MUTED"
              style_line "Telegram selected - configure credentials now." "$FG_MUTED"
              TELEGRAM_BOT_TOKEN="$(prompt_required_input \
                "Telegram bot token (from @BotFather)" \
                "123456789:ABC..." \
                "${TELEGRAM_BOT_TOKEN}")"
              if [[ "${TELEGRAM_BOT_TOKEN}" == "__BACK__" ]]; then
                PROTECTIONS_ERROR="Telegram setup canceled. Review selections and continue."
                continue
              fi

              while true; do
                TELEGRAM_CHAT_ID="$(prompt_required_input \
                  "Telegram chat ID (user: 123..., group: -100...)" \
                  "-1001234567890" \
                  "${TELEGRAM_CHAT_ID}")"
                if [[ "${TELEGRAM_CHAT_ID}" == "__BACK__" ]]; then
                  PROTECTIONS_ERROR="Telegram setup canceled. Review selections and continue."
                  continue 2
                fi
                if [[ "${TELEGRAM_CHAT_ID#-}" =~ ^[0-9]+$ ]]; then
                  break
                fi
                style_line "Telegram chat ID must be numeric (optionally starting with '-')." "$FG_WARN"
                TELEGRAM_CHAT_ID=""
              done
            else
              TELEGRAM_SELECTED="false"
              TELEGRAM_BOT_TOKEN=""
              TELEGRAM_CHAT_ID=""
            fi

            if selection_has "Slack alerts"; then
              SLACK_SELECTED="true"
              render_header
              style_line "[1/2] Channels" "$FG_MUTED"
              style_line "Slack selected - configure webhook now." "$FG_MUTED"
              while true; do
                SLACK_WEBHOOK_URL="$(prompt_required_input \
                  "Slack Incoming Webhook URL" \
                  "Cole aqui a URL completa do Slack" \
                  "${SLACK_WEBHOOK_URL}")"
                if [[ "${SLACK_WEBHOOK_URL}" == "__BACK__" ]]; then
                  PROTECTIONS_ERROR="Slack setup canceled. Review selections and continue."
                  continue 2
                fi
                if [[ "${SLACK_WEBHOOK_URL}" =~ ^https://hooks\.slack\.com/services/ ]]; then
                  break
                fi
                style_line "Slack webhook must start with https://hooks.slack.com/services/." "$FG_WARN"
                SLACK_WEBHOOK_URL=""
              done
            else
              SLACK_SELECTED="false"
              SLACK_WEBHOOK_URL=""
            fi

            if selection_has "Webhook alerts"; then
              WEBHOOK_SELECTED="true"
              render_header
              style_line "[1/2] Channels" "$FG_MUTED"
              style_line "Webhook selected - configure endpoint now." "$FG_MUTED"
              while true; do
                WEBHOOK_URL="$(prompt_required_input \
                  "Webhook URL (required)" \
                  "Cole aqui a URL completa do webhook" \
                  "${WEBHOOK_URL}")"
                if [[ "${WEBHOOK_URL}" == "__BACK__" ]]; then
                  PROTECTIONS_ERROR="Webhook setup canceled. Review selections and continue."
                  continue 2
                fi
                if [[ "${WEBHOOK_URL}" =~ ^https?:// ]]; then
                  break
                fi
                style_line "Webhook URL must start with http:// or https://." "$FG_WARN"
                WEBHOOK_URL=""
              done
            else
              WEBHOOK_SELECTED="false"
              WEBHOOK_URL=""
            fi

            WIZARD_STEP=2
            break
          fi

          PROTECTIONS_ERROR="Selection not confirmed. Review and confirm to continue."
        done
        ;;
      2)
        render_header
        style_line "[2/2] Apply mode" "$FG_MUTED"
        style_line "Progress: step 2 of 2" "$FG_MUTED"
        style_line "Alert threshold is automatic: High + Critical (system default)." "$FG_MUTED"
        style_line "Choose how to finish this setup session:" "$FG_MUTED"
        style_line "  - Review first (recommended): save plan and review before applying." "$FG_MUTED"
        style_line "  - Apply immediately: run setup right after this wizard." "$FG_MUTED"
        style_line "  - Back: return to channels." "$FG_MUTED"
        echo ""
        APPLY_CHOICE="$(gum choose \
          "Review first (recommended)" \
          "Apply immediately" \
          "Back" \
          --header "How do you want to finish?")"

        if [[ "$APPLY_CHOICE" == "Back" ]]; then
          WIZARD_STEP=1
        else
          APPLY_MODE="$APPLY_CHOICE"
          WIZARD_STEP=3
        fi
        ;;
    esac
  done

  PROTECTIONS_CSV="$(echo "$PROTECTIONS" | tr '\n' ',' | sed 's/,$//')"

  render_header
  style_line "Final review" "$FG_ACCENT" "--bold"
  style_line "Progress: review" "$FG_MUTED"
  style_line "Experience: $EXPERIENCE (default)" "$FG_MAIN"
  style_line "Block-IP: enabled (default)" "$FG_MAIN"
  style_line "Channels: ${PROTECTIONS_CSV:-none}" "$FG_MAIN"
  style_line "Alert threshold: $SEVERITY" "$FG_MAIN"
  if [[ "${TELEGRAM_SELECTED}" == "true" ]]; then
    style_line "Telegram: enabled (credentials collected)" "$FG_MAIN"
  else
    style_line "Telegram: not selected" "$FG_MAIN"
  fi
  if [[ "${SLACK_SELECTED}" == "true" ]]; then
    style_line "Slack: enabled (webhook collected)" "$FG_MAIN"
  else
    style_line "Slack: not selected" "$FG_MAIN"
  fi
  if [[ "${WEBHOOK_SELECTED}" == "true" ]]; then
    style_line "Webhook: enabled (endpoint collected)" "$FG_MAIN"
  else
    style_line "Webhook: not selected" "$FG_MAIN"
  fi
  style_line "Mode: $APPLY_MODE" "$FG_MAIN"
  echo ""

  REVIEW_ACTION="$(gum choose \
    "Save and finish" \
    "Back to apply mode" \
    "Back to channels" \
    --header "Confirm setup plan")"

  case "$REVIEW_ACTION" in
    "Save and finish")
      break
      ;;
    "Back to apply mode")
      WIZARD_STEP=2
      ;;
    "Back to channels")
      WIZARD_STEP=1
      ;;
  esac
done

style_line "\nSaving plan to: $PLAN_FILE" "$FG_MUTED"

if [[ "${TELEGRAM_SELECTED}" == "true" ]]; then
  TELEGRAM_PLAN_LINE="enabled (credentials collected)"
else
  TELEGRAM_PLAN_LINE="not selected"
fi

if [[ "${SLACK_SELECTED}" == "true" ]]; then
  SLACK_PLAN_LINE="enabled (webhook collected)"
else
  SLACK_PLAN_LINE="not selected"
fi

if [[ "${WEBHOOK_SELECTED}" == "true" ]]; then
  WEBHOOK_PLAN_LINE="enabled (endpoint collected)"
else
  WEBHOOK_PLAN_LINE="not selected"
fi

cat > "$PLAN_FILE" <<PLAN
# Setup Session ($TS)

## Choices
- Experience: $EXPERIENCE
- Block-IP: enabled (default)
- Channels: ${PROTECTIONS_CSV:-none}
- Alert threshold: $SEVERITY
- Telegram: ${TELEGRAM_PLAN_LINE}
- Slack: ${SLACK_PLAN_LINE}
- Webhook: ${WEBHOOK_PLAN_LINE}
- Mode: $APPLY_MODE

## Next actions
- Review selected controls.
- Confirm rollback strategy.
- Run setup when approved.

## Suggested command
\`innerwarden setup\`
PLAN

if [[ "$APPLY_MODE" == "Apply immediately" ]]; then
  if command -v innerwarden >/dev/null 2>&1; then
    if gum confirm "Run 'innerwarden setup' now?"; then
      innerwarden setup
    else
      style_line "Setup not applied. Plan saved at $PLAN_FILE" "$FG_WARN"
    fi
  else
    style_line "innerwarden binary not found in PATH." "$FG_WARN"
    style_line "Plan saved at $PLAN_FILE" "$FG_WARN"
  fi
else
  style_line "Done. Review complete." "$FG_OK"
fi
