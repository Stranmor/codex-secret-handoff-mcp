# Codex Secret Handoff MCP

Локальный Rust MCP-сервер для передачи API-ключей в разрешённый локальный
оператор без помещения plaintext в контекст Codex.

## Что защищается

- секрет вводится локально через prompt без отображения символов;
- MCP-аргументы и ответы содержат только непрозрачный `handle` и метаданные;
- plaintext не записывается в state-файл, stdout, stderr, логи, URL или argv;
- секрет хранится в системном Secret Service (`secret-tool`/GNOME Keyring);
- запуск внешней команды возможен только через именованную allowlist-операцию.

Важно: безопасный маршрут не может принять plaintext из сообщения модели. Если
ключ уже попал в prompt или чат, этот MCP не может задним числом сделать его
нераскрытым.

## Установка

```sh
cargo install --path . --locked
```

Для Codex добавьте в `~/.codex/config.toml`:

```toml
[mcp_servers.secret-handoff]
command = "/home/USER/.cargo/bin/codex-secret-handoff-mcp"
default_tools_approval_mode = "approve"
startup_timeout_sec = 30
tool_timeout_sec = 120
```

После изменения конфигурации используйте штатный Codex MCP autoreload или
перезапустите только Codex App Server в рамках его поддерживаемого маршрута.

## Использование

Из Codex вызовите `secret_handoff_capture` с `target`, `label`, сроком жизни и
флагом `single_use`. Сервер попросит ключ в локальном TTY, сохранит его в
keyring и вернёт только handle. Для запуска операции вызовите
`secret_handoff_run` с handle и именем операции. Конфигурация операций хранится
локально в `${XDG_CONFIG_HOME:-~/.config}/codex-secret-handoff/operations.json`:

```json
{
  "operations": {
    "github-publish": {
      "command": "/usr/bin/gh",
      "args": ["api", "user"],
      "secret_env": "GH_TOKEN"
    }
  }
}
```

Команда должна быть абсолютным путём; shell-строки и произвольные аргументы
запрещены. Вывод дочерней команды намеренно отбрасывается, а receipt содержит
только exit-код, длительность и статус.

CLI-маршрут для среды без MCP:

```sh
codex-secret-handoff-mcp capture --target github --label publish --single-use
codex-secret-handoff-mcp status
codex-secret-handoff-mcp delete <handle>
```

## Ограничения

Это локальный security boundary, а не менеджер секретов для публикации в
интернете. Реальная безопасность зависит от доверия к локальной ОС, keyring и
allowlist-команде. Репозиторий не содержит ключей и не публикует их.
