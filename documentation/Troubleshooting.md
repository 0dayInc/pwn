# Troubleshooting

## Common Issues

### Burp / ZAP Proxy Problems
- Prefer `PWN::Plugins::BurpSuite`
- 502 errors usually mean upstream proxy not listening or crashed. Check with `ps`, `ss -tlnp`, restart via plugin methods.

### Ruby / Gemset Issues
- Use RVM and the gemset defined in `.ruby-version` / `.ruby-gemset`.
- Re-run `./install.sh ruby-gem` or the vagrant provisioner after Ruby upgrades.

### AI / LLM Authentication
- Grok uses OAuth device flow (public client) — see `xai_grok_oauth_device_flow` skill.
- Store credentials via `PWN::Config` or environment as documented.

### SHIFT+ENTER Not Working in pwn-ai
- Requires tmux `extended-keys on` on **both** inner and outer sides.
- See recent lessons in memory for exact tmux config.

### Git / Permissions
- Run `sudo chown -R $USER:$USER /opt/pwn` if permission issues after install.

## Diagnostics

```bash
pwn
PWN.help
# Inside REPL:
PWN::Config
PWN::Plugins::PWNLogger
```

Check `~/.pwn/` for logs, metrics, learning files.

Report bugs via GitHub issues with full reproduction + `pwn` version.

[[Diagrams]]
