# Repository instructions

- Keep shared behavior independent of the site, device, account, or deployment used to reproduce a problem. Do not hardcode context-specific settings or make a one-off workaround the global default.
- Use reliable runtime information when available. Otherwise, let the user choose or configure the setting at the narrowest relevant scope. Keep values used only to reproduce an issue in test fixtures or example configuration.
- For the generic website login browser, use controls such as Mobile / Desktop. Do not fix a handset identity, login path, or list of resource domains in shared code to make one site work.
