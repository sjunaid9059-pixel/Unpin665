# SJ Hacker — APK Metadata + Permissions Scanner

A private Telegram bot for inspecting APK metadata and the permissions declared in an Android manifest.

## Safety scope
- Parses APK files as data only.
- Does not install, execute, patch, re-sign, or modify APKs.
- Does not bypass SSL pinning, VPN/proxy checks, device identifiers, or screenshot protections.
- A permission declaration is not proof of runtime behavior or malware.

## Deploy on Railway
1. Create a new Railway project and deploy this folder from a GitHub repository.
2. Add these Railway Variables:
   - `BOT_TOKEN`: token from Telegram BotFather
   - `ADMIN_IDS`: your numeric Telegram user ID (get it by starting the bot and using `/id`; if access is restricted, `/id` still works)
   - `MAX_FILE_MB`: optional; default is `50`
3. Railway will use `Procfile` to start the worker.
4. Open the bot in Telegram and send `/start`.
5. Send an APK as a **document**, not as a photo.

## Find your Telegram numeric ID
- Start the bot and send `/id`. This command works even before authorization.
- Copy the numeric ID into Railway's `ADMIN_IDS` variable.
- Separate multiple IDs with commas, e.g. `123456789,987654321`.
- Restart/redeploy the Railway service after changing variables.

## Important
Keep `BOT_TOKEN` private. Never paste it into source code or a public GitHub repository. If a token is exposed, revoke it through BotFather and create a new one.

The bot is configured to fail closed: if `ADMIN_IDS` is empty, APK scanning is disabled.
