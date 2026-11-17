import os
import logging
import tempfile
from pathlib import Path

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters,
)
from analyzer import analyze_apk, format_report

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_IDS = {
    int(x.strip()) for x in os.getenv("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
}
MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "50"))
MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("sj-hacker-apk-scanner")


def authorized(user_id: int) -> bool:
    # Fail closed: configure at least one Telegram numeric user ID.
    return bool(ADMIN_IDS) and user_id in ADMIN_IDS


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update.effective_user.id):
        await update.message.reply_text(
            "Access restricted. Ask the bot owner to add your Telegram user ID."
        )
        return
    await update.message.reply_text(
        "🛡️ SJ Hacker | APK Metadata + Permissions Scanner\n\n"
        "Send me an APK file to inspect its package metadata and declared "
        "Android permissions.\n\n"
        f"Maximum file size: {MAX_FILE_MB} MB\n"
        "Commands: /start, /help, /id\n\n"
        "Safety: the APK is parsed as data only. It is never installed, "
        "executed, modified, or unpinned."
    )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not authorized(update.effective_user.id):
        await update.message.reply_text("Access restricted.")
        return
    await update.message.reply_text(
        "How to use:\n"
        "1. Send an .apk document.\n"
        "2. Wait for analysis.\n"
        "3. Receive package name, version, SDK details, permissions and SHA-256.\n\n"
        "Only inspect APKs you own or are authorized to review."
    )


async def id_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"Your Telegram numeric user ID: {update.effective_user.id}"
    )


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    message = update.effective_message
    if not authorized(user.id):
        await message.reply_text("Access restricted. Use /id and ask the owner to authorize you.")
        return

    doc = message.document
    if not doc:
        return
    filename = (doc.file_name or "uploaded.apk").strip()
    if Path(filename).suffix.lower() != ".apk":
        await message.reply_text("Please send a single .apk file as a document.")
        return
    if doc.file_size is not None and doc.file_size > MAX_FILE_BYTES:
        await message.reply_text(f"File too large. Maximum allowed: {MAX_FILE_MB} MB.")
        return

    status = await message.reply_text("⏳ APK received. Checking metadata and permissions…")
    temp_path = None
    try:
        tg_file = await context.bot.get_file(doc.file_id)
        with tempfile.NamedTemporaryFile(prefix="sj_apk_", suffix=".apk", delete=False) as tmp:
            temp_path = Path(tmp.name)
        await tg_file.download_to_drive(custom_path=temp_path)

        if temp_path.stat().st_size > MAX_FILE_BYTES:
            await status.edit_text(f"File too large. Maximum allowed: {MAX_FILE_MB} MB.")
            return

        report = analyze_apk(temp_path)
        text = format_report(report)
        # Telegram message limit is 4096 characters.
        if len(text) <= 3900:
            await status.edit_text(text)
        else:
            report_file = temp_path.with_suffix(".txt")
            report_file.write_text(text, encoding="utf-8")
            await status.edit_text("✅ Analysis complete. Full report attached.")
            with report_file.open("rb") as f:
                await message.reply_document(document=f, filename="SJ_APK_Report.txt")
            report_file.unlink(missing_ok=True)
    except Exception as exc:
        log.exception("APK analysis failed")
        await status.edit_text(
            "❌ Could not analyze this APK. It may be malformed, encrypted, "
            "or unsupported. No app code was executed."
        )
    finally:
        if temp_path:
            temp_path.unlink(missing_ok=True)


def main():
    if not BOT_TOKEN:
        raise RuntimeError("BOT_TOKEN environment variable is missing.")
    if not ADMIN_IDS:
        raise RuntimeError("ADMIN_IDS is required. Set your Telegram numeric user ID.")
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("id", id_cmd))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    log.info("SJ Hacker APK Scanner is starting.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
