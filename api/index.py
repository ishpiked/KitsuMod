# api/index.py

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from handlers.ban import ban, unban
from handlers.mute import mute, unmute
from handlers.verify import get_verification_handlers
from handlers.channel import delete_channel_post


# ============================================================================
# Configuration
# ============================================================================

BOT_TOKEN = os.getenv("BOT_TOKEN")
GROUP_ID_RAW = os.getenv("GROUP_ID")

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN environment variable is missing.")

if not GROUP_ID_RAW:
    raise RuntimeError("GROUP_ID environment variable is missing.")

try:
    GROUP_ID = int(GROUP_ID_RAW)
except ValueError:
    raise RuntimeError("GROUP_ID must be a valid Telegram chat ID.")


# ============================================================================
# Logging
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("modbot")


# ============================================================================
# Telegram Application
# ============================================================================

telegram_app = (
    Application.builder()
    .token(BOT_TOKEN)
    .concurrent_updates(True)
    .build()
)


# ============================================================================
# Initialization lock
# ============================================================================

_initialization_lock = asyncio.Lock()
_initialized = False


async def ensure_initialized() -> None:
    """
    Initialize python-telegram-bot exactly once per Vercel instance.

    Vercel can reuse an instance for multiple requests, but it can also
    create multiple instances. Each instance safely initializes itself.
    """

    global _initialized

    if _initialized:
        return

    async with _initialization_lock:
        if _initialized:
            return

        logger.info("Initializing Telegram application...")

        await telegram_app.initialize()

        _initialized = True

        logger.info("Telegram application initialized.")


# ============================================================================
# Group restriction
# ============================================================================

async def enforce_allowed_group(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """
    Hard-lock the bot to GROUP_ID.

    If the bot is added to another group/supergroup/channel, it leaves
    immediately.

    This handler also prevents updates from unauthorized groups from
    reaching moderation handlers.
    """

    chat = update.effective_chat

    if not chat:
        return

    # Private chats are simply ignored.
    if chat.type == "private":
        return

    # The configured group is allowed.
    if chat.id == GROUP_ID:
        return

    # Any other group/supergroup gets the bot removed.
    if chat.type in {"group", "supergroup"}:
        try:
            await context.bot.leave_chat(chat.id)

            logger.warning(
                "Left unauthorized group %s (%s).",
                chat.id,
                chat.title,
            )

        except Exception as exc:
            logger.exception(
                "Failed to leave unauthorized group %s: %s",
                chat.id,
                exc,
            )


# ============================================================================
# Bot added / removed handling
# ============================================================================

async def handle_my_chat_member(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """
    Handles changes to the bot's own membership.

    This is the important part for the single-group restriction because
    Telegram sends a ChatMemberUpdated update when the bot is added.
    """

    chat_member_update = update.my_chat_member

    if not chat_member_update:
        return

    chat = chat_member_update.chat
    new_status = chat_member_update.new_chat_member.status

    # Private chats are ignored.
    if chat.type == "private":
        return

    # Allowed group.
    if chat.id == GROUP_ID:
        logger.info(
            "Bot membership changed in allowed group %s: %s",
            chat.id,
            new_status,
        )
        return

    # Unauthorized group/supergroup.
    if chat.type in {"group", "supergroup"}:
        try:
            await context.bot.leave_chat(chat.id)

            logger.warning(
                "Bot was added to unauthorized group %s (%s). Left it.",
                chat.id,
                chat.title,
            )

        except Exception as exc:
            logger.exception(
                "Failed to leave unauthorized group %s: %s",
                chat.id,
                exc,
            )


# ============================================================================
# Allowed-group filter
# ============================================================================

async def allowed_group_only(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """
    Fallback guard for every normal update.

    This prevents a handler from accidentally processing an update from
    another group.
    """

    chat = update.effective_chat

    if not chat:
        return

    if chat.type == "private":
        return

    if chat.id != GROUP_ID:
        if chat.type in {"group", "supergroup"}:
            try:
                await context.bot.leave_chat(chat.id)
            except Exception:
                logger.exception(
                    "Failed to leave unauthorized group %s.",
                    chat.id,
                )


# ============================================================================
# Register handlers
# ============================================================================

# ---------------------------------------------------------------------------
# Membership protection
# ---------------------------------------------------------------------------

telegram_app.add_handler(
    # my_chat_member updates are specifically for the bot's own membership.
    __import__("telegram.ext", fromlist=["ChatMemberHandler"])
    .ChatMemberHandler(
        handle_my_chat_member,
        chat_member_types=__import__(
            "telegram.ext",
            fromlist=["ChatMemberHandler"],
        ).ChatMemberHandler.MY_CHAT_MEMBER,
    ),
    group=-100,
)


# ---------------------------------------------------------------------------
# Moderation
# ---------------------------------------------------------------------------

telegram_app.add_handler(
    CommandHandler(
        "ban",
        ban,
    ),
    group=0,
)

telegram_app.add_handler(
    CommandHandler(
        "unban",
        unban,
    ),
    group=0,
)

telegram_app.add_handler(
    CommandHandler(
        "mute",
        mute,
    ),
    group=0,
)

telegram_app.add_handler(
    CommandHandler(
        "unmute",
        unmute,
    ),
    group=0,
)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

for handler in get_verification_handlers():
    telegram_app.add_handler(
        handler,
        group=0,
    )


# ---------------------------------------------------------------------------
# Channel-post deletion
# ---------------------------------------------------------------------------

telegram_app.add_handler(
    MessageHandler(
        filters.ALL,
        delete_channel_post,
    ),
    group=10,
)


# ============================================================================
# FastAPI lifespan
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifecycle.

    Vercel may not keep a serverless instance alive for long, so this does
    not depend on startup state remaining permanently available.
    """

    await ensure_initialized()

    yield

    # Do not aggressively shut down the Telegram application here.
    #
    # Vercel can terminate/recycle the runtime itself. Explicit shutdown
    # during every request lifecycle would create unnecessary connection
    # churn.


# ============================================================================
# FastAPI application
# ============================================================================

app = FastAPI(
    title="Telegram Moderation Bot",
    version="1.0.0",
    lifespan=lifespan,
)


# ============================================================================
# Health endpoint
# ============================================================================

@app.get("/")
async def root():
    return {
        "status": "ok",
        "service": "telegram-moderation-bot",
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "telegram": _initialized,
        "group": GROUP_ID,
    }


# ============================================================================
# Telegram webhook
# ============================================================================

@app.post("/webhook")
async def telegram_webhook(request: Request):
    """
    Receive Telegram webhook updates.

    Telegram POSTs every update here.
    """

    try:
        data = await request.json()

    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "error": "Invalid JSON.",
            },
        )

    await ensure_initialized()

    try:
        update = Update.de_json(
            data,
            telegram_app.bot,
        )

    except Exception as exc:
        logger.exception(
            "Failed to parse Telegram update: %s",
            exc,
        )

        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "error": "Invalid Telegram update.",
            },
        )

    # ------------------------------------------------------------------------
    # Fast rejection of unauthorized group updates.
    #
    # The my_chat_member handler must still receive membership updates so
    # that unauthorized groups can be left.
    # ------------------------------------------------------------------------

    chat = update.effective_chat

    if (
        chat
        and chat.type in {"group", "supergroup"}
        and chat.id != GROUP_ID
        and not update.my_chat_member
    ):
        try:
            await context_leave_unauthorized(
                update,
                telegram_app,
            )
        except Exception:
            logger.exception(
                "Failed processing unauthorized group update."
            )

        return JSONResponse(
            status_code=200,
            content={
                "ok": True,
                "ignored": True,
            },
        )

    # ------------------------------------------------------------------------
    # Process update.
    #
    # Telegram only needs a successful HTTP response. PTB handles the actual
    # handler dispatch here.
    # ------------------------------------------------------------------------

    try:
        await telegram_app.process_update(update)

    except Exception as exc:
        logger.exception(
            "Unhandled error while processing Telegram update: %s",
            exc,
        )

        # Still return 200 so Telegram doesn't endlessly retry an update
        # that has already reached our application.
        return JSONResponse(
            status_code=200,
            content={
                "ok": True,
            },
        )

    return JSONResponse(
        status_code=200,
        content={
            "ok": True,
        },
    )


# ============================================================================
# Unauthorized group helper
# ============================================================================

async def context_leave_unauthorized(
    update: Update,
    telegram_application: Application,
) -> None:
    """
    Leave an unauthorized group.

    Kept outside the handler system so the webhook can reject unauthorized
    updates before dispatching them to the moderation handlers.
    """

    chat = update.effective_chat

    if not chat:
        return

    if chat.type not in {"group", "supergroup"}:
        return

    if chat.id == GROUP_ID:
        return

    await telegram_application.bot.leave_chat(
        chat_id=chat.id,
    )

    logger.warning(
        "Left unauthorized group %s (%s).",
        chat.id,
        chat.title,
    )
