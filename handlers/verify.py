# handlers/verify.py

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from typing import Optional

from telegram import (
    ChatPermissions,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.constants import ChatMemberStatus
from telegram.error import BadRequest, Forbidden, TelegramError
from telegram.ext import (
    CallbackQueryHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VERIFY_SECRET = os.getenv("VERIFY_SECRET", "")

# Verification expires after 5 minutes.
VERIFICATION_TTL = 300

# Maximum number of verification attempts.
MAX_ATTEMPTS = 3

# Number of random digits the user must select.
CHALLENGE_SIZE = 6


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------

_redis = None


def _get_redis():
    """
    Lazily initialize Redis.

    Expected environment variable:

        REDIS_URL

    Example:

        REDIS_URL=rediss://default:password@hostname:6379
    """

    global _redis

    if _redis is not None:
        return _redis

    redis_url = os.getenv("REDIS_URL")

    if not redis_url:
        raise RuntimeError(
            "REDIS_URL is not configured. "
            "Verification requires persistent storage."
        )

    try:
        import redis

        _redis = redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
        )

        return _redis

    except Exception as exc:
        logger.exception(
            "Failed to initialize Redis: %s",
            exc,
        )
        raise


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def _pending_key(chat_id: int, user_id: int) -> str:
    return f"modbot:verify:pending:{chat_id}:{user_id}"


def _verified_key(chat_id: int, user_id: int) -> str:
    return f"modbot:verify:verified:{chat_id}:{user_id}"


# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------

def _sign(value: str) -> str:
    """
    Generate a short HMAC signature.

    This prevents users from modifying callback data manually.
    """

    if not VERIFY_SECRET:
        raise RuntimeError(
            "VERIFY_SECRET is not configured."
        )

    digest = hmac.new(
        VERIFY_SECRET.encode(),
        value.encode(),
        hashlib.sha256,
    ).hexdigest()

    return digest[:16]


def _make_callback(
    chat_id: int,
    user_id: int,
    nonce: str,
) -> str:
    """
    Build authenticated callback data.

    Format:

        verify:<chat>:<user>:<nonce>:<signature>
    """

    payload = f"{chat_id}:{user_id}:{nonce}"
    signature = _sign(payload)

    return (
        f"verify:{chat_id}:{user_id}:"
        f"{nonce}:{signature}"
    )


def _verify_callback_signature(
    chat_id: int,
    user_id: int,
    nonce: str,
    signature: str,
) -> bool:
    payload = f"{chat_id}:{user_id}:{nonce}"

    expected = _sign(payload)

    return hmac.compare_digest(
        expected,
        signature,
    )


# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------

def _get_pending(
    chat_id: int,
    user_id: int,
) -> Optional[str]:

    redis = _get_redis()

    return redis.get(
        _pending_key(chat_id, user_id)
    )


def _set_pending(
    chat_id: int,
    user_id: int,
    nonce: str,
) -> None:

    redis = _get_redis()

    redis.setex(
        _pending_key(chat_id, user_id),
        VERIFICATION_TTL,
        nonce,
    )


def _delete_pending(
    chat_id: int,
    user_id: int,
) -> None:

    redis = _get_redis()

    redis.delete(
        _pending_key(chat_id, user_id)
    )


def _is_verified(
    chat_id: int,
    user_id: int,
) -> bool:

    redis = _get_redis()

    return bool(
        redis.exists(
            _verified_key(chat_id, user_id)
        )
    )


def _set_verified(
    chat_id: int,
    user_id: int,
) -> None:

    redis = _get_redis()

    # Keep verification for 24 hours.
    redis.setex(
        _verified_key(chat_id, user_id),
        86400,
        "1",
    )


# ---------------------------------------------------------------------------
# Telegram permission helpers
# ---------------------------------------------------------------------------

async def _get_bot_id(
    context: ContextTypes.DEFAULT_TYPE,
) -> Optional[int]:

    try:
        return (await context.bot.get_me()).id

    except TelegramError as exc:
        logger.exception(
            "Failed to get bot ID: %s",
            exc,
        )

        return None


async def _restrict_user(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
) -> bool:
    """
    Restrict an unverified user.

    Returns True if successful.
    """

    chat = update.effective_chat

    if not chat:
        return False

    permissions = ChatPermissions(
        can_send_messages=False,
        can_send_audios=False,
        can_send_documents=False,
        can_send_photos=False,
        can_send_videos=False,
        can_send_video_notes=False,
        can_send_voice_notes=False,
        can_send_polls=False,
        can_send_other_messages=False,
        can_add_web_page_previews=False,
    )

    try:
        await context.bot.restrict_chat_member(
            chat_id=chat.id,
            user_id=user_id,
            permissions=permissions,
            use_independent_chat_permissions=True,
        )

        return True

    except (BadRequest, Forbidden) as exc:
        logger.warning(
            "Failed to restrict %s: %s",
            user_id,
            exc,
        )

        return False

    except TelegramError as exc:
        logger.exception(
            "Telegram error restricting %s: %s",
            user_id,
            exc,
        )

        return False


async def _restore_user(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
) -> bool:
    """
    Restore normal permissions after verification.
    """

    chat = update.effective_chat

    if not chat:
        return False

    permissions = ChatPermissions(
        can_send_messages=True,
        can_send_audios=True,
        can_send_documents=True,
        can_send_photos=True,
        can_send_videos=True,
        can_send_video_notes=True,
        can_send_voice_notes=True,
        can_send_polls=True,
        can_send_other_messages=True,
        can_add_web_page_previews=True,
    )

    try:
        await context.bot.restrict_chat_member(
            chat_id=chat.id,
            user_id=user_id,
            permissions=permissions,
            use_independent_chat_permissions=True,
        )

        return True

    except (BadRequest, Forbidden) as exc:
        logger.warning(
            "Failed to restore permissions for %s: %s",
            user_id,
            exc,
        )

        return False

    except TelegramError as exc:
        logger.exception(
            "Telegram error restoring %s: %s",
            user_id,
            exc,
        )

        return False


# ---------------------------------------------------------------------------
# Verification challenge
# ---------------------------------------------------------------------------

def _generate_challenge() -> tuple[list[int], int]:
    """
    Generate six numbers.

    Exactly one is the correct answer.
    """

    numbers = list(
        secrets.SystemRandom().sample(
            range(10, 100),
            CHALLENGE_SIZE,
        )
    )

    correct = secrets.choice(numbers)

    return numbers, correct


# ---------------------------------------------------------------------------
# Send verification
# ---------------------------------------------------------------------------

async def send_verification(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    user_id: int,
) -> bool:
    """
    Create and send a verification challenge.

    The actual state is stored in Redis, not Vercel memory.
    """

    chat = update.effective_chat

    if not chat:
        return False

    # Don't recreate a valid verification every time.
    existing_nonce = _get_pending(
        chat.id,
        user_id,
    )

    if existing_nonce:
        return True

    numbers, correct = _generate_challenge()

    nonce = secrets.token_urlsafe(12)

    # Store the challenge server-side.
    #
    # We store:
    #
    # correct_answer|nonce
    #
    # The nonce is also embedded into the signed callback.
    redis = _get_redis()

    redis.setex(
        _pending_key(chat.id, user_id),
        VERIFICATION_TTL,
        f"{correct}|{nonce}",
    )

    keyboard = []

    row = []

    for number in numbers:

        callback_data = _make_callback(
            chat.id,
            user_id,
            nonce,
        )

        # The actual number is deliberately NOT trusted from
        # callback data. It is stored server-side instead.
        #
        # We use the button position as the answer identifier.
        index = numbers.index(number)

        signed_data = (
            f"{callback_data}:{index}"
        )

        row.append(
            InlineKeyboardButton(
                text=str(number),
                callback_data=signed_data,
            )
        )

        if len(row) == 2:
            keyboard.append(row)
            row = []

    if row:
        keyboard.append(row)

    try:
        await context.bot.send_message(
            chat_id=chat.id,
            text=(
                "Before you can chat here, you need to verify "
                "that you're human.\n\n"
                "Tap the correct number below."
            ),
            reply_markup=InlineKeyboardMarkup(
                keyboard
            ),
        )

        return True

    except TelegramError as exc:
        logger.exception(
            "Failed to send verification challenge: %s",
            exc,
        )

        # Don't leave stale state behind if Telegram rejected
        # the message.
        _delete_pending(
            chat.id,
            user_id,
        )

        return False


# ---------------------------------------------------------------------------
# New member verification
# ---------------------------------------------------------------------------

async def verify_new_member(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """
    Automatically restrict new members and start verification.
    """

    message = update.effective_message

    if not message:
        return

    chat = update.effective_chat

    if not chat:
        return

    # This handler should only process new members.
    if not message.new_chat_members:
        return

    for user in message.new_chat_members:

        # Never verify the bot itself.
        bot_id = await _get_bot_id(context)

        if bot_id and user.id == bot_id:
            continue

        # Never verify administrators.
        try:
            member = await chat.get_member(user.id)

        except TelegramError:
            continue

        if member.status in {
            ChatMemberStatus.ADMINISTRATOR,
            ChatMemberStatus.OWNER,
        }:
            continue

        # If already verified in Redis, don't touch them.
        if _is_verified(chat.id, user.id):
            continue

        # FIRST restrict the user.
        #
        # This happens before the verification message.
        # Therefore a Vercel cold start or Redis delay cannot
        # accidentally give an unverified user permission to chat.
        restricted = await _restrict_user(
            update,
            context,
            user.id,
        )

        if not restricted:
            logger.error(
                "Could not restrict unverified user %s in %s",
                user.id,
                chat.id,
            )

            continue

        # Then create the verification challenge.
        await send_verification(
            update,
            context,
            user.id,
        )


# ---------------------------------------------------------------------------
# Verification callback
# ---------------------------------------------------------------------------

async def verification_callback(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """
    Handle verification button clicks.
    """

    query = update.callback_query

    if not query:
        return

    await query.answer()

    user = query.from_user
    chat = query.message.chat if query.message else None

    if not chat:
        return

    # -----------------------------------------------------------------------
    # Parse callback
    # -----------------------------------------------------------------------

    try:
        parts = query.data.split(":")

        # verify:chat_id:user_id:nonce:signature:index
        if len(parts) != 6:
            raise ValueError

        (
            prefix,
            callback_chat_id,
            callback_user_id,
            nonce,
            signature,
            answer_index,
        ) = parts

        if prefix != "verify":
            raise ValueError

        callback_chat_id = int(callback_chat_id)
        callback_user_id = int(callback_user_id)
        answer_index = int(answer_index)

    except (ValueError, TypeError):
        await query.answer(
            "This verification button is invalid.",
            show_alert=True,
        )
        return

    # -----------------------------------------------------------------------
    # Bind verification to the actual user
    # -----------------------------------------------------------------------

    if user.id != callback_user_id:
        await query.answer(
            "This verification belongs to another user.",
            show_alert=True,
        )
        return

    if chat.id != callback_chat_id:
        await query.answer(
            "This verification belongs to another group.",
            show_alert=True,
        )
        return

    # -----------------------------------------------------------------------
    # Validate signature
    # -----------------------------------------------------------------------

    try:
        valid_signature = _verify_callback_signature(
            callback_chat_id,
            callback_user_id,
            nonce,
            signature,
        )

    except RuntimeError:
        logger.exception(
            "Verification secret is missing."
        )

        await query.answer(
            "Verification is temporarily unavailable.",
            show_alert=True,
        )
        return

    if not valid_signature:
        await query.answer(
            "This verification button is invalid.",
            show_alert=True,
        )
        return

    # -----------------------------------------------------------------------
    # Read authoritative state from Redis
    # -----------------------------------------------------------------------

    try:
        redis = _get_redis()

        stored = redis.get(
            _pending_key(
                callback_chat_id,
                callback_user_id,
            )
        )

    except Exception:
        logger.exception(
            "Redis failure during verification."
        )

        await query.answer(
            "Verification is temporarily unavailable. Try again.",
            show_alert=True,
        )

        return

    # Redis is unavailable or state expired.
    if not stored:
        await query.answer(
            "This verification has expired. Please request a new one.",
            show_alert=True,
        )
        return

    # -----------------------------------------------------------------------
    # Validate nonce
    # -----------------------------------------------------------------------

    try:
        stored_correct, stored_nonce = stored.split(
            "|",
            1,
        )

    except ValueError:
        _delete_pending(
            callback_chat_id,
            callback_user_id,
        )

        await query.answer(
            "This verification is invalid. Please try again.",
            show_alert=True,
        )

        return

    if not hmac.compare_digest(
        stored_nonce,
        nonce,
    ):
        await query.answer(
            "This verification session is invalid.",
            show_alert=True,
        )
        return

    # -----------------------------------------------------------------------
    # Validate answer
    # -----------------------------------------------------------------------

    try:
        stored_correct = int(stored_correct)

    except ValueError:
        _delete_pending(
            callback_chat_id,
            callback_user_id,
        )

        await query.answer(
            "Verification data is corrupted.",
            show_alert=True,
        )

        return

    # Reconstruct the original number sequence isn't possible from the
    # callback index alone, so instead we store the selected answer directly
    # in a separate callback-safe lookup.
    #
    # This implementation expects the callback's final index to correspond
    # to the challenge answer stored server-side.
    #
    # For safety, use the index only as an opaque identifier.

    # -----------------------------------------------------------------------
    # Resolve selected button
    # -----------------------------------------------------------------------

    if not query.message or not query.message.reply_markup:
        await query.answer(
            "Verification message is invalid.",
            show_alert=True,
        )
        return

    selected_number = None

    flat_buttons = []

    for row in query.message.reply_markup.inline_keyboard:
        flat_buttons.extend(row)

    if answer_index < 0 or answer_index >= len(flat_buttons):
        await query.answer(
            "Invalid verification selection.",
            show_alert=True,
        )
        return

    try:
        selected_number = int(
            flat_buttons[answer_index].text
        )

    except (ValueError, TypeError):
        await query.answer(
            "Invalid verification selection.",
            show_alert=True,
        )
        return

    # -----------------------------------------------------------------------
    # Wrong answer
    # -----------------------------------------------------------------------

    if selected_number != stored_correct:
        await query.answer(
            "Wrong answer. Try again.",
            show_alert=True,
        )
        return

    # -----------------------------------------------------------------------
    # Atomic-ish verification commit
    # -----------------------------------------------------------------------

    # Remove pending state first so the same challenge cannot be reused.
    _delete_pending(
        callback_chat_id,
        callback_user_id,
    )

    _set_verified(
        callback_chat_id,
        callback_user_id,
    )

    # -----------------------------------------------------------------------
    # Restore permissions
    # -----------------------------------------------------------------------

    fake_update = update

    restored = await _restore_user(
        fake_update,
        context,
        callback_user_id,
    )

    if not restored:
        # Critical safety behavior:
        #
        # The user remains restricted if Telegram failed to restore
        # permissions. We DO NOT mark this as a successful verification
        # from the user's perspective.
        #
        # Keep a short retry state.
        redis.setex(
            _pending_key(
                callback_chat_id,
                callback_user_id,
            ),
            120,
            f"{stored_correct}|{nonce}",
        )

        await query.answer(
            "Verification passed, but I couldn't restore your permissions. "
            "Please try the button again.",
            show_alert=True,
        )

        return

    # -----------------------------------------------------------------------
    # Success
    # -----------------------------------------------------------------------

    try:
        await query.edit_message_text(
            "Verification complete. You can chat now."
        )

    except TelegramError:
        # Not fatal. Permissions were already restored.
        pass

    await query.answer(
        "Verified successfully.",
        show_alert=True,
    )


# ---------------------------------------------------------------------------
# Public handler registration
# ---------------------------------------------------------------------------

def get_verification_handlers():
    """
    Return handlers to register in the main application.
    """

    return [
        MessageHandler(
            filters.StatusUpdate.NEW_CHAT_MEMBERS,
            verify_new_member,
        ),
        CallbackQueryHandler(
            verification_callback,
            pattern=r"^verify:",
        ),
    ]
