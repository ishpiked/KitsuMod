# handlers/mute.py

from __future__ import annotations

import logging
from typing import Optional

from telegram import ChatPermissions, Update
from telegram.constants import ChatMemberStatus
from telegram.error import BadRequest, Forbidden, TelegramError
from telegram.ext import ContextTypes

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_bot_id(
    context: ContextTypes.DEFAULT_TYPE,
) -> Optional[int]:
    """Return the bot's Telegram user ID."""

    try:
        return (await context.bot.get_me()).id
    except TelegramError as exc:
        logger.exception("Failed to get bot information: %s", exc)
        return None


async def _is_admin(
    update: Update,
    user_id: int,
) -> bool:
    """Check whether a user is an administrator or group owner."""

    chat = update.effective_chat

    if not chat:
        return False

    try:
        member = await chat.get_member(user_id)

        return member.status in {
            ChatMemberStatus.ADMINISTRATOR,
            ChatMemberStatus.OWNER,
        }

    except TelegramError as exc:
        logger.warning(
            "Failed to check admin status for %s: %s",
            user_id,
            exc,
        )
        return False


async def _get_target_user(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> tuple[Optional[int], Optional[str]]:
    """
    Resolve the moderation target.

    Supported:
        /mute <user_id>
        /unmute <user_id>

    Or:
        Reply to a user's message and use /mute or /unmute.
    """

    message = update.effective_message

    if not message:
        return None, "This command can't be used here."

    # Reply-based targeting.
    if message.reply_to_message:
        replied_user = message.reply_to_message.from_user

        if replied_user:
            return replied_user.id, None

    # User-ID targeting.
    if context.args:
        raw_user_id = context.args[0]

        try:
            return int(raw_user_id), None
        except (TypeError, ValueError):
            return None, "That doesn't look like a valid user ID."

    return (
        None,
        "Reply to the user's message or provide their user ID.",
    )


def _display_name(user) -> str:
    """Return a readable user name."""

    if not user:
        return "this user"

    if user.full_name:
        return user.full_name

    if user.username:
        return f"@{user.username}"

    return str(user.id)


# ---------------------------------------------------------------------------
# MUTE
# ---------------------------------------------------------------------------

async def mute(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """
    Restrict a user from sending messages.

    Usage:
        /mute <user_id>

    Or reply to the user's message:
        /mute
    """

    message = update.effective_message
    chat = update.effective_chat
    moderator = update.effective_user

    if not message or not chat or not moderator:
        return

    # Only operate inside groups.
    if chat.type not in {"group", "supergroup"}:
        return

    # -----------------------------------------------------------------------
    # Check moderator permissions
    # -----------------------------------------------------------------------

    if not await _is_admin(update, moderator.id):
        await message.reply_text(
            "You need to be an administrator to use this command."
        )
        return

    # -----------------------------------------------------------------------
    # Check bot permissions
    # -----------------------------------------------------------------------

    bot_id = await _get_bot_id(context)

    if bot_id is None:
        await message.reply_text(
            "I couldn't verify my own permissions right now."
        )
        return

    try:
        bot_member = await chat.get_member(bot_id)

    except TelegramError as exc:
        logger.exception(
            "Failed to fetch bot membership in %s: %s",
            chat.id,
            exc,
        )

        await message.reply_text(
            "I couldn't verify my permissions in this group."
        )
        return

    if bot_member.status != ChatMemberStatus.ADMINISTRATOR:
        await message.reply_text(
            "I need to be an administrator to mute users."
        )
        return

    if not bot_member.can_restrict_members:
        await message.reply_text(
            "I don't have permission to restrict members."
        )
        return

    # -----------------------------------------------------------------------
    # Resolve target
    # -----------------------------------------------------------------------

    target_id, error = await _get_target_user(update, context)

    if error:
        await message.reply_text(error)
        return

    if target_id is None:
        return

    # -----------------------------------------------------------------------
    # Prevent invalid targets
    # -----------------------------------------------------------------------

    if target_id == moderator.id:
        await message.reply_text(
            "You can't mute yourself."
        )
        return

    if target_id == bot_id:
        await message.reply_text(
            "I can't mute myself."
        )
        return

    # -----------------------------------------------------------------------
    # Fetch target
    # -----------------------------------------------------------------------

    try:
        target = await chat.get_member(target_id)

    except BadRequest:
        await message.reply_text(
            "I couldn't find that user in this group."
        )
        return

    except Forbidden:
        await message.reply_text(
            "I don't have permission to inspect that user."
        )
        return

    except TelegramError as exc:
        logger.exception(
            "Failed to fetch target member %s: %s",
            target_id,
            exc,
        )

        await message.reply_text(
            "Telegram returned an error while checking that user."
        )
        return

    # -----------------------------------------------------------------------
    # Validate membership
    # -----------------------------------------------------------------------

    if target.status in {
        ChatMemberStatus.LEFT,
        ChatMemberStatus.BANNED,
    }:
        await message.reply_text(
            "That user isn't currently a member of this group."
        )
        return

    # -----------------------------------------------------------------------
    # Protect administrators and owner
    # -----------------------------------------------------------------------

    if target.status in {
        ChatMemberStatus.ADMINISTRATOR,
        ChatMemberStatus.OWNER,
    }:
        await message.reply_text(
            "I can't mute an administrator."
        )
        return

    # -----------------------------------------------------------------------
    # Check whether already muted
    # -----------------------------------------------------------------------

    permissions = target.permissions

    if permissions and not permissions.can_send_messages:
        await message.reply_text(
            f"{_display_name(target.user)} is already muted."
        )
        return

    # -----------------------------------------------------------------------
    # Restrict user
    # -----------------------------------------------------------------------

    # Explicitly disable every relevant message permission.
    # This prevents users from bypassing the mute through media,
    # polls, previews, stickers, etc.
    muted_permissions = ChatPermissions(
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
            user_id=target_id,
            permissions=muted_permissions,
            use_independent_chat_permissions=True,
        )

    except BadRequest as exc:
        logger.warning(
            "Telegram rejected mute for %s in %s: %s",
            target_id,
            chat.id,
            exc,
        )

        await message.reply_text(
            "I couldn't mute that user. They may have higher "
            "permissions than me."
        )
        return

    except Forbidden:
        await message.reply_text(
            "I don't have permission to restrict users in this group."
        )
        return

    except TelegramError as exc:
        logger.exception(
            "Unexpected Telegram error while muting %s: %s",
            target_id,
            exc,
        )

        await message.reply_text(
            "Something went wrong while muting that user."
        )
        return

    # -----------------------------------------------------------------------
    # Success
    # -----------------------------------------------------------------------

    await message.reply_text(
        f"Muted {_display_name(target.user)}."
    )


# ---------------------------------------------------------------------------
# UNMUTE
# ---------------------------------------------------------------------------

async def unmute(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """
    Restore a user's normal messaging permissions.

    Usage:
        /unmute <user_id>

    Or reply to the user's message:
        /unmute
    """

    message = update.effective_message
    chat = update.effective_chat
    moderator = update.effective_user

    if not message or not chat or not moderator:
        return

    # Only operate inside groups.
    if chat.type not in {"group", "supergroup"}:
        return

    # -----------------------------------------------------------------------
    # Check moderator permissions
    # -----------------------------------------------------------------------

    if not await _is_admin(update, moderator.id):
        await message.reply_text(
            "You need to be an administrator to use this command."
        )
        return

    # -----------------------------------------------------------------------
    # Check bot permissions
    # -----------------------------------------------------------------------

    bot_id = await _get_bot_id(context)

    if bot_id is None:
        await message.reply_text(
            "I couldn't verify my own permissions right now."
        )
        return

    try:
        bot_member = await chat.get_member(bot_id)

    except TelegramError:
        await message.reply_text(
            "I couldn't verify my permissions in this group."
        )
        return

    if bot_member.status != ChatMemberStatus.ADMINISTRATOR:
        await message.reply_text(
            "I need to be an administrator to unmute users."
        )
        return

    if not bot_member.can_restrict_members:
        await message.reply_text(
            "I don't have permission to restrict members."
        )
        return

    # -----------------------------------------------------------------------
    # Resolve target
    # -----------------------------------------------------------------------

    target_id, error = await _get_target_user(update, context)

    if error:
        await message.reply_text(error)
        return

    if target_id is None:
        return

    if target_id == bot_id:
        await message.reply_text(
            "I can't unmute myself."
        )
        return

    # -----------------------------------------------------------------------
    # Fetch target
    # -----------------------------------------------------------------------

    try:
        target = await chat.get_member(target_id)

    except BadRequest:
        await message.reply_text(
            "I couldn't find that user in this group."
        )
        return

    except Forbidden:
        await message.reply_text(
            "I don't have permission to inspect that user."
        )
        return

    except TelegramError as exc:
        logger.exception(
            "Failed to fetch target member %s: %s",
            target_id,
            exc,
        )

        await message.reply_text(
            "Telegram returned an error while checking that user."
        )
        return

    # -----------------------------------------------------------------------
    # Validate membership
    # -----------------------------------------------------------------------

    if target.status in {
        ChatMemberStatus.LEFT,
        ChatMemberStatus.BANNED,
    }:
        await message.reply_text(
            "That user isn't currently a member of this group."
        )
        return

    # -----------------------------------------------------------------------
    # Administrators don't need unmuting
    # -----------------------------------------------------------------------

    if target.status in {
        ChatMemberStatus.ADMINISTRATOR,
        ChatMemberStatus.OWNER,
    }:
        await message.reply_text(
            "That user is an administrator and isn't affected by this mute."
        )
        return

    # -----------------------------------------------------------------------
    # Check whether actually muted
    # -----------------------------------------------------------------------

    permissions = target.permissions

    if permissions and permissions.can_send_messages:
        await message.reply_text(
            f"{_display_name(target.user)} isn't muted."
        )
        return

    # -----------------------------------------------------------------------
    # Restore normal permissions
    # -----------------------------------------------------------------------

    normal_permissions = ChatPermissions(
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
            user_id=target_id,
            permissions=normal_permissions,
            use_independent_chat_permissions=True,
        )

    except BadRequest as exc:
        logger.warning(
            "Telegram rejected unmute for %s in %s: %s",
            target_id,
            chat.id,
            exc,
        )

        await message.reply_text(
            "I couldn't unmute that user."
        )
        return

    except Forbidden:
        await message.reply_text(
            "I don't have permission to modify user permissions."
        )
        return

    except TelegramError as exc:
        logger.exception(
            "Unexpected Telegram error while unmuting %s: %s",
            target_id,
            exc,
        )

        await message.reply_text(
            "Something went wrong while unmuting that user."
        )
        return

    # -----------------------------------------------------------------------
    # Success
    # -----------------------------------------------------------------------

    await message.reply_text(
        f"Unmuted {_display_name(target.user)}."
    )
