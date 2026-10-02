# handlers/ban.py

from __future__ import annotations

import logging
from typing import Optional

from telegram import Update
from telegram.constants import ChatMemberStatus
from telegram.error import BadRequest, Forbidden, TelegramError
from telegram.ext import ContextTypes

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _get_target_user(
    update: Update,
) -> tuple[Optional[int], Optional[str]]:
    """
    Resolve the moderation target.

    Supported:
    - Replying to a user's message
    - /ban <user_id>

    Returns:
        (user_id, error_message)
    """

    message = update.effective_message

    if not message:
        return None, "This command can't be used here."

    # Preferred method: reply to the target user's message.
    if message.reply_to_message:
        replied_user = message.reply_to_message.from_user

        if replied_user:
            return replied_user.id, None

    # Optional fallback: /ban <user_id>
    if context_args := getattr(update, "_moderation_args", None):
        if context_args:
            raw_user_id = context_args[0]

            try:
                return int(raw_user_id), None
            except (TypeError, ValueError):
                return None, "That doesn't look like a valid user ID."

    return (
        None,
        "Reply to the user's message to use this command.",
    )


async def _is_admin(
    update: Update,
    user_id: int,
) -> bool:
    """Check whether a user is an administrator."""

    chat = update.effective_chat

    if not chat:
        return False

    try:
        member = await chat.get_member(user_id)

        return member.status in {
            ChatMemberStatus.ADMINISTRATOR,
            ChatMemberStatus.OWNER,
        }

    except TelegramError:
        return False


async def _get_bot_id(
    context: ContextTypes.DEFAULT_TYPE,
) -> Optional[int]:
    """Return the bot's own Telegram user ID."""

    try:
        me = await context.bot.get_me()
        return me.id
    except TelegramError:
        return None


def _display_name(user) -> str:
    """Return a safe human-readable user name."""

    if not user:
        return "this user"

    if user.full_name:
        return user.full_name

    if user.username:
        return f"@{user.username}"

    return str(user.id)


# ---------------------------------------------------------------------------
# BAN
# ---------------------------------------------------------------------------

async def ban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Ban a user from the group.

    Usage:
        Reply to message:
            /ban

        Or:
            /ban <user_id>
    """

    message = update.effective_message
    chat = update.effective_chat
    moderator = update.effective_user

    if not message or not chat or not moderator:
        return

    # This handler should only operate in groups.
    if chat.type not in {"group", "supergroup"}:
        return

    # Store arguments temporarily for _get_target_user().
    update._moderation_args = context.args

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
        logger.exception("Failed to fetch bot membership: %s", exc)
        await message.reply_text(
            "I couldn't verify my permissions in this group."
        )
        return

    if bot_member.status != ChatMemberStatus.ADMINISTRATOR:
        await message.reply_text(
            "I need to be an administrator to ban users."
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

    target_id, error = await _get_target_user(update)

    if error:
        await message.reply_text(error)
        return

    if target_id is None:
        return

    # -----------------------------------------------------------------------
    # Prevent obvious invalid targets
    # -----------------------------------------------------------------------

    if target_id == moderator.id:
        await message.reply_text(
            "You can't ban yourself."
        )
        return

    if target_id == bot_id:
        await message.reply_text(
            "I can't ban myself."
        )
        return

    # -----------------------------------------------------------------------
    # Fetch target member
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
    # Don't allow banning administrators
    # -----------------------------------------------------------------------

    if target.status in {
        ChatMemberStatus.ADMINISTRATOR,
        ChatMemberStatus.OWNER,
    }:
        await message.reply_text(
            "I can't ban an administrator."
        )
        return

    # Already banned / left user.
    if target.status == ChatMemberStatus.BANNED:
        await message.reply_text(
            f"{_display_name(target.user)} is already banned."
        )
        return

    if target.status == ChatMemberStatus.LEFT:
        await message.reply_text(
            "That user isn't currently a member of this group."
        )
        return

    # -----------------------------------------------------------------------
    # Perform ban
    # -----------------------------------------------------------------------

    try:
        await context.bot.ban_chat_member(
            chat_id=chat.id,
            user_id=target_id,
        )

    except BadRequest as exc:
        logger.warning(
            "Telegram rejected ban for %s in %s: %s",
            target_id,
            chat.id,
            exc,
        )

        await message.reply_text(
            "I couldn't ban that user. They may have higher permissions "
            "than me or Telegram rejected the request."
        )
        return

    except Forbidden:
        await message.reply_text(
            "I don't have permission to ban users in this group."
        )
        return

    except TelegramError as exc:
        logger.exception(
            "Unexpected Telegram error while banning %s: %s",
            target_id,
            exc,
        )

        await message.reply_text(
            "Something went wrong while banning that user."
        )
        return

    # -----------------------------------------------------------------------
    # Success
    # -----------------------------------------------------------------------

    await message.reply_text(
        f"Banned {_display_name(target.user)}."
    )


# ---------------------------------------------------------------------------
# UNBAN
# ---------------------------------------------------------------------------

async def unban(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """
    Unban a user.

    Usage:
        /unban <user_id>

    Or reply to a user's message:
        /unban
    """

    message = update.effective_message
    chat = update.effective_chat
    moderator = update.effective_user

    if not message or not chat or not moderator:
        return

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
            "I need to be an administrator to unban users."
        )
        return

    if not bot_member.can_restrict_members:
        await message.reply_text(
            "I don't have permission to manage banned users."
        )
        return

    # -----------------------------------------------------------------------
    # Resolve target
    # -----------------------------------------------------------------------

    update._moderation_args = context.args

    target_id, error = await _get_target_user(update)

    if error:
        await message.reply_text(
            "Use `/unban <user_id>` or reply to the user's message.",
            parse_mode="Markdown",
        )
        return

    if target_id is None:
        return

    # -----------------------------------------------------------------------
    # Don't unban the bot itself
    # -----------------------------------------------------------------------

    if target_id == bot_id:
        await message.reply_text(
            "I can't unban myself."
        )
        return

    # -----------------------------------------------------------------------
    # Check current ban status
    # -----------------------------------------------------------------------

    try:
        target = await chat.get_member(target_id)

    except BadRequest:
        # Telegram may not return useful member information for users
        # who have never interacted with the group. We can still attempt
        # the unban using the supplied user ID.
        target = None

    except TelegramError as exc:
        logger.warning(
            "Could not inspect user %s before unban: %s",
            target_id,
            exc,
        )
        target = None

    if target and target.status != ChatMemberStatus.BANNED:
        await message.reply_text(
            f"{_display_name(target.user)} isn't currently banned."
        )
        return

    # -----------------------------------------------------------------------
    # Perform unban
    # -----------------------------------------------------------------------

    try:
        await context.bot.unban_chat_member(
            chat_id=chat.id,
            user_id=target_id,
            only_if_banned=True,
        )

    except BadRequest as exc:
        logger.warning(
            "Telegram rejected unban for %s in %s: %s",
            target_id,
            chat.id,
            exc,
        )

        await message.reply_text(
            "I couldn't unban that user. Check the user ID and my "
            "administrator permissions."
        )
        return

    except Forbidden:
        await message.reply_text(
            "I don't have permission to unban users in this group."
        )
        return

    except TelegramError as exc:
        logger.exception(
            "Unexpected Telegram error while unbanning %s: %s",
            target_id,
            exc,
        )

        await message.reply_text(
            "Something went wrong while unbanning that user."
        )
        return

    # -----------------------------------------------------------------------
    # Success
    # -----------------------------------------------------------------------

    if target and target.user:
        name = _display_name(target.user)
        await message.reply_text(f"Unbanned {name}.")
    else:
        await message.reply_text(
            f"User `{target_id}` has been unbanned.",
            parse_mode="Markdown",
        )
