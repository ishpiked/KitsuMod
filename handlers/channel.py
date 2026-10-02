# handlers/channel.py

from __future__ import annotations

import logging

from telegram import Update
from telegram.error import BadRequest, Forbidden, TelegramError
from telegram.ext import ContextTypes

logger = logging.getLogger(__name__)


async def delete_channel_post(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """
    Automatically delete messages posted by a connected channel.

    Telegram exposes the originating channel through
    message.sender_chat.

    Only messages where sender_chat.type == "channel" are removed.
    Normal users and administrators are untouched.
    """

    message = update.effective_message
    chat = update.effective_chat

    if not message or not chat:
        return

    # Only operate inside groups/supergroups.
    if chat.type not in {"group", "supergroup"}:
        return

    sender_chat = message.sender_chat

    # Not a channel-originated message.
    if not sender_chat:
        return

    # Ignore anonymous admins / other sender chats.
    if sender_chat.type != "channel":
        return

    try:
        await context.bot.delete_message(
            chat_id=chat.id,
            message_id=message.message_id,
        )

        logger.info(
            "Deleted channel post %s from channel %s in group %s",
            message.message_id,
            sender_chat.id,
            chat.id,
        )

    except BadRequest as exc:
        logger.warning(
            "Could not delete channel post %s in %s: %s",
            message.message_id,
            chat.id,
            exc,
        )

    except Forbidden:
        logger.error(
            "Bot does not have permission to delete messages in %s",
            chat.id,
        )

    except TelegramError as exc:
        logger.exception(
            "Unexpected Telegram error deleting channel post: %s",
            exc,
        )
