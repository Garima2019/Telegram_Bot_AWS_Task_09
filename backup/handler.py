import json
import os
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from io import BytesIO

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

TELEGRAM_API_BASE = "https://api.telegram.org/bot"

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
DDB_TABLE_NAME = os.environ.get("DDB_TABLE_NAME")
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
AWS_ENDPOINT_URL = os.environ.get("AWS_ENDPOINT_URL")  # For LocalStack

# Initialize AWS clients
if AWS_ENDPOINT_URL:
    # LocalStack configuration
    dynamodb = boto3.resource("dynamodb", endpoint_url=AWS_ENDPOINT_URL)
    s3_client = boto3.client("s3", endpoint_url=AWS_ENDPOINT_URL)
else:
    # Production AWS
    dynamodb = boto3.resource("dynamodb")
    s3_client = boto3.client("s3")

table = dynamodb.Table(DDB_TABLE_NAME)


# ========= TELEGRAM HELPERS =========


def telegram_request(method: str, payload: dict):
    """Low level helper to call Telegram Bot API."""
    url = f"{TELEGRAM_API_BASE}{TELEGRAM_BOT_TOKEN}/{method}"

    encoded = {
        k: json.dumps(v) if isinstance(v, (dict, list)) else v
        for k, v in payload.items()
        if v is not None
    }

    data = urllib.parse.urlencode(encoded).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            return json.loads(body.decode("utf-8"))
    except Exception as e:
        print(f"Error in telegram_request: {e}")
        return None


def send_message(chat_id: int, text: str, parse_mode: str = None):
    payload = {
        "chat_id": chat_id,
        "text": text,
    }
    if parse_mode:
        payload["parse_mode"] = parse_mode
    return telegram_request("sendMessage", payload)


def answer_callback_query(callback_query_id: str, text: str | None = None):
    payload = {"callback_query_id": callback_query_id}
    if text:
        payload["text"] = text
    return telegram_request("answerCallbackQuery", payload)


def get_file_info(file_id: str) -> dict | None:
    """Get file information from Telegram."""
    payload = {"file_id": file_id}
    return telegram_request("getFile", payload)


def download_telegram_file(file_path: str) -> bytes | None:
    """Download file from Telegram servers."""
    url = f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}"
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except Exception as e:
        print(f"Error downloading file: {e}")
        return None


# ========= TIME / UTILS =========


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def generate_s3_key(user_id: int, file_type: str, filename: str) -> str:
    """Generate a unique S3 key for file storage."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    safe_filename = filename.replace(" ", "_").replace("/", "_")
    return f"{user_id}/{file_type}/{timestamp}_{safe_filename}"


# ========= S3 HELPERS =========


def upload_file_to_s3(file_data: bytes, s3_key: str, content_type: str = "application/octet-stream") -> bool:
    """Upload file to S3 bucket."""
    try:
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=s3_key,
            Body=file_data,
            ContentType=content_type,
            ServerSideEncryption='AES256'
        )
        print(f"Successfully uploaded file to s3://{S3_BUCKET_NAME}/{s3_key}")
        return True
    except ClientError as e:
        print(f"Error uploading to S3: {e}")
        return False


def get_file_from_s3(s3_key: str) -> bytes | None:
    """Download file from S3."""
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
        return response['Body'].read()
    except ClientError as e:
        print(f"Error downloading from S3: {e}")
        return None


def list_user_files(user_id: int, file_type: str = None, limit: int = 10) -> list:
    """List files for a user from S3."""
    prefix = f"{user_id}/"
    if file_type:
        prefix = f"{user_id}/{file_type}/"
    
    try:
        response = s3_client.list_objects_v2(
            Bucket=S3_BUCKET_NAME,
            Prefix=prefix,
            MaxKeys=limit
        )
        
        files = []
        for obj in response.get('Contents', []):
            files.append({
                'key': obj['Key'],
                'size': obj['Size'],
                'last_modified': obj['LastModified'].isoformat()
            })
        return files
    except ClientError as e:
        print(f"Error listing S3 files: {e}")
        return []


def delete_file_from_s3(s3_key: str) -> bool:
    """Delete file from S3."""
    try:
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
        print(f"Deleted file from S3: {s3_key}")
        return True
    except ClientError as e:
        print(f"Error deleting from S3: {e}")
        return False


# ========= DYNAMODB HELPERS =========


def save_key_value(user_id: int, key: str, value: str):
    item = {
        "user_id": str(user_id),
        "sort_key": f"kv#{key}",
        "value": value,
        "updated_at": now_iso(),
    }
    table.put_item(Item=item)


def get_key_value(user_id: int, key: str):
    resp = table.get_item(
        Key={
            "user_id": str(user_id),
            "sort_key": f"kv#{key}",
        }
    )
    return resp.get("Item")


def list_keys(user_id: int):
    resp = table.query(
        KeyConditionExpression=Key("user_id").eq(str(user_id))
        & Key("sort_key").begins_with("kv#"),
        ScanIndexForward=True,
    )
    items = resp.get("Items", [])
    keys = [item["sort_key"][3:] for item in items]
    return keys


def save_message_record(user_id: int, message_id: int, text: str):
    item = {
        "user_id": str(user_id),
        "sort_key": f"msg#{message_id}",
        "message_id": message_id,
        "text": text,
        "created_at": now_iso(),
    }
    table.put_item(Item=item)


def save_file_metadata(user_id: int, file_id: str, s3_key: str, file_type: str, 
                       filename: str, file_size: int, mime_type: str = None):
    """Save file metadata to DynamoDB."""
    item = {
        "user_id": str(user_id),
        "sort_key": f"file#{file_id}",
        "file_id": file_id,
        "s3_key": s3_key,
        "file_type": file_type,
        "filename": filename,
        "file_size": file_size,
        "mime_type": mime_type,
        "created_at": now_iso(),
    }
    table.put_item(Item=item)


def get_file_metadata(user_id: int, file_id: str):
    """Retrieve file metadata from DynamoDB."""
    resp = table.get_item(
        Key={
            "user_id": str(user_id),
            "sort_key": f"file#{file_id}",
        }
    )
    return resp.get("Item")


def list_file_metadata(user_id: int, limit: int = 20):
    """List file metadata for a user."""
    resp = table.query(
        KeyConditionExpression=Key("user_id").eq(str(user_id))
        & Key("sort_key").begins_with("file#"),
        ScanIndexForward=False,
        Limit=limit
    )
    return resp.get("Items", [])


def get_message_by_id(user_id: int, message_id: int):
    resp = table.get_item(
        Key={
            "user_id": str(user_id),
            "sort_key": f"msg#{message_id}",
        }
    )
    return resp.get("Item")


def get_all_messages(user_id: int):
    resp = table.query(
        KeyConditionExpression=Key("user_id").eq(str(user_id))
        & Key("sort_key").begins_with("msg#"),
        ScanIndexForward=True,
    )
    return resp.get("Items", [])


def get_last_messages(user_id: int, limit: int = 5):
    items = get_all_messages(user_id)
    items_sorted = sorted(items, key=lambda x: x.get("created_at", ""), reverse=True)
    return items_sorted[:limit]


def search_messages(user_id: int, keyword: str, limit: int = 20):
    items = get_all_messages(user_id)
    keyword_lower = keyword.lower()
    matches = [
        item
        for item in items
        if "text" in item and keyword_lower in item["text"].lower()
    ]
    matches_sorted = sorted(matches, key=lambda x: x.get("created_at", ""), reverse=True)
    return matches_sorted[:limit]


def get_last_notes(user_id: int, limit: int = 10):
    items = get_all_messages(user_id)
    notes = [
        item
        for item in items
        if isinstance(item.get("text"), str)
        and not item["text"].strip().startswith("/")
    ]
    notes_sorted = sorted(notes, key=lambda x: x.get("created_at", ""), reverse=True)
    return notes_sorted[:limit]


# ========= AI HELPERS =========


def ask_openai(question: str) -> str:
    if not OPENAI_API_KEY:
        return "OpenAI is not configured. Set OPENAI_API_KEY in Lambda env."

    url = "https://api.openai.com/v1/chat/completions"
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful assistant answering concisely.",
            },
            {"role": "user", "content": question},
        ],
        "max_tokens": 300,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {OPENAI_API_KEY}")

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
        return resp_data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        print("HTTPError from OpenAI:", e.code, err_body)
        if e.code == 429:
            return "I'm hitting the OpenAI rate/usage limit right now.\nPlease try again in a bit."
        else:
            return "OpenAI returned an error. Please try again later."
    except Exception as e:
        print("Error calling OpenAI:", repr(e))
        return "Sorry, I could not get an OpenAI reply right now."


def ask_gemini(prompt: str) -> str:
    if not GEMINI_API_KEY:
        return "Gemini is not configured. Set GEMINI_API_KEY in Lambda env."

    url = (
        "https://generativelanguage.googleapis.com/v1beta/"
        "models/gemini-1.5-flash:generateContent"
        f"?key={GEMINI_API_KEY}"
    )

    body = {"contents": [{"parts": [{"text": prompt}]}]}
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))

        candidates = resp_data.get("candidates") or []
        if not candidates:
            return "Gemini did not return any answer."

        content = candidates[0].get("content") or {}
        parts = content.get("parts") or []
        if not parts:
            return "Gemini returned an empty response."

        text = parts[0].get("text") or ""
        return text.strip() or "Gemini response was empty."
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        print("HTTPError from Gemini:", e.code, err_body)
        if e.code == 429:
            return "Gemini is currently rate-limited or over quota.\nPlease try again later."
        else:
            return "Gemini returned an error. Please try again later."
    except Exception as e:
        print("Error calling Gemini:", repr(e))
        return "Sorry, I could not get a Gemini reply right now."


def ask_ai(question: str) -> str:
    if OPENAI_API_KEY:
        return ask_openai(question)
    if GEMINI_API_KEY:
        return ask_gemini(question)
    return "No AI provider is configured.\nPlease set OPENAI_API_KEY or GEMINI_API_KEY in Lambda."


def summarize_last_notes(user_id: int, limit: int = 10) -> str:
    notes = get_last_notes(user_id, limit=limit)
    if not notes:
        return "I couldn't find any notes to summarise (non-command messages)."

    notes_sorted = sorted(notes, key=lambda x: x.get("created_at", ""))

    parts = []
    for idx, item in enumerate(notes_sorted, start=1):
        ts = item.get("created_at", "")
        txt = item.get("text", "").strip()
        if len(txt) > 400:
            txt = txt[:397] + "..."
        parts.append(f"{idx}. [{ts}] {txt}")

    joined_notes = "\n".join(parts)

    prompt = (
        "You are an assistant helping a user with their personal notes.\n"
        "Below are the user's latest notes (messages that are not commands).\n"
        "Please provide a concise summary in 5–7 bullet points, capturing:\n"
        "- main themes/topics\n"
        "- any tasks or follow-ups implied\n"
        "- overall sentiment if relevant.\n\n"
        "User notes:\n"
        f"{joined_notes}"
    )

    return ask_ai(prompt)


def compute_personal_stats(user_id: int) -> str:
    items = get_all_messages(user_id)
    if not items:
        return "No messages stored yet, so I can't compute stats."

    total_msgs = len(items)

    created_times = []
    for item in items:
        ts = item.get("created_at")
        if not ts:
            continue
        try:
            created_times.append(datetime.fromisoformat(ts))
        except Exception:
            continue

    now = datetime.now(timezone.utc)

    msgs_last_7_days = 0
    notes_count = 0
    total_chars_notes = 0
    command_counts: dict[str, int] = {}

    for item in items:
        text = (item.get("text") or "").strip()
        ts_str = item.get("created_at")
        dt = None
        if ts_str:
            try:
                dt = datetime.fromisoformat(ts_str)
            except Exception:
                dt = None

        if dt is not None:
            delta = now - dt
            if delta.days < 7:
                msgs_last_7_days += 1

        if text.startswith("/"):
            cmd = text.split(maxsplit=1)[0]
            command_counts[cmd] = command_counts.get(cmd, 0) + 1
        else:
            notes_count += 1
            total_chars_notes += len(text)

    avg_note_length = 0
    if notes_count > 0:
        avg_note_length = round(total_chars_notes / notes_count, 1)

    first_ts = min(created_times) if created_times else None
    last_ts = max(created_times) if created_times else None

    most_used_cmd = None
    most_used_cmd_count = 0
    if command_counts:
        most_used_cmd, most_used_cmd_count = max(
            command_counts.items(), key=lambda kv: kv[1]
        )

    # Get file statistics
    file_items = list_file_metadata(user_id, limit=1000)
    total_files = len(file_items)
    total_file_size = sum(item.get("file_size", 0) for item in file_items)
    
    file_type_counts = {}
    for item in file_items:
        ft = item.get("file_type", "unknown")
        file_type_counts[ft] = file_type_counts.get(ft, 0) + 1

    lines = []
    lines.append("📊 Your Personal Stats")
    lines.append("")
    lines.append(f"• Total stored messages: {total_msgs}")
    lines.append(f"• Messages in last 7 days: {msgs_last_7_days}")
    lines.append(f"• Notes (non-command messages): {notes_count}")
    if notes_count > 0:
        lines.append(f"• Avg note length: {avg_note_length} characters")

    if total_files > 0:
        lines.append(f"• Total files uploaded: {total_files}")
        lines.append(f"• Total storage used: {total_file_size / 1024 / 1024:.2f} MB")
        if file_type_counts:
            ft_str = ", ".join(f"{k}: {v}" for k, v in file_type_counts.items())
            lines.append(f"• File types: {ft_str}")

    if first_ts and last_ts:
        lines.append(f"• First stored message: {first_ts.strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"• Latest stored message: {last_ts.strftime('%Y-%m-%d %H:%M UTC')}")

    if most_used_cmd:
        lines.append(f"• Most used command: {most_used_cmd} ({most_used_cmd_count} times)")

    return "\n".join(lines)


# ========= FILE HANDLING =========


def handle_photo(chat_id: int, message: dict):
    """Handle photo uploads from Telegram."""
    photos = message.get("photo", [])
    if not photos:
        send_message(chat_id, "No photo found in message.")
        return

    # Get the largest photo (last in array)
    photo = photos[-1]
    file_id = photo.get("file_id")
    file_size = photo.get("file_size", 0)

    # Get file info from Telegram
    file_info = get_file_info(file_id)
    if not file_info or not file_info.get("ok"):
        send_message(chat_id, "❌ Failed to get photo information.")
        return

    file_path = file_info["result"]["file_path"]
    
    # Download file
    file_data = download_telegram_file(file_path)
    if not file_data:
        send_message(chat_id, "❌ Failed to download photo.")
        return

    # Generate S3 key and upload
    filename = f"photo_{file_id}.jpg"
    s3_key = generate_s3_key(chat_id, "photos", filename)
    
    if upload_file_to_s3(file_data, s3_key, "image/jpeg"):
        # Save metadata to DynamoDB
        save_file_metadata(
            user_id=chat_id,
            file_id=file_id,
            s3_key=s3_key,
            file_type="photo",
            filename=filename,
            file_size=len(file_data),
            mime_type="image/jpeg"
        )
        
        send_message(
            chat_id, 
            f"✅ Photo saved successfully!\n\n"
            f"File ID: {file_id}\n"
            f"Size: {len(file_data) / 1024:.1f} KB\n"
            f"Storage path: {s3_key}"
        )
    else:
        send_message(chat_id, "❌ Failed to save photo to storage.")


def handle_document(chat_id: int, message: dict):
    """Handle document uploads from Telegram."""
    document = message.get("document")
    if not document:
        send_message(chat_id, "No document found in message.")
        return

    file_id = document.get("file_id")
    file_name = document.get("file_name", f"document_{file_id}")
    file_size = document.get("file_size", 0)
    mime_type = document.get("mime_type", "application/octet-stream")

    # Check file size (Telegram max is 20MB for bots)
    if file_size > 20 * 1024 * 1024:
        send_message(chat_id, "❌ File is too large (max 20MB).")
        return

    # Get file info
    file_info = get_file_info(file_id)
    if not file_info or not file_info.get("ok"):
        send_message(chat_id, "❌ Failed to get document information.")
        return

    file_path = file_info["result"]["file_path"]
    
    # Download file
    file_data = download_telegram_file(file_path)
    if not file_data:
        send_message(chat_id, "❌ Failed to download document.")
        return

    # Generate S3 key and upload
    s3_key = generate_s3_key(chat_id, "documents", file_name)
    
    if upload_file_to_s3(file_data, s3_key, mime_type):
        # Save metadata
        save_file_metadata(
            user_id=chat_id,
            file_id=file_id,
            s3_key=s3_key,
            file_type="document",
            filename=file_name,
            file_size=len(file_data),
            mime_type=mime_type
        )
        
        send_message(
            chat_id,
            f"✅ Document saved successfully!\n\n"
            f"File: {file_name}\n"
            f"Size: {len(file_data) / 1024:.1f} KB\n"
            f"Type: {mime_type}\n"
            f"File ID: {file_id}"
        )
    else:
        send_message(chat_id, "❌ Failed to save document to storage.")


def handle_voice(chat_id: int, message: dict):
    """Handle voice message uploads."""
    voice = message.get("voice")
    if not voice:
        send_message(chat_id, "No voice message found.")
        return

    file_id = voice.get("file_id")
    file_size = voice.get("file_size", 0)
    duration = voice.get("duration", 0)

    file_info = get_file_info(file_id)
    if not file_info or not file_info.get("ok"):
        send_message(chat_id, "❌ Failed to get voice message information.")
        return

    file_path = file_info["result"]["file_path"]
    file_data = download_telegram_file(file_path)
    
    if not file_data:
        send_message(chat_id, "❌ Failed to download voice message.")
        return

    filename = f"voice_{file_id}.ogg"
    s3_key = generate_s3_key(chat_id, "voice", filename)
    
    if upload_file_to_s3(file_data, s3_key, "audio/ogg"):
        save_file_metadata(
            user_id=chat_id,
            file_id=file_id,
            s3_key=s3_key,
            file_type="voice",
            filename=filename,
            file_size=len(file_data),
            mime_type="audio/ogg"
        )
        
        send_message(
            chat_id,
            f"✅ Voice message saved!\n\n"
            f"Duration: {duration}s\n"
            f"Size: {len(file_data) / 1024:.1f} KB"
        )
    else:
        send_message(chat_id, "❌ Failed to save voice message.")


# ========= COMMAND HELPERS =========


def help_text() -> str:
    return (
        "Here's what I can do:\n\n"
        "📝 Basic Commands:\n"
        "/hello - greet\n"
        "/help - this message\n"
        "/echo <text> - echo back\n\n"
        "💾 Storage Commands:\n"
        "/save <key> <value> - save your data\n"
        "/get <key> - retrieve your value\n"
        "/list - list saved keys\n\n"
        "📁 File Commands:\n"
        "/myfiles - list your uploaded files\n"
        "/fileinfo <file_id> - get file details\n"
        "Just send me photos, documents, or voice messages to save them!\n\n"
        "🔍 Message Commands:\n"
        "/getid <message_id> - fetch specific message\n"
        "/search <keyword> - search your messages\n"
        "/latest - show your latest note\n"
        "/history - show your last 5 notes\n\n"
        "🤖 AI Commands:\n"
        "/ask <question> - AI answer\n"
        "/summarize - AI summary of your notes\n\n"
        "📊 Analytics:\n"
        "/stats - personal usage statistics\n\n"
        "/menu - show this menu again"
    )


# ========= COMMAND HANDLING =========


# def handle_text_message(chat_id: int, message_id: int, text: str, first_name: str | None):
#     text = text.strip()

#     # /start
#     if text.startswith("/start"):
#         username = first_name or "there"
#         send_message(chat_id, f"Welcome, {username}! 😉")
#         send_message(chat_id, help_text())
#         return

#     # /hello
#     if text.startswith("/hello"):
#         send_message(chat_id, "👋 Hello! How can I help you today?")
#         return

#     # /help or /menu
#     if text.startswith("/help") or text.startswith("/menu"):
#         send_message(chat_id, help_text())
#         return

#     # /echo
#     if text.startswith("/echo"):
#         parts = text.split(maxsplit=1)
#         if len(parts) == 1:
#             send_message(chat_id, "Usage: /echo <text>")
#         else:
#             send_message(chat_id, parts[1])
#         return

#     # /save
#     if text.startswith("/save"):
#         parts = text.split(maxsplit=3)
#         if len(parts) < 3:
#             send_message(chat_id, "Usage: /save <key> <value>")
#             return
#         key = parts[1]
#         value = parts[2] if len(parts) == 3 else " ".join(parts[2:])
#         save_key_value(chat_id, key, value)
#         send_message(chat_id, f"✅ Saved key '{key}'.")
#         return

#     # /get
#     if text.startswith("/get"):
#         parts = text.split(maxsplit=1)
#         if len(parts) < 2:
#             send_message(chat_id, "Usage: /get <key>")
#             return
#         key = parts[1]
#         item = get_key_value(chat_id, key)
#         if not item:
#             send_message(chat_id, f"❌ No value found for key '{key}'.")
#         else:
#             send_message(chat_id, f"🔑 {key} = {item.get('value', '')}")
#         return

#     # /list
#     if text == "/list":
#         keys = list_keys(chat_id)
#         if not keys:
#             send_message(chat_id, "You have not saved any keys yet.")
#         else:
#             lines = "\n".join(f"• {k}" for k in keys)
#             send_message(chat_id, "Your saved keys:\n" + lines)
#         return

#     # /myfiles
#     if text == "/myfiles":
#         files = list_file_metadata(chat_id, limit=20)
#         if not files:
#             send_message(chat_id, "You haven't uploaded any files yet.")
#             return
        
#         lines = ["📁 Your Files:\n"]
#         for item in files:
#             filename = item.get("filename", "unknown")
#             file_type = item.get("file_type", "unknown")
#             size_kb = item.get("file_size", 0) / 1024
#             created = item.get("created_at", "")[:10]
#             file_id = item.get("file_id", "")
#             lines.append(f"• {filename} ({file_type})")
#             lines.append(f"  Size: {size_kb:.1f} KB | {created} | ID: {file_id[:8]}...")
        
#         send_message(chat_id, "\n".join(lines))
#         return

#     # /fileinfo
#     if text.startswith("/fileinfo"):
#         parts = text.split(maxsplit=1)
#         if len(parts) < 2:
#             send_message(chat_id, "Usage: /fileinfo <file_id>")
#             return
        
#         file_id = parts[1]
#         metadata = get_file_metadata(chat_id, file_id)
        
#         if not metadata:
#             send_message(chat_id, f"❌ No file found with ID: {file_id}")
#             return
        
#         info = (
#             f"📄 File Information:\n\n"
#             f"Filename: {metadata.get('filename')}\n"
#             f"Type: {metadata.get('file_type')}\n"
#             f"Size: {metadata.get('file_size', 0) / 1024:.1f} KB\n"
#             f"MIME: {metadata.get('mime_type', 'N/A')}\n"
#             f"S3 Key: {metadata.get('s3_key')}\n"
#             f"Uploaded: {metadata.get('created_at')}"
#         )
#         send_message(chat_id, info)
#         return

#     # /getid
#     if text.startswith("/getid"):
#         parts = text.split(maxsplit=1)
#         if len(parts) < 2:
#             send_message(chat_id, "Usage: /getid <message_id>")
#             return
#         try:
#             msg_id = int(parts[1])
#         except ValueError:
#             send_message(chat_id, "Message id must be a number.")
#             return

#         item = get_message_by_id(chat_id, msg_id)
#         if not item:
#             send_message(chat_id, f"No message stored with id {msg_id}.")
#         else:
#             send_message(
#                 chat_id,
#                 f"🧾 Message {msg_id} (at {item.get('created_at', '')}):\n\n{item.get('text', '')}",
#             )
#         return

#     # /search
#     if text.startswith("/search"):
#         parts = text.split(maxsplit=1)
#         if len(parts) < 2:
#             send_message(chat_id, "Usage: /search <keyword>")
#             return
#         keyword = parts[1]
#         matches = search_messages(chat_id, keyword)
#         if not matches:
#             send_message(chat_id, f"No messages found containing '{keyword}'.")
#             return

#         lines = []
#         for item in matches:
#             msg_id = item.get("message_id")
#             snippet = item.get("text", "")
#             if len(snippet) > 80:
#                 snippet = snippet[:77] + "..."
#             lines.append(f"{msg_id}: {snippet}")
#         send_message(chat_id, "🔍 Search results:\n\n" + "\n".join(lines))
#         return

#     # /latest
#     if text.startswith("/latest"):
#         items = get_last_messages(chat_id, limit=1)
#         if not items:
#             send_message(chat_id, "No messages stored yet.")
#             return
#         item = items[0]
#         send_message(
#             chat_id,
#             f"📝 Latest message (at {item.get('created_at', '')}):\n\n{item.get('text', '')}",
#         )
#         return

#     # /history
#     if text.startswith("/history"):
#         items = get_last_messages(chat_id, limit=5)
#         if not items:
#             send_message(chat_id, "No messages stored yet.")
#             return
#         lines = []
#         for idx, item in enumerate(items, start=1):
#             snippet = item.get("text", "")
#             if len(snippet) > 80:
#                 snippet = snippet[:77] + "..."
#             lines.append(f"{idx}. [{item.get('created_at', '')}]\n{snippet}")
#         send_message(chat_id, "🧾 Your last messages:\n\n" + "\n\n".join(lines))
#         return

#     # /ask
#     if text.startswith("/ask "):
#         question = text[len("/ask ") :].strip()
#         if not question:
#             send_message(chat_id, "Usage: /ask <question>")
#             return
#         reply = ask_ai(question)
#         send_message(chat_id, reply)
#         return

#     if text == "/ask":
#         send_message(chat_id, "Usage: /ask <question>")
#         return

#     # /ask_openai
#     if text.startswith("/ask_openai"):
#         parts = text.split(maxsplit=1)
#         if len(parts) < 2:
#             send_message(chat_id, "Usage: /ask_openai <question>")
#             return
#         question = parts[1]
#         reply = ask_openai(question)
#         send_message(chat_id, reply)
#         return

#     # /ask_gemini
#     if text.startswith("/ask_gemini"):
#         parts = text.split(maxsplit=1)
#         if len(parts) < 2:
#             send_message(chat_id, "Usage: /ask_gemini <question>")
#             return
#         question = parts[1]
#         reply = ask_gemini(question)
#         send_message(chat_id, reply)
#         return

#     # /summarize
#     if text.startswith("/summarize"):
#         reply = summarize_last_notes(chat_id, limit=10)
#         send_message(chat_id, reply)
#         return

#     # /stats
#     if text.startswith("/stats"):
#         stats_text = compute_personal_stats(chat_id)
#         send_message(chat_id, stats_text)
#         return

#     # Fallback
#     send_message(
#         chat_id,
#         "I did not recognise that. Type /help to see all commands.",
#     )

def handle_text_message(chat_id: int, message_id: int, text: str, first_name: str | None):
    text = text.strip()

    # /start
    if text.startswith("/start"):
        username = first_name or "there"
        send_message(chat_id, f"Welcome, {username}! 😉")
        send_message(chat_id, help_text())
        return

    # /hello
    if text.startswith("/hello"):
        send_message(chat_id, "👋 Hello! How can I help you today?")
        return

    # /help or /menu
    if text.startswith("/help") or text.startswith("/menu"):
        send_message(chat_id, help_text())
        return

    # /echo
    if text.startswith("/echo"):
        parts = text.split(maxsplit=1)
        if len(parts) == 1:
            send_message(chat_id, "Usage: /echo <text>")
        else:
            send_message(chat_id, parts[1])
        return

    # /save
    if text.startswith("/save"):
        parts = text.split(maxsplit=3)
        if len(parts) < 3:
            send_message(chat_id, "Usage: /save <key> <value>")
            return
        key = parts[1]
        value = parts[2] if len(parts) == 3 else " ".join(parts[2:])
        save_key_value(chat_id, key, value)
        send_message(chat_id, f"✅ Saved key '{key}'.")
        return

    # /get
    if text.startswith("/get"):
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            send_message(chat_id, "Usage: /get <key>")
            return
        key = parts[1]
        item = get_key_value(chat_id, key)
        if not item:
            send_message(chat_id, f"❌ No value found for key '{key}'.")
        else:
            send_message(chat_id, f"🔑 {key} = {item.get('value', '')}")
        return

    # /list
    if text == "/list":
        keys = list_keys(chat_id)
        if not keys:
            send_message(chat_id, "You have not saved any keys yet.")
        else:
            lines = "\n".join(f"• {k}" for k in keys)
            send_message(chat_id, "Your saved keys:\n" + lines)
        return

    # /myfiles
    if text == "/myfiles":
        files = list_file_metadata(chat_id, limit=20)
        if not files:
            send_message(chat_id, "You haven't uploaded any files yet.")
            return
        
        lines = ["📁 Your Files:\n"]
        for item in files:
            filename = item.get("filename", "unknown")
            file_type = item.get("file_type", "unknown")
            size_kb = item.get("file_size", 0) / 1024
            created = item.get("created_at", "")[:10]
            file_id = item.get("file_id", "")
            lines.append(f"• {filename} ({file_type})")
            lines.append(f"  Size: {size_kb:.1f} KB | {created} | ID: {file_id[:8]}...")
        
        send_message(chat_id, "\n".join(lines))
        return

    # /fileinfo
    if text.startswith("/fileinfo"):
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            send_message(chat_id, "Usage: /fileinfo <file_id>")
            return
        
        file_id = parts[1]
        metadata = get_file_metadata(chat_id, file_id)
        
        if not metadata:
            send_message(chat_id, f"❌ No file found with ID: {file_id}")
            return
        
        info = (
            f"📄 File Information:\n\n"
            f"Filename: {metadata.get('filename')}\n"
            f"Type: {metadata.get('file_type')}\n"
            f"Size: {metadata.get('file_size', 0) / 1024:.1f} KB\n"
            f"MIME: {metadata.get('mime_type', 'N/A')}\n"
            f"S3 Key: {metadata.get('s3_key')}\n"
            f"Uploaded: {metadata.get('created_at')}"
        )
        send_message(chat_id, info)
        return

    # /getid
    if text.startswith("/getid"):
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            send_message(chat_id, "Usage: /getid <message_id>")
            return
        try:
            msg_id = int(parts[1])
        except ValueError:
            send_message(chat_id, "Message id must be a number.")
            return

        item = get_message_by_id(chat_id, msg_id)
        if not item:
            send_message(chat_id, f"No message stored with id {msg_id}.")
        else:
            send_message(
                chat_id,
                f"🧾 Message {msg_id} (at {item.get('created_at', '')}):\n\n{item.get('text', '')}",
            )
        return

    # /search
    if text.startswith("/search"):
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            send_message(chat_id, "Usage: /search <keyword>")
            return
        keyword = parts[1]
        matches = search_messages(chat_id, keyword)
        if not matches:
            send_message(chat_id, f"No messages found containing '{keyword}'.")
            return

        lines = []
        for item in matches:
            msg_id = item.get("message_id")
            snippet = item.get("text", "")
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            lines.append(f"{msg_id}: {snippet}")
        send_message(chat_id, "🔍 Search results:\n\n" + "\n".join(lines))
        return

    # /latest
    if text.startswith("/latest"):
        items = get_last_messages(chat_id, limit=1)
        if not items:
            send_message(chat_id, "No messages stored yet.")
            return
        item = items[0]
        send_message(
            chat_id,
            f"📝 Latest message (at {item.get('created_at', '')}):\n\n{item.get('text', '')}",
        )
        return

    # /history - MOVED BEFORE THE FALLBACK
    if text.startswith("/history"):
        items = get_last_messages(chat_id, limit=5)
        if not items:
            send_message(chat_id, "No messages stored yet.")
            return
        lines = []
        for idx, item in enumerate(items, start=1):
            snippet = item.get("text", "")
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            lines.append(f"{idx}. [{item.get('created_at', '')}]\n{snippet}")
        send_message(chat_id, "🧾 Your last messages:\n\n" + "\n\n".join(lines))
        return

    # /ask
    if text.startswith("/ask "):
        question = text[len("/ask ") :].strip()
        if not question:
            send_message(chat_id, "Usage: /ask <question>")
            return
        reply = ask_ai(question)
        send_message(chat_id, reply)
        return

    if text == "/ask":
        send_message(chat_id, "Usage: /ask <question>")
        return

    # /ask_openai
    if text.startswith("/ask_openai"):
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            send_message(chat_id, "Usage: /ask_openai <question>")
            return
        question = parts[1]
        reply = ask_openai(question)
        send_message(chat_id, reply)
        return

    # /ask_gemini
    if text.startswith("/ask_gemini"):
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            send_message(chat_id, "Usage: /ask_gemini <question>")
            return
        question = parts[1]
        reply = ask_gemini(question)
        send_message(chat_id, reply)
        return

    # /summarize
    if text.startswith("/summarize"):
        reply = summarize_last_notes(chat_id, limit=10)
        send_message(chat_id, reply)
        return

    # /stats
    if text.startswith("/stats"):
        stats_text = compute_personal_stats(chat_id)
        send_message(chat_id, stats_text)
        return

    # Fallback - THIS MUST BE AT THE END
    send_message(
        chat_id,
        "I did not recognise that. Type /help to see all commands.",
    )



def handle_callback_query(callback_query: dict):
    callback_id = callback_query["id"]
    answer_callback_query(callback_id)


# ========= LAMBDA HANDLER =========


def lambda_handler(event, context):
    print("Incoming event:", json.dumps(event))

    if not TELEGRAM_BOT_TOKEN:
        return {
            "statusCode": 500,
            "body": json.dumps({"ok": False, "error": "Missing TELEGRAM_BOT_TOKEN"}),
        }

    try:
        body = event.get("body") or "{}"
        update = json.loads(body)
    except json.JSONDecodeError:
        print("Invalid JSON body")
        return {"statusCode": 400, "body": "Invalid JSON"}

    if "callback_query" in update:
        handle_callback_query(update["callback_query"])
    else:
        message = update.get("message") or update.get("edited_message")
        if not message:
            return {"statusCode": 200, "body": json.dumps({"ok": True})}

        chat = message.get("chat", {})
        chat_id = chat.get("id")
        text = message.get("text", "")
        message_id = message.get("message_id")
        from_user = message.get("from", {}) or {}
        first_name = from_user.get("first_name") or from_user.get("username") or None

        if chat_id is None:
            return {"statusCode": 200, "body": json.dumps({"ok": True})}

        # Handle different message types
        if "photo" in message:
            handle_photo(chat_id, message)
        elif "document" in message:
            handle_document(chat_id, message)
        elif "voice" in message:
            handle_voice(chat_id, message)
        elif text:
            # Save text messages
            if message_id is not None:
                try:
                    save_message_record(chat_id, message_id, text)
                except Exception as e:
                    print("Error saving message record:", e)
            
            # Handle command
            handle_text_message(chat_id, message_id, text, first_name)
        else:
            send_message(chat_id, "I can handle text, photos, documents, and voice messages!")

    return {
        "statusCode": 200,
        "body": json.dumps({"ok": True}),
    }