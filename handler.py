import json
import os
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from io import BytesIO
import hashlib
import traceback
import logging

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

# ========= STRUCTURED LOGGING SETUP =========

class StructuredLogger:
    """
    Production-grade structured logger for CloudWatch.
    Logs consistent fields: level, timestamp, request_id, user_id, action, outcome, error details.
    """
    def __init__(self, name):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Remove default handlers to avoid duplicates
        self.logger.handlers = []
        
        # Create console handler for Lambda (goes to CloudWatch)
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        self.logger.addHandler(handler)
        
        # Context fields that persist across logs in the same request
        self.context = {}
    
    def set_context(self, **kwargs):
        """Set context fields that will be included in all subsequent logs"""
        self.context.update(kwargs)
    
    def clear_context(self):
        """Clear context fields"""
        self.context = {}
    
    def _log(self, level, message, **extra_fields):
        """Internal method to create structured log entry"""
        log_entry = {
            "level": level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message,
            **self.context,  # Include context fields
            **extra_fields   # Include additional fields
        }
        
        # Log as JSON for easy parsing in CloudWatch Insights
        log_message = json.dumps(log_entry)
        
        if level == "INFO":
            self.logger.info(log_message)
        elif level == "WARNING":
            self.logger.warning(log_message)
        elif level == "ERROR":
            self.logger.error(log_message)
        elif level == "DEBUG":
            self.logger.debug(log_message)
    
    def info(self, message, **extra_fields):
        """Log INFO level message"""
        self._log("INFO", message, **extra_fields)
    
    def warning(self, message, **extra_fields):
        """Log WARNING level message"""
        self._log("WARNING", message, **extra_fields)
    
    def error(self, message, error=None, **extra_fields):
        """Log ERROR level message with optional exception details"""
        if error:
            extra_fields["error_type"] = type(error).__name__
            extra_fields["error_message"] = str(error)
            extra_fields["stack_trace"] = traceback.format_exc()
        self._log("ERROR", message, **extra_fields)
    
    def debug(self, message, **extra_fields):
        """Log DEBUG level message"""
        self._log("DEBUG", message, **extra_fields)

# Initialize structured logger
logger = StructuredLogger(__name__)

# ========= ENVIRONMENT & AWS SETUP =========

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
        logger.error("Telegram API request failed", error=e, method=method, outcome="failure")
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
        logger.error("Failed to download file from Telegram", error=e, file_path=file_path, outcome="failure")
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
        logger.info("File uploaded to S3", s3_key=s3_key, size_bytes=len(file_data), content_type=content_type, outcome="success")
        return True
    except ClientError as e:
        logger.error("S3 upload failed", error=e, s3_key=s3_key, outcome="failure")
        return False


def get_file_from_s3(s3_key: str) -> bytes | None:
    """Download file from S3."""
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
        logger.info("File downloaded from S3", s3_key=s3_key, outcome="success")
        return response['Body'].read()
    except ClientError as e:
        logger.error("S3 download failed", error=e, s3_key=s3_key, outcome="failure")
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
        logger.info("S3 files listed", user_id=user_id, file_count=len(files), outcome="success")
        return files
    except ClientError as e:
        logger.error("S3 list failed", error=e, user_id=user_id, outcome="failure")
        return []


def delete_file_from_s3(s3_key: str) -> bool:
    """Delete file from S3."""
    try:
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=s3_key)
        logger.info("File deleted from S3", s3_key=s3_key, outcome="success")
        return True
    except ClientError as e:
        logger.error("S3 delete failed", error=e, s3_key=s3_key, outcome="failure")
        return False


# ========= DYNAMODB HELPERS =========


def save_key_value(user_id: int, key: str, value: str):
    """Save key-value pair to DynamoDB."""
    item = {
        "user_id": str(user_id),
        "sort_key": f"kv#{key}",
        "value": value,
        "updated_at": now_iso(),
    }
    try:
        table.put_item(Item=item)
        logger.info("Key-value saved to DynamoDB", user_id=user_id, key=key, outcome="success")
    except Exception as e:
        logger.error("DynamoDB save failed", error=e, user_id=user_id, key=key, outcome="failure")


def get_key_value(user_id: int, key: str):
    """Retrieve key-value pair from DynamoDB."""
    try:
        resp = table.get_item(
            Key={
                "user_id": str(user_id),
                "sort_key": f"kv#{key}",
            }
        )
        item = resp.get("Item")
        logger.info("Key-value retrieved from DynamoDB", user_id=user_id, key=key, found=bool(item), outcome="success")
        return item
    except Exception as e:
        logger.error("DynamoDB get failed", error=e, user_id=user_id, key=key, outcome="failure")
        return None


def list_keys(user_id: int):
    """List all keys for a user from DynamoDB."""
    try:
        resp = table.query(
            KeyConditionExpression=Key("user_id").eq(str(user_id))
            & Key("sort_key").begins_with("kv#"),
            ScanIndexForward=True,
        )
        items = resp.get("Items", [])
        keys = [item["sort_key"][3:] for item in items]
        logger.info("Keys listed from DynamoDB", user_id=user_id, key_count=len(keys), outcome="success")
        return keys
    except Exception as e:
        logger.error("DynamoDB list failed", error=e, user_id=user_id, outcome="failure")
        return []


def save_message_record(user_id: int, message_id: int, text: str, message_type: str = "text"):
    """
    Save text message to DynamoDB.
    This is the CREATE operation for text messages.
    """
    item = {
        "user_id": str(user_id),
        "sort_key": f"msg#{message_id}",
        "message_id": message_id,
        "message_type": message_type,
        "text": text,
        "created_at": now_iso(),
    }
    try:
        table.put_item(Item=item)
        logger.info("Message saved to DynamoDB", user_id=user_id, message_id=message_id, message_type=message_type, outcome="success")
    except Exception as e:
        logger.error("DynamoDB message save failed", error=e, user_id=user_id, message_id=message_id, outcome="failure")


def save_file_metadata(user_id: int, file_id: str, s3_key: str, file_type: str, 
                       filename: str, file_size: int, mime_type: str = None,
                       telegram_message_id: int = None):
    """
    Save file metadata to DynamoDB.
    This is the CREATE operation for media files.
    Links S3 storage with DynamoDB metadata.
    """
    item = {
        "user_id": str(user_id),
        "sort_key": f"file#{file_id}",
        "file_id": file_id,
        "s3_key": s3_key,
        "file_type": file_type,
        "filename": filename,
        "file_size": file_size,
        "mime_type": mime_type,
        "telegram_message_id": telegram_message_id,
        "created_at": now_iso(),
    }
    try:
        table.put_item(Item=item)
        logger.info("File metadata saved to DynamoDB", user_id=user_id, file_id=file_id, file_type=file_type, filename=filename, file_size=file_size, outcome="success")
    except Exception as e:
        logger.error("DynamoDB file metadata save failed", error=e, user_id=user_id, file_id=file_id, outcome="failure")


def get_file_metadata(user_id: int, file_id: str):
    """Retrieve file metadata from DynamoDB (READ operation)."""
    try:
        resp = table.get_item(
            Key={
                "user_id": str(user_id),
                "sort_key": f"file#{file_id}",
            }
        )
        item = resp.get("Item")
        logger.info("File metadata retrieved from DynamoDB", user_id=user_id, file_id=file_id, found=bool(item), outcome="success")
        return item
    except Exception as e:
        logger.error("DynamoDB file metadata get failed", error=e, user_id=user_id, file_id=file_id, outcome="failure")
        return None


def list_file_metadata(user_id: int, limit: int = 20):
    """List file metadata for a user (READ operation)."""
    try:
        resp = table.query(
            KeyConditionExpression=Key("user_id").eq(str(user_id))
            & Key("sort_key").begins_with("file#"),
            ScanIndexForward=False,
            Limit=limit
        )
        items = resp.get("Items", [])
        logger.info("File metadata listed from DynamoDB", user_id=user_id, file_count=len(items), outcome="success")
        return items
    except Exception as e:
        logger.error("DynamoDB file metadata list failed", error=e, user_id=user_id, outcome="failure")
        return []


def get_message_by_id(user_id: int, message_id: int):
    """Retrieve specific message from DynamoDB (READ operation)."""
    try:
        resp = table.get_item(
            Key={
                "user_id": str(user_id),
                "sort_key": f"msg#{message_id}",
            }
        )
        item = resp.get("Item")
        logger.info("Message retrieved from DynamoDB", user_id=user_id, message_id=message_id, found=bool(item), outcome="success")
        return item
    except Exception as e:
        logger.error("DynamoDB message get failed", error=e, user_id=user_id, message_id=message_id, outcome="failure")
        return None


def get_all_messages(user_id: int):
    """Get all messages for a user (READ operation)."""
    try:
        resp = table.query(
            KeyConditionExpression=Key("user_id").eq(str(user_id))
            & Key("sort_key").begins_with("msg#"),
            ScanIndexForward=True,
        )
        items = resp.get("Items", [])
        logger.info("All messages retrieved from DynamoDB", user_id=user_id, message_count=len(items), outcome="success")
        return items
    except Exception as e:
        logger.error("DynamoDB all messages get failed", error=e, user_id=user_id, outcome="failure")
        return []


def get_last_messages(user_id: int, limit: int = 5):
    """Get last N messages (READ operation)."""
    items = get_all_messages(user_id)
    items_sorted = sorted(items, key=lambda x: x.get("created_at", ""), reverse=True)
    return items_sorted[:limit]


def search_messages(user_id: int, keyword: str, limit: int = 20):
    """Search messages by keyword (READ operation)."""
    items = get_all_messages(user_id)
    keyword_lower = keyword.lower()
    matches = [
        item
        for item in items
        if "text" in item and keyword_lower in item["text"].lower()
    ]
    matches_sorted = sorted(matches, key=lambda x: x.get("created_at", ""), reverse=True)
    logger.info("Messages searched", user_id=user_id, keyword=keyword, match_count=len(matches), outcome="success")
    return matches_sorted[:limit]


def get_last_notes(user_id: int, limit: int = 10):
    """Get last non-command messages."""
    items = get_all_messages(user_id)
    notes = [
        item
        for item in items
        if isinstance(item.get("text"), str)
        and not item["text"].strip().startswith("/")
    ]
    notes_sorted = sorted(notes, key=lambda x: x.get("created_at", ""), reverse=True)
    return notes_sorted[:limit]


# ========= NOTES SYSTEM (DynamoDB CRUD Demo) =========


def create_note(user_id: int, title: str, content: str) -> str:
    """
    CREATE operation - Save a note to DynamoDB
    Returns the note_id
    """
    # Generate unique note ID
    timestamp = datetime.now(timezone.utc).isoformat()
    note_id = hashlib.md5(f"{user_id}{timestamp}".encode()).hexdigest()[:12]
    
    item = {
        "user_id": str(user_id),
        "sort_key": f"note#{note_id}",
        "note_id": note_id,
        "title": title,
        "content": content,
        "created_at": timestamp,
        "updated_at": timestamp,
    }
    
    try:
        table.put_item(Item=item)
        logger.info("Note created", user_id=user_id, note_id=note_id, title=title, outcome="success")
        return note_id
    except Exception as e:
        logger.error("Note creation failed", error=e, user_id=user_id, title=title, outcome="failure")
        return None


def read_note(user_id: int, note_id: str) -> dict:
    """
    READ operation - Retrieve a specific note from DynamoDB
    """
    try:
        resp = table.get_item(
            Key={
                "user_id": str(user_id),
                "sort_key": f"note#{note_id}",
            }
        )
        item = resp.get("Item")
        logger.info("Note read", user_id=user_id, note_id=note_id, found=bool(item), outcome="success")
        return item
    except Exception as e:
        logger.error("Note read failed", error=e, user_id=user_id, note_id=note_id, outcome="failure")
        return None


def update_note(user_id: int, note_id: str, title: str = None, content: str = None) -> bool:
    """
    UPDATE operation - Modify an existing note
    """
    # Build update expression dynamically
    update_expr = "SET updated_at = :updated_at"
    expr_values = {":updated_at": datetime.now(timezone.utc).isoformat()}
    
    if title:
        update_expr += ", title = :title"
        expr_values[":title"] = title
    
    if content:
        update_expr += ", content = :content"
        expr_values[":content"] = content
    
    try:
        table.update_item(
            Key={
                "user_id": str(user_id),
                "sort_key": f"note#{note_id}",
            },
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
        )
        logger.info("Note updated", user_id=user_id, note_id=note_id, outcome="success")
        return True
    except Exception as e:
        logger.error("Note update failed", error=e, user_id=user_id, note_id=note_id, outcome="failure")
        return False


def delete_note(user_id: int, note_id: str) -> bool:
    """
    DELETE operation - Remove a note from DynamoDB
    """
    try:
        table.delete_item(
            Key={
                "user_id": str(user_id),
                "sort_key": f"note#{note_id}",
            }
        )
        logger.info("Note deleted", user_id=user_id, note_id=note_id, outcome="success")
        return True
    except Exception as e:
        logger.error("Note deletion failed", error=e, user_id=user_id, note_id=note_id, outcome="failure")
        return False


def list_all_notes(user_id: int, limit: int = 50) -> list:
    """
    LIST operation - Get all notes for a user
    """
    try:
        resp = table.query(
            KeyConditionExpression=Key("user_id").eq(str(user_id))
            & Key("sort_key").begins_with("note#"),
            ScanIndexForward=False,  # Most recent first
            Limit=limit
        )
        items = resp.get("Items", [])
        logger.info("Notes listed", user_id=user_id, note_count=len(items), outcome="success")
        return items
    except Exception as e:
        logger.error("Notes list failed", error=e, user_id=user_id, outcome="failure")
        return []


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
        logger.info("OpenAI request successful", outcome="success")
        return resp_data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        logger.error("OpenAI API error", error=e, http_code=e.code, response_body=err_body[:200], outcome="failure")
        if e.code == 429:
            return "I'm hitting the OpenAI rate/usage limit right now.\nPlease try again in a bit."
        else:
            return "OpenAI returned an error. Please try again later."
    except Exception as e:
        logger.error("OpenAI request failed", error=e, outcome="failure")
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
        logger.info("Gemini request successful", outcome="success")
        return text.strip() or "Gemini response was empty."
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        logger.error("Gemini API error", error=e, http_code=e.code, response_body=err_body[:200], outcome="failure")
        if e.code == 429:
            return "Gemini is currently rate-limited or over quota.\nPlease try again later."
        else:
            return "Gemini returned an error. Please try again later."
    except Exception as e:
        logger.error("Gemini request failed", error=e, outcome="failure")
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
    """Compute statistics from DynamoDB and S3."""
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

    # Get file statistics from DynamoDB metadata
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
    lines.append(f"💬 Text Messages (DynamoDB):")
    lines.append(f"  • Total stored messages: {total_msgs}")
    lines.append(f"  • Messages in last 7 days: {msgs_last_7_days}")
    lines.append(f"  • Notes (non-command): {notes_count}")
    if notes_count > 0:
        lines.append(f"  • Avg note length: {avg_note_length} characters")

    if total_files > 0:
        lines.append("")
        lines.append(f"📁 Media Files (S3 + DynamoDB):")
        lines.append(f"  • Total files uploaded: {total_files}")
        lines.append(f"  • Total storage used: {total_file_size / 1024 / 1024:.2f} MB")
        if file_type_counts:
            lines.append(f"  • File types:")
            for ft, count in file_type_counts.items():
                lines.append(f"    - {ft}: {count}")

    if first_ts and last_ts:
        lines.append("")
        lines.append(f"📅 Timeline:")
        lines.append(f"  • First message: {first_ts.strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"  • Latest message: {last_ts.strftime('%Y-%m-%d %H:%M UTC')}")

    if most_used_cmd:
        lines.append("")
        lines.append(f"⭐ Most used command: {most_used_cmd} ({most_used_cmd_count} times)")

    return "\n".join(lines)


# ========= FILE HANDLING =========


def handle_photo(chat_id: int, message: dict):
    """Handle photo uploads: Save to S3 + metadata to DynamoDB"""
    logger.info("Photo upload started", user_id=chat_id, action="handle_photo")
    
    photos = message.get("photo", [])
    if not photos:
        send_message(chat_id, "No photo found in message.")
        logger.warning("No photo in message", user_id=chat_id, action="handle_photo", outcome="failure")
        return

    # Get the largest photo (last in array)
    photo = photos[-1]
    file_id = photo.get("file_id")
    file_size = photo.get("file_size", 0)
    message_id = message.get("message_id")

    logger.info("Photo details received", user_id=chat_id, file_id=file_id, file_size=file_size, message_id=message_id)

    # Get file info from Telegram
    file_info = get_file_info(file_id)
    if not file_info or not file_info.get("ok"):
        send_message(chat_id, "❌ Failed to get photo information.")
        logger.error("Failed to get photo info from Telegram", user_id=chat_id, file_id=file_id, outcome="failure")
        return

    file_path = file_info["result"]["file_path"]
    
    # Download file
    logger.info("Downloading photo from Telegram", user_id=chat_id, file_path=file_path)
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
            mime_type="image/jpeg",
            telegram_message_id=message_id
        )
        
        logger.info("Photo upload completed", user_id=chat_id, file_id=file_id, s3_key=s3_key, action="handle_photo", outcome="success")
        
        send_message(
            chat_id, 
            f"✅ Photo saved successfully!\n\n"
            f"📸 File ID: {file_id}\n"
            f"💾 Size: {len(file_data) / 1024:.1f} KB\n"
            f"☁️ S3 Path: {s3_key}\n"
            f"🗄️ Metadata: Saved to DynamoDB"
        )
    else:
        send_message(chat_id, "❌ Failed to save photo to storage.")


def handle_document(chat_id: int, message: dict):
    """Handle document uploads: Save to S3 + metadata to DynamoDB"""
    logger.info("Document upload started", user_id=chat_id, action="handle_document")
    
    document = message.get("document")
    if not document:
        send_message(chat_id, "No document found in message.")
        logger.warning("No document in message", user_id=chat_id, action="handle_document", outcome="failure")
        return

    file_id = document.get("file_id")
    file_name = document.get("file_name", f"document_{file_id}")
    file_size = document.get("file_size", 0)
    mime_type = document.get("mime_type", "application/octet-stream")
    message_id = message.get("message_id")

    logger.info("Document details received", user_id=chat_id, file_id=file_id, filename=file_name, file_size=file_size, mime_type=mime_type)

    # Check file size (Telegram max is 20MB for bots)
    if file_size > 20 * 1024 * 1024:
        send_message(chat_id, "❌ File is too large (max 20MB).")
        logger.warning("Document too large", user_id=chat_id, file_size=file_size, outcome="failure")
        return

    # Get file info
    file_info = get_file_info(file_id)
    if not file_info or not file_info.get("ok"):
        send_message(chat_id, "❌ Failed to get document information.")
        logger.error("Failed to get document info from Telegram", user_id=chat_id, file_id=file_id, outcome="failure")
        return

    file_path = file_info["result"]["file_path"]
    
    # Download file
    logger.info("Downloading document from Telegram", user_id=chat_id, file_path=file_path)
    file_data = download_telegram_file(file_path)
    if not file_data:
        send_message(chat_id, "❌ Failed to download document.")
        return

    # Generate S3 key and upload
    s3_key = generate_s3_key(chat_id, "documents", file_name)
    
    if upload_file_to_s3(file_data, s3_key, mime_type):
        # Save metadata to DynamoDB
        save_file_metadata(
            user_id=chat_id,
            file_id=file_id,
            s3_key=s3_key,
            file_type="document",
            filename=file_name,
            file_size=len(file_data),
            mime_type=mime_type,
            telegram_message_id=message_id
        )
        
        logger.info("Document upload completed", user_id=chat_id, file_id=file_id, s3_key=s3_key, action="handle_document", outcome="success")
        
        send_message(
            chat_id,
            f"✅ Document saved successfully!\n\n"
            f"📄 File: {file_name}\n"
            f"💾 Size: {len(file_data) / 1024:.1f} KB\n"
            f"📝 Type: {mime_type}\n"
            f"🆔 File ID: {file_id}\n"
            f"☁️ S3 Path: {s3_key}\n"
            f"🗄️ Metadata: Saved to DynamoDB"
        )
    else:
        send_message(chat_id, "❌ Failed to save document to storage.")


def handle_voice(chat_id: int, message: dict):
    """Handle voice message uploads: Save to S3 + metadata to DynamoDB"""
    logger.info("Voice message upload started", user_id=chat_id, action="handle_voice")
    
    voice = message.get("voice")
    if not voice:
        send_message(chat_id, "No voice message found.")
        logger.warning("No voice message in message", user_id=chat_id, action="handle_voice", outcome="failure")
        return

    file_id = voice.get("file_id")
    file_size = voice.get("file_size", 0)
    duration = voice.get("duration", 0)
    message_id = message.get("message_id")

    logger.info("Voice message details received", user_id=chat_id, file_id=file_id, file_size=file_size, duration=duration)

    file_info = get_file_info(file_id)
    if not file_info or not file_info.get("ok"):
        send_message(chat_id, "❌ Failed to get voice message information.")
        logger.error("Failed to get voice info from Telegram", user_id=chat_id, file_id=file_id, outcome="failure")
        return

    file_path = file_info["result"]["file_path"]
    
    logger.info("Downloading voice message from Telegram", user_id=chat_id, file_path=file_path)
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
            mime_type="audio/ogg",
            telegram_message_id=message_id
        )
        
        logger.info("Voice message upload completed", user_id=chat_id, file_id=file_id, s3_key=s3_key, action="handle_voice", outcome="success")
        
        send_message(
            chat_id,
            f"✅ Voice message saved!\n\n"
            f"🎤 Duration: {duration}s\n"
            f"💾 Size: {len(file_data) / 1024:.1f} KB\n"
            f"🆔 File ID: {file_id}\n"
            f"☁️ S3 Path: {s3_key}\n"
            f"🗄️ Metadata: Saved to DynamoDB"
        )
    else:
        send_message(chat_id, "❌ Failed to save voice message.")


def handle_video(chat_id: int, message: dict):
    """Handle video uploads: Save to S3 + metadata to DynamoDB"""
    logger.info("Video upload started", user_id=chat_id, action="handle_video")
    
    video = message.get("video")
    if not video:
        send_message(chat_id, "No video found in message.")
        logger.warning("No video in message", user_id=chat_id, action="handle_video", outcome="failure")
        return

    file_id = video.get("file_id")
    file_size = video.get("file_size", 0)
    duration = video.get("duration", 0)
    mime_type = video.get("mime_type", "video/mp4")
    message_id = message.get("message_id")

    logger.info("Video details received", user_id=chat_id, file_id=file_id, file_size=file_size, duration=duration)

    # Check file size
    if file_size > 20 * 1024 * 1024:
        send_message(chat_id, "❌ Video is too large (max 20MB).")
        logger.warning("Video too large", user_id=chat_id, file_size=file_size, outcome="failure")
        return

    file_info = get_file_info(file_id)
    if not file_info or not file_info.get("ok"):
        send_message(chat_id, "❌ Failed to get video information.")
        logger.error("Failed to get video info from Telegram", user_id=chat_id, file_id=file_id, outcome="failure")
        return

    file_path = file_info["result"]["file_path"]
    
    logger.info("Downloading video from Telegram", user_id=chat_id, file_path=file_path)
    file_data = download_telegram_file(file_path)
    
    if not file_data:
        send_message(chat_id, "❌ Failed to download video.")
        return

    filename = f"video_{file_id}.mp4"
    s3_key = generate_s3_key(chat_id, "videos", filename)
    
    if upload_file_to_s3(file_data, s3_key, mime_type):
        save_file_metadata(
            user_id=chat_id,
            file_id=file_id,
            s3_key=s3_key,
            file_type="video",
            filename=filename,
            file_size=len(file_data),
            mime_type=mime_type,
            telegram_message_id=message_id
        )
        
        logger.info("Video upload completed", user_id=chat_id, file_id=file_id, s3_key=s3_key, action="handle_video", outcome="success")
        
        send_message(
            chat_id,
            f"✅ Video saved successfully!\n\n"
            f"🎥 Duration: {duration}s\n"
            f"💾 Size: {len(file_data) / 1024:.1f} KB\n"
            f"🆔 File ID: {file_id}\n"
            f"☁️ S3 Path: {s3_key}\n"
            f"🗄️ Metadata: Saved to DynamoDB"
        )
    else:
        send_message(chat_id, "❌ Failed to save video.")


def handle_audio(chat_id: int, message: dict):
    """Handle audio file uploads: Save to S3 + metadata to DynamoDB"""
    logger.info("Audio upload started", user_id=chat_id, action="handle_audio")
    
    audio = message.get("audio")
    if not audio:
        send_message(chat_id, "No audio found in message.")
        logger.warning("No audio in message", user_id=chat_id, action="handle_audio", outcome="failure")
        return

    file_id = audio.get("file_id")
    file_size = audio.get("file_size", 0)
    duration = audio.get("duration", 0)
    mime_type = audio.get("mime_type", "audio/mpeg")
    file_name = audio.get("file_name", f"audio_{file_id}.mp3")
    message_id = message.get("message_id")

    logger.info("Audio details received", user_id=chat_id, file_id=file_id, filename=file_name, file_size=file_size, duration=duration)

    if file_size > 20 * 1024 * 1024:
        send_message(chat_id, "❌ Audio file is too large (max 20MB).")
        logger.warning("Audio too large", user_id=chat_id, file_size=file_size, outcome="failure")
        return

    file_info = get_file_info(file_id)
    if not file_info or not file_info.get("ok"):
        send_message(chat_id, "❌ Failed to get audio information.")
        logger.error("Failed to get audio info from Telegram", user_id=chat_id, file_id=file_id, outcome="failure")
        return

    file_path = file_info["result"]["file_path"]
    
    logger.info("Downloading audio from Telegram", user_id=chat_id, file_path=file_path)
    file_data = download_telegram_file(file_path)
    
    if not file_data:
        send_message(chat_id, "❌ Failed to download audio.")
        return

    s3_key = generate_s3_key(chat_id, "audio", file_name)
    
    if upload_file_to_s3(file_data, s3_key, mime_type):
        save_file_metadata(
            user_id=chat_id,
            file_id=file_id,
            s3_key=s3_key,
            file_type="audio",
            filename=file_name,
            file_size=len(file_data),
            mime_type=mime_type,
            telegram_message_id=message_id
        )
        
        logger.info("Audio upload completed", user_id=chat_id, file_id=file_id, s3_key=s3_key, action="handle_audio", outcome="success")
        
        send_message(
            chat_id,
            f"✅ Audio saved successfully!\n\n"
            f"🎵 File: {file_name}\n"
            f"⏱️ Duration: {duration}s\n"
            f"💾 Size: {len(file_data) / 1024:.1f} KB\n"
            f"🆔 File ID: {file_id}\n"
            f"☁️ S3 Path: {s3_key}\n"
            f"🗄️ Metadata: Saved to DynamoDB"
        )
    else:
        send_message(chat_id, "❌ Failed to save audio.")


# ========= COMMAND HANDLERS FOR NOTES =========


def handle_note_commands(chat_id: int, text: str) -> bool:
    """
    Handle all note-related commands
    Returns True if command was handled, False otherwise
    """
    
    # /newnote <title> | <content>
    if text.startswith("/newnote"):
        logger.info("Processing newnote command", user_id=chat_id, action="newnote")
        parts = text[len("/newnote"):].strip()
        if not parts or "|" not in parts:
            send_message(
                chat_id,
                "Usage: /newnote <title> | <content>\n\n"
                "Example: /newnote Shopping List | Buy milk, eggs, bread"
            )
            return True
        
        title, content = parts.split("|", 1)
        title = title.strip()
        content = content.strip()
        
        if not title or not content:
            send_message(chat_id, "Both title and content are required!")
            return True
        
        note_id = create_note(chat_id, title, content)
        if note_id:
            send_message(
                chat_id,
                f"✅ Note created successfully!\n\n"
                f"📝 Title: {title}\n"
                f"🆔 Note ID: {note_id}\n\n"
                f"Use /readnote {note_id} to view it"
            )
        else:
            send_message(chat_id, "❌ Failed to create note. Please try again.")
        return True
    
    # /readnote <note_id>
    if text.startswith("/readnote"):
        logger.info("Processing readnote command", user_id=chat_id, action="readnote")
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            send_message(chat_id, "Usage: /readnote <note_id>")
            return True
        
        note_id = parts[1].strip()
        note = read_note(chat_id, note_id)
        
        if note:
            send_message(
                chat_id,
                f"📝 **{note.get('title', 'Untitled')}**\n\n"
                f"{note.get('content', '')}\n\n"
                f"🆔 ID: {note.get('note_id')}\n"
                f"📅 Created: {note.get('created_at', '')[:19]}\n"
                f"📝 Updated: {note.get('updated_at', '')[:19]}",
                parse_mode="Markdown"
            )
        else:
            send_message(chat_id, f"❌ Note '{note_id}' not found.")
        return True
    
    # /updatenote <note_id> | <new_title> | <new_content>
    if text.startswith("/updatenote"):
        logger.info("Processing updatenote command", user_id=chat_id, action="updatenote")
        parts = text[len("/updatenote"):].strip()
        if not parts or "|" not in parts:
            send_message(
                chat_id,
                "Usage: /updatenote <note_id> | <new_title> | <new_content>\n\n"
                "Example: /updatenote abc123 | New Title | Updated content"
            )
            return True
        
        split_parts = parts.split("|")
        if len(split_parts) < 3:
            send_message(chat_id, "Please provide note_id, title, and content separated by |")
            return True
        
        note_id = split_parts[0].strip()
        new_title = split_parts[1].strip()
        new_content = split_parts[2].strip()
        
        if update_note(chat_id, note_id, new_title, new_content):
            send_message(chat_id, f"✅ Note '{note_id}' updated successfully!")
        else:
            send_message(chat_id, f"❌ Failed to update note '{note_id}'.")
        return True
    
    # /deletenote <note_id>
    if text.startswith("/deletenote"):
        logger.info("Processing deletenote command", user_id=chat_id, action="deletenote")
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            send_message(chat_id, "Usage: /deletenote <note_id>")
            return True
        
        note_id = parts[1].strip()
        if delete_note(chat_id, note_id):
            send_message(chat_id, f"✅ Note '{note_id}' deleted successfully!")
        else:
            send_message(chat_id, f"❌ Failed to delete note '{note_id}'.")
        return True
    
    # /mynotes
    if text == "/mynotes":
        logger.info("Processing mynotes command", user_id=chat_id, action="mynotes")
        notes = list_all_notes(chat_id, limit=50)
        
        if not notes:
            send_message(chat_id, "📝 You don't have any notes yet.\n\nCreate one with: /newnote <title> | <content>")
            return True
        
        lines = [f"📚 Your Notes ({len(notes)} total):\n"]
        for idx, note in enumerate(notes, start=1):
            title = note.get("title", "Untitled")
            note_id = note.get("note_id", "")
            created = note.get("created_at", "")[:10]
            content_preview = note.get("content", "")[:50]
            if len(note.get("content", "")) > 50:
                content_preview += "..."
            
            lines.append(
                f"{idx}. **{title}**\n"
                f"   🆔 {note_id} | 📅 {created}\n"
                f"   {content_preview}\n"
            )
        
        send_message(chat_id, "\n".join(lines), parse_mode="Markdown")
        return True
    
    # /notesdemo - Run a complete CRUD demo
    if text == "/notesdemo":
        logger.info("Processing notesdemo command", user_id=chat_id, action="notesdemo")
        run_crud_demo(chat_id)
        return True
    
    return False


def run_crud_demo(chat_id: int):
    """Demonstrate complete CRUD cycle in DynamoDB"""
    logger.info("CRUD demo started", user_id=chat_id, action="crud_demo")
    send_message(chat_id, "🚀 Starting DynamoDB CRUD Demo...\n")
    
    # 1. CREATE
    send_message(chat_id, "1️⃣ CREATE: Creating a new note in DynamoDB...")
    note_id = create_note(
        chat_id, 
        "Demo Note", 
        "This is a demonstration of DynamoDB persistence"
    )
    
    if not note_id:
        send_message(chat_id, "❌ Demo failed at CREATE step")
        logger.error("CRUD demo failed at CREATE", user_id=chat_id, action="crud_demo", outcome="failure")
        return
    
    send_message(chat_id, f"✅ Created note with ID: {note_id}")
    
    # 2. READ
    send_message(chat_id, "\n2️⃣ READ: Reading the note back from DynamoDB...")
    note = read_note(chat_id, note_id)
    
    if note:
        send_message(
            chat_id,
            f"✅ Retrieved note:\n"
            f"Title: {note.get('title')}\n"
            f"Content: {note.get('content')}"
        )
    else:
        send_message(chat_id, "❌ Demo failed at READ step")
        logger.error("CRUD demo failed at READ", user_id=chat_id, action="crud_demo", outcome="failure")
        return
    
    # 3. UPDATE
    send_message(chat_id, "\n3️⃣ UPDATE: Updating the note in DynamoDB...")
    if update_note(chat_id, note_id, "Updated Demo Note", "Content has been modified!"):
        updated_note = read_note(chat_id, note_id)
        send_message(
            chat_id,
            f"✅ Updated note:\n"
            f"Title: {updated_note.get('title')}\n"
            f"Content: {updated_note.get('content')}"
        )
    else:
        send_message(chat_id, "❌ Demo failed at UPDATE step")
        logger.error("CRUD demo failed at UPDATE", user_id=chat_id, action="crud_demo", outcome="failure")
        return
    
    # 4. LIST
    send_message(chat_id, "\n4️⃣ LIST: Getting all your notes from DynamoDB...")
    all_notes = list_all_notes(chat_id, limit=10)
    send_message(chat_id, f"✅ You have {len(all_notes)} total notes")
    
    # 5. DELETE
    send_message(chat_id, "\n5️⃣ DELETE: Cleaning up demo note from DynamoDB...")
    if delete_note(chat_id, note_id):
        send_message(chat_id, "✅ Demo note deleted")
    else:
        send_message(chat_id, "❌ Demo failed at DELETE step")
        logger.error("CRUD demo failed at DELETE", user_id=chat_id, action="crud_demo", outcome="failure")
        return
    
    logger.info("CRUD demo completed successfully", user_id=chat_id, action="crud_demo", outcome="success")
    send_message(
        chat_id,
        "\n🎉 CRUD Demo Complete!\n\n"
        "All DynamoDB operations (Create, Read, Update, Delete, List) "
        "executed successfully and data persisted correctly."
    )


# ========= COMMAND HELPERS =========


def help_text() -> str:
    return (
        "Here's what I can do:\n\n"
        "🔹 Basic Commands:\n"
        "/hello - greet\n"
        "/help - this message\n"
        "/echo <text> - echo back\n\n"
        "💾 Storage Commands (DynamoDB):\n"
        "/save <key> <value> - save your data\n"
        "/get <key> - retrieve your value\n"
        "/list - list saved keys\n\n"
        "📝 Notes System (DynamoDB CRUD Demo):\n"
        "/newnote <title> | <content> - create note\n"
        "/readnote <note_id> - read a note\n"
        "/updatenote <note_id> | <title> | <content> - update note\n"
        "/deletenote <note_id> - delete note\n"
        "/mynotes - list all your notes\n"
        "/notesdemo - run CRUD demo\n\n"
        "📁 File Commands (S3 + DynamoDB):\n"
        "/myfiles - list your uploaded files\n"
        "/fileinfo <file_id> - get file details\n"
        "Send me photos, documents, videos, audio, or voice messages!\n\n"
        "📋 Message Commands (DynamoDB):\n"
        "/search <keyword> - search your messages\n"
        "/latest - show your latest note\n"
        "/history - show your last 5 notes\n\n"
        "🤖 AI Commands:\n"
        "/ask <question> - AI answer\n"
        "/summarize - AI summary of your notes\n\n"
        "📊 Analytics:\n"
        "/stats - personal usage statistics\n\n"
        "🧪 Testing:\n"
        "/testerror - trigger test error (for CloudWatch)\n\n"
        "/menu - show this menu again"
    )


# ========= COMMAND HANDLING =========


def handle_text_message(chat_id: int, message_id: int, text: str, first_name: str | None):
    """
    Handle all text-based commands and messages.
    All text messages are saved to DynamoDB.
    """
    text = text.strip()
    
    logger.info("Processing text message", user_id=chat_id, message_id=message_id, command=text.split()[0] if text.startswith("/") else "message", action="handle_text")
    
    # TEST ERROR COMMAND - For CloudWatch alarm testing
    if text == "/testerror":
        logger.error("Intentional test error", error=Exception("This is a test error for CloudWatch"), user_id=chat_id, action="test_error", outcome="failure")
        send_message(chat_id, "✅ Test error logged successfully!\n\nCheck CloudWatch Logs to see the ERROR entry with full stack trace.\n\nThe alarm 'telegram-bot-lambda-errors' should trigger within 5 minutes.")
        return
    
    # Check note commands first (these have their own DynamoDB operations)
    if handle_note_commands(chat_id, text):
        return

    # /start
    if text.startswith("/start"):
        logger.info("Start command received", user_id=chat_id, action="start")
        username = first_name or "there"
        send_message(chat_id, f"Welcome, {username}! 😉")
        send_message(chat_id, help_text())
        return

    # /hello
    if text.startswith("/hello"):
        logger.info("Hello command received", user_id=chat_id, action="hello")
        send_message(chat_id, "👋 Hello! How can I help you today?")
        return

    # /help or /menu
    if text.startswith("/help") or text.startswith("/menu"):
        logger.info("Help command received", user_id=chat_id, action="help")
        send_message(chat_id, help_text())
        return

    # /echo
    if text.startswith("/echo"):
        logger.info("Echo command received", user_id=chat_id, action="echo")
        parts = text.split(maxsplit=1)
        if len(parts) == 1:
            send_message(chat_id, "Usage: /echo <text>")
        else:
            send_message(chat_id, parts[1])
        return

    # /save
    if text.startswith("/save"):
        logger.info("Save command received", user_id=chat_id, action="save")
        parts = text.split(maxsplit=2)
        if len(parts) < 3:
            send_message(chat_id, "Usage: /save <key> <value>")
            return
        key = parts[1]
        value = parts[2]
        save_key_value(chat_id, key, value)
        send_message(chat_id, f"✅ Saved key '{key}' to DynamoDB.")
        return

    # /get
    if text.startswith("/get"):
        logger.info("Get command received", user_id=chat_id, action="get")
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            send_message(chat_id, "Usage: /get <key>")
            return
        key = parts[1]
        item = get_key_value(chat_id, key)
        if not item:
            send_message(chat_id, f"❌ No value found for key '{key}' in DynamoDB.")
        else:
            send_message(chat_id, f"🔑 {key} = {item.get('value', '')} (from DynamoDB)")
        return

    # /list
    if text == "/list":
        logger.info("List command received", user_id=chat_id, action="list")
        keys = list_keys(chat_id)
        if not keys:
            send_message(chat_id, "You have not saved any keys yet in DynamoDB.")
        else:
            lines = "\n".join(f"• {k}" for k in keys)
            send_message(chat_id, "Your saved keys (from DynamoDB):\n" + lines)
        return

    # /myfiles
    if text == "/myfiles":
        logger.info("Myfiles command received", user_id=chat_id, action="myfiles")
        files = list_file_metadata(chat_id, limit=20)
        if not files:
            send_message(chat_id, "You haven't uploaded any files yet.")
            return
        
        lines = ["📁 Your Files (from DynamoDB metadata):\n"]
        for item in files:
            filename = item.get("filename", "unknown")
            file_type = item.get("file_type", "unknown")
            size_kb = item.get("file_size", 0) / 1024
            created = item.get("created_at", "")[:10]
            file_id = item.get("file_id", "")
            lines.append(f"• {filename} ({file_type})")
            lines.append(f"  Size: {size_kb:.1f} KB | {created} | ID: {file_id[:8]}...")
        
        lines.append(f"\n💡 Files stored in S3, metadata in DynamoDB")
        send_message(chat_id, "\n".join(lines))
        return

    # /fileinfo
    if text.startswith("/fileinfo"):
        logger.info("Fileinfo command received", user_id=chat_id, action="fileinfo")
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
            f"📄 File Information (from DynamoDB):\n\n"
            f"Filename: {metadata.get('filename')}\n"
            f"Type: {metadata.get('file_type')}\n"
            f"Size: {metadata.get('file_size', 0) / 1024:.1f} KB\n"
            f"MIME: {metadata.get('mime_type', 'N/A')}\n"
            f"☁️ S3 Key: {metadata.get('s3_key')}\n"
            f"📅 Uploaded: {metadata.get('created_at')}\n"
            f"💡 File stored in S3, metadata in DynamoDB"
        )
        send_message(chat_id, info)
        return

    # /getid
    if text.startswith("/getid"):
        logger.info("Getid command received", user_id=chat_id, action="getid")
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
            send_message(chat_id, f"No message stored with id {msg_id} in DynamoDB.")
        else:
            send_message(
                chat_id,
                f"🧾 Message {msg_id} (from DynamoDB at {item.get('created_at', '')}):\n\n{item.get('text', '')}",
            )
        return

    # /search
    if text.startswith("/search"):
        logger.info("Search command received", user_id=chat_id, action="search")
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            send_message(chat_id, "Usage: /search <keyword>")
            return
        keyword = parts[1]
        matches = search_messages(chat_id, keyword)
        if not matches:
            send_message(chat_id, f"No messages found containing '{keyword}' in DynamoDB.")
            return

        lines = []
        for item in matches:
            msg_id = item.get("message_id")
            snippet = item.get("text", "")
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            lines.append(f"{msg_id}: {snippet}")
        send_message(chat_id, "🔍 Search results (from DynamoDB):\n\n" + "\n".join(lines))
        return

    # /latest
    if text.startswith("/latest"):
        logger.info("Latest command received", user_id=chat_id, action="latest")
        items = get_last_messages(chat_id, limit=1)
        if not items:
            send_message(chat_id, "No messages stored yet in DynamoDB.")
            return
        item = items[0]
        send_message(
            chat_id,
            f"📝 Latest message (from DynamoDB at {item.get('created_at', '')}):\n\n{item.get('text', '')}",
        )
        return

    # /history
    if text.startswith("/history"):
        logger.info("History command received", user_id=chat_id, action="history")
        items = get_last_messages(chat_id, limit=5)
        if not items:
            send_message(chat_id, "No messages stored yet in DynamoDB.")
            return
        lines = []
        for idx, item in enumerate(items, start=1):
            snippet = item.get("text", "")
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            lines.append(f"{idx}. [{item.get('created_at', '')}]\n{snippet}")
        send_message(chat_id, "🧾 Your last messages (from DynamoDB):\n\n" + "\n\n".join(lines))
        return

    # /ask
    if text.startswith("/ask "):
        logger.info("Ask command received", user_id=chat_id, action="ask")
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
        logger.info("Ask_openai command received", user_id=chat_id, action="ask_openai")
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
        logger.info("Ask_gemini command received", user_id=chat_id, action="ask_gemini")
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
        logger.info("Summarize command received", user_id=chat_id, action="summarize")
        reply = summarize_last_notes(chat_id, limit=10)
        send_message(chat_id, reply)
        return

    # /stats
    if text.startswith("/stats"):
        logger.info("Stats command received", user_id=chat_id, action="stats")
        stats_text = compute_personal_stats(chat_id)
        send_message(chat_id, stats_text)
        return

    # Fallback - THIS MUST BE AT THE END
    logger.warning("Unknown command", user_id=chat_id, command=text, action="unknown_command")
    send_message(
        chat_id,
        "I did not recognise that command. Type /help to see all commands.",
    )


def handle_callback_query(callback_query: dict):
    callback_id = callback_query["id"]
    logger.info("Callback query received", callback_id=callback_id, action="callback_query")
    answer_callback_query(callback_id)


# ========= LAMBDA HANDLER =========


def lambda_handler(event, context):
    """
    Main Lambda handler.
    - Text messages → Saved to DynamoDB
    - Media files → Uploaded to S3, metadata saved to DynamoDB
    """
    
    # Generate request_id from Lambda context
    request_id = context.request_id if hasattr(context, 'request_id') else 'local-test'
    function_name = context.function_name if hasattr(context, 'function_name') else 'unknown'
    
    # Set context for all logs in this request
    logger.set_context(request_id=request_id)
    
    logger.info("Lambda invocation started", 
                aws_request_id=request_id,
                function_name=function_name)

    if not TELEGRAM_BOT_TOKEN:
        logger.error("Missing TELEGRAM_BOT_TOKEN", outcome="failure")
        return {
            "statusCode": 500,
            "body": json.dumps({"ok": False, "error": "Missing TELEGRAM_BOT_TOKEN"}),
        }

    try:
        body = event.get("body") or "{}"
        update = json.loads(body)
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON body", error=e, outcome="failure")
        return {"statusCode": 400, "body": "Invalid JSON"}

    if "callback_query" in update:
        handle_callback_query(update["callback_query"])
    else:
        message = update.get("message") or update.get("edited_message")
        if not message:
            logger.warning("No message found in update", outcome="skipped")
            return {"statusCode": 200, "body": json.dumps({"ok": True})}

        chat = message.get("chat", {})
        chat_id = chat.get("id")
        text = message.get("text", "")
        message_id = message.get("message_id")
        from_user = message.get("from", {}) or {}
        first_name = from_user.get("first_name") or from_user.get("username") or None

        if chat_id is None:
            logger.warning("No chat_id found", outcome="skipped")
            return {"statusCode": 200, "body": json.dumps({"ok": True})}

        # Set user context for all subsequent logs
        logger.set_context(user_id=chat_id, message_id=message_id)
        
        logger.info("Processing message from user", 
                   chat_id=chat_id, 
                   message_id=message_id,
                   username=first_name)

        # Determine message type
        message_type = "text"
        if "photo" in message:
            message_type = "photo"
        elif "document" in message:
            message_type = "document"
        elif "voice" in message:
            message_type = "voice"
        elif "video" in message:
            message_type = "video"
        elif "audio" in message:
            message_type = "audio"

        logger.info("Message type detected", message_type=message_type)

        # Handle different message types
        try:
            if message_type == "photo":
                handle_photo(chat_id, message)
            elif message_type == "document":
                handle_document(chat_id, message)
            elif message_type == "voice":
                handle_voice(chat_id, message)
            elif message_type == "video":
                handle_video(chat_id, message)
            elif message_type == "audio":
                handle_audio(chat_id, message)
            elif text:
                # Save ALL text messages to DynamoDB
                if message_id is not None:
                    try:
                        save_message_record(chat_id, message_id, text, message_type="text")
                    except Exception as e:
                        logger.error("Error saving message record to DynamoDB", error=e, outcome="failure")
                
                # Handle command
                handle_text_message(chat_id, message_id, text, first_name)
            else:
                logger.warning("Unknown message type", outcome="skipped")
                send_message(chat_id, "I can handle text, photos, documents, videos, audio, and voice messages!")
        
        except Exception as e:
            logger.error("Error processing message", error=e, message_type=message_type, outcome="failure")
            send_message(chat_id, "❌ An error occurred while processing your message. Please try again.")

    logger.info("Lambda invocation completed", outcome="success")
    logger.clear_context()

    return {
        "statusCode": 200,
        "body": json.dumps({"ok": True}),
    }