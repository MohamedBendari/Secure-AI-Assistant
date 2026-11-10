
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models import SecurityLog, User
from backend.security.authentication import get_current_user

from backend.security.prompt_security import detect_prompt_injection
from backend.security.content_safety import check_content_safety
from backend.security.output_protection import protect_output

from backend.ai.gemini_service import generate_ai_response


router = APIRouter(
    prefix="/chat",
    tags=["AI Chat Security"]
)


# ==============================
# Request Models
# ==============================

class PromptRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)


class ContentSafetyRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)


class OutputProtectionRequest(BaseModel):
    output: str = Field(min_length=1, max_length=10000)


class SecureChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)


# ==============================
# Security Log Helper
# ==============================

def save_security_log(
    db: Session,
    user_id: int,
    event_type: str,
    description: str,
    is_attack: bool = False
):
    security_log = SecurityLog(
        user_id=user_id,
        event_type=event_type,
        description=description[:500],
        is_attack=is_attack
    )

    db.add(security_log)
    db.commit()
    db.refresh(security_log)

    return security_log


# ==============================
# 1. Prompt Injection Detection
# ==============================

@router.post("/check-prompt")
def check_prompt(
    request: PromptRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = detect_prompt_injection(request.message)

    if result["is_suspicious"]:
        event_type = "PROMPT_INJECTION_BLOCKED"
        description = (
            "Potential prompt injection detected. "
            f"Matched rules: {', '.join(result['matched_patterns'])}"
        )
        status = "blocked"
    else:
        event_type = "PROMPT_CHECK_ALLOWED"
        description = "No known prompt injection pattern detected."
        status = "allowed"

    security_log = save_security_log(
        db,
        current_user.id,
        event_type,
        description,
        result["is_suspicious"]
    )

    return {
        "status": status,
        "security_check": result,
        "log_id": security_log.id,
        "message": "Security event recorded successfully"
    }


# ==============================
# 2. Get Security Logs
# ==============================

@router.get("/security-logs")
def get_security_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(default=50, ge=1, le=200)
):
    logs = (
        db.query(SecurityLog)
        .filter(SecurityLog.user_id == current_user.id)
        .order_by(desc(SecurityLog.created_at))
        .limit(limit)
        .all()
    )

    return {
        "total": len(logs),
        "logs": [
            {
                "id": log.id,
                "user_id": log.user_id,
                "event_type": log.event_type,
                "description": log.description,
                "is_attack": log.is_attack,
                "created_at": log.created_at
            }
            for log in logs
        ]
    }


# ==============================
# 3. Content Safety
# ==============================

@router.post("/check-content")
def check_content(
    request: ContentSafetyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = check_content_safety(request.message)

    if result["is_unsafe"]:
        event_type = "UNSAFE_CONTENT_BLOCKED"
        description = (
            f"Unsafe content detected. "
            f"Category: {result['category']}"
        )
        status = "blocked"
    else:
        event_type = "CONTENT_CHECK_ALLOWED"
        description = "No known unsafe content pattern detected."
        status = "allowed"

    security_log = save_security_log(
        db,
        current_user.id,
        event_type,
        description,
        result["is_unsafe"]
    )

    return {
        "status": status,
        "content_safety": result,
        "log_id": security_log.id,
        "message": "Security event recorded successfully"
    }


# ==============================
# 4. Output Protection
# ==============================

@router.post("/protect-output")
def protect_ai_output(
    request: OutputProtectionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = protect_output(request.output)

    if result["is_sensitive"]:
        event_type = "SENSITIVE_OUTPUT_REDACTED"
        description = (
            "Sensitive information detected and redacted. "
            f"Types: {', '.join(result['detected_types'])}"
        )
    else:
        event_type = "OUTPUT_CHECK_PASSED"
        description = "No known sensitive information detected."

    security_log = save_security_log(
        db,
        current_user.id,
        event_type,
        description,
        result["is_sensitive"]
    )

    return {
        "status": "protected" if result["is_sensitive"] else "safe",
        "output_protection": result,
        "log_id": security_log.id,
        "message": "Output security event recorded successfully"
    }


# ==============================
# 5. Complete Secure AI Chat
# ==============================

@router.post("/secure-chat")
def secure_chat(
    request: SecureChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    # STEP 1: Prompt Injection Detection

    prompt_result = detect_prompt_injection(request.message)

    if prompt_result["is_suspicious"]:

        log = save_security_log(
            db,
            current_user.id,
            "PROMPT_INJECTION_BLOCKED",
            "Prompt injection detected and blocked.",
            True
        )

        return {
            "status": "blocked",
            "stage": "prompt_security",
            "security_check": prompt_result,
            "log_id": log.id,
            "message": "Request blocked by Prompt Injection Detection."
        }

    # STEP 2: Content Safety

    content_result = check_content_safety(request.message)

    if content_result["is_unsafe"]:

        log = save_security_log(
            db,
            current_user.id,
            "UNSAFE_CONTENT_BLOCKED",
            f"Unsafe content detected. Category: {content_result['category']}",
            True
        )

        return {
            "status": "blocked",
            "stage": "content_safety",
            "content_safety": content_result,
            "log_id": log.id,
            "message": "Request blocked by Content Safety."
        }

    # STEP 3: Generate AI Response

    try:
        ai_response = generate_ai_response(request.message)

    except Exception:
        save_security_log(
            db,
            current_user.id,
            "AI_MODEL_ERROR",
            "Gemini API failed to generate a response.",
            False
        )

        raise HTTPException(
            status_code=502,
            detail="AI service is temporarily unavailable. Please try again."
        )

    # STEP 4: Output Protection

    output_result = protect_output(ai_response)

    if output_result["is_sensitive"]:

        event_type = "SENSITIVE_OUTPUT_REDACTED"
        description = (
            "Sensitive information detected and redacted. "
            f"Types: {', '.join(output_result['detected_types'])}"
        )

    else:

        event_type = "SECURE_CHAT_COMPLETED"
        description = "AI response passed output protection."

    log = save_security_log(
        db,
        current_user.id,
        event_type,
        description,
        output_result["is_sensitive"]
    )

    # STEP 5: Return Protected Response

    return {
        "status": "success",
        "user_message": request.message,
        "ai_response": output_result["protected_output"],
        "security": {
            "prompt_injection": "passed",
            "content_safety": "passed",
            "output_protection": (
                "redacted"
                if output_result["is_sensitive"]
                else "passed"
            )
        },
        "detected_sensitive_types": output_result["detected_types"],
        "log_id": log.id,
        "message": "Secure AI response generated successfully."
    }
