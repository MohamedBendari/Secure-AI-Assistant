
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import UserPrivateData, User
from backend.schemas import PrivateDataCreate, PrivateDataResponse
from backend.security.authentication import get_current_user
from backend.security.encryption import encrypt_data, decrypt_data

router = APIRouter(
    prefix="/privacy",
    tags=["Data Protection"]
)


@router.post("/store", response_model=PrivateDataResponse)
def store_private_data(
    data: PrivateDataCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    encrypted_value = encrypt_data(data.sensitive_data)

    record = UserPrivateData(
        user_id=current_user.id,
        encrypted_value=encrypted_value
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "id": record.id,
        "message": "Sensitive data encrypted and stored successfully"
    }


@router.get("/read/{record_id}")
def read_private_data(
    record_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    record = db.query(UserPrivateData).filter(
        UserPrivateData.id == record_id,
        UserPrivateData.user_id == current_user.id
    ).first()

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Private record not found"
        )

    return {
        "id": record.id,
        "sensitive_data": decrypt_data(record.encrypted_value)
    }
