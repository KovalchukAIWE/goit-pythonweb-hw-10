# app/main.py
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
from datetime import timedelta
import os
import time

from app import models, schemas, crud, auth
from app.database import SessionLocal, engine
import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv

# Завантаження змінних середовища
load_dotenv()

# Налаштування Cloudinary
cloudinary.config(
  cloud_name = os.getenv("CLOUDINARY_CLOUD_NAME"),
  api_key = os.getenv("CLOUDINARY_API_KEY"),
  api_secret = os.getenv("CLOUDINARY_API_SECRET")
)

# Створення таблиць
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Contact API",
    description="REST API для зберігання та управління контактами",
    version="1.0.0"
)

# Увімкнення CORS (будь ласка, обмеж у production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency для бази даних
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Проста in-memory система rate limiting для /me (5 запитів за 60 секунд)
user_requests = {}
RATE_LIMIT = 5  # максимальна кількість запитів
TIME_WINDOW = 60  # секунд

def rate_limit(request: Request):
    client_ip = request.client.host
    current_time = time.time()
    if client_ip not in user_requests:
        user_requests[client_ip] = []
    # Очищення старих запитів
    user_requests[client_ip] = [timestamp for timestamp in user_requests[client_ip] if current_time - timestamp < TIME_WINDOW]
    if len(user_requests[client_ip]) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many requests")
    user_requests[client_ip].append(current_time)

# --- Ендпоінти аутентифікації ---

# Реєстрація користувача. Якщо користувач з таким email вже існує - повернути 409 Conflict.
@app.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=409, detail="User with this email already exists")
    new_user = crud.create_user(db, user)
    # Тут можна додати відправку листа для верифікації через background task
    return new_user

# Логін користувача (отримання JWT access_token)
@app.post("/token", response_model=schemas.Token)
def login(login_data: schemas.Login, db: Session = Depends(get_db)):
    user = crud.authenticate_user(db, email=login_data.email, password=login_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=crud.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = crud.create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# Захищений маршрут для отримання даних поточного користувача, з rate limiting
@app.get("/me", response_model=schemas.UserOut)
def read_me(current_user: models.User = Depends(auth.get_current_active_user), request: Request = None, _: None = Depends(rate_limit)):
    return current_user

# Ендпоінт для оновлення аватара користувача з використанням Cloudinary
@app.post("/me/avatar", response_model=schemas.UserOut)
def update_avatar(file: UploadFile = File(...), current_user: models.User = Depends(auth.get_current_active_user), db: Session = Depends(get_db)):
    result = cloudinary.uploader.upload(file.file)
    current_user.avatar_url = result.get("secure_url")
    db.commit()
    db.refresh(current_user)
    return current_user

# Ендпоінт для верифікації електронної пошти (симуляція)
@app.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    # У реальному застосунку потрібно розшифрувати token та знайти користувача
    # Для демонстрації використаємо token як email
    user = crud.get_user_by_email(db, email=token)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")
    user.is_verified = True
    db.commit()
    return {"detail": "Email verified successfully"}

# --- Ендпоінти для контактів (тільки для автентифікованих користувачів) ---

@app.post("/contacts/", response_model=schemas.ContactOut, status_code=status.HTTP_201_CREATED)
def create_contact(contact: schemas.ContactCreate, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    return crud.create_contact(db, contact, current_user.id)

@app.get("/contacts/", response_model=List[schemas.ContactOut])
def read_contacts(
    skip: int = 0,
    limit: int = 100,
    query: str = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    if query:
        contacts = crud.search_contacts(db, current_user.id, query)
    else:
        contacts = crud.get_contacts(db, current_user.id, skip=skip, limit=limit)
    return contacts

@app.get("/contacts/{contact_id}", response_model=schemas.ContactOut)
def read_contact(contact_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    db_contact = crud.get_contact(db, current_user.id, contact_id)
    if not db_contact:
        raise HTTPException(status_code=404, detail="Контакт не знайдено")
    return db_contact

@app.put("/contacts/{contact_id}", response_model=schemas.ContactOut)
def update_contact(contact_id: int, contact: schemas.ContactUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    db_contact = crud.update_contact(db, current_user.id, contact_id, contact)
    if not db_contact:
        raise HTTPException(status_code=404, detail="Контакт не знайдено")
    return db_contact

@app.delete("/contacts/{contact_id}")
def delete_contact(contact_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    db_contact = crud.delete_contact(db, current_user.id, contact_id)
    if not db_contact:
        raise HTTPException(status_code=404, detail="Контакт не знайдено")
    return {"detail": "Контакт видалено"}

@app.get("/contacts/birthdays/", response_model=List[schemas.ContactOut])
def read_birthdays(days: int = 7, db: Session = Depends(get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    return crud.get_birthdays(db, current_user.id, days)
