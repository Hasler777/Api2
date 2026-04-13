import hmac
import hashlib
import time
import uuid
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Cookie, Header, Response
from pydantic import ValidationError

from models import UserCreate, LoginData, CommonHeaders

app = FastAPI()

SECRET_KEY = "supersecretkey_krutov_2026"


fake_users = {
    "user123": {
        "username": "user123",
        "password": "password123",
        "user_id": str(uuid.uuid4()),
        "name": "Ivan Krutov",
        "email": "krutov@example.com",
    }
}


sessions: dict = {}


sample_product_1 = {
    "product_id": 123,
    "name": "Smartphone",
    "category": "Electronics",
    "price": 599.99,
}
sample_product_2 = {
    "product_id": 456,
    "name": "Phone Case",
    "category": "Accessories",
    "price": 19.99,
}
sample_product_3 = {
    "product_id": 789,
    "name": "Iphone",
    "category": "Electronics",
    "price": 1299.99,
}
sample_product_4 = {
    "product_id": 101,
    "name": "Headphones",
    "category": "Accessories",
    "price": 99.99,
}
sample_product_5 = {
    "product_id": 202,
    "name": "Smartwatch",
    "category": "Electronics",
    "price": 299.99,
}

sample_products = [
    sample_product_1,
    sample_product_2,
    sample_product_3,
    sample_product_4,
    sample_product_5,
]




def _sign(data: str) -> str:
    return hmac.new(
        SECRET_KEY.encode(), data.encode(), hashlib.sha256
    ).hexdigest()


def create_session_token(user_id: str, timestamp: float) -> str:
    payload = f"{user_id}.{int(timestamp)}"
    signature = _sign(payload)
    return f"{payload}.{signature}"


def verify_session_token(token: str) -> Optional[dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    user_id, ts_str, signature = parts
    try:
        ts = int(ts_str)
    except ValueError:
        return None
    expected = _sign(f"{user_id}.{ts_str}")
    if not hmac.compare_digest(signature, expected):
        return None
    return {"user_id": user_id, "timestamp": ts}


def _find_user_by_id(user_id: str) -> Optional[dict]:
    for u in fake_users.values():
        if u["user_id"] == user_id:
            return u
    return None



@app.post("/create_user")
def create_user(user: UserCreate):
    return user.model_dump()




@app.get("/product/{product_id}")
def get_product(product_id: int):
    for p in sample_products:
        if p["product_id"] == product_id:
            return p
    raise HTTPException(status_code=404, detail="Product not found")


@app.get("/products/search")
def search_products(
    keyword: str,
    category: Optional[str] = None,
    limit: int = 10,
):
    results = []
    for p in sample_products:
        if keyword.lower() in p["name"].lower():
            if category is None or p["category"].lower() == category.lower():
                results.append(p)
    return results[:limit]




@app.post("/login")
def login(data: LoginData, response: Response):
    user = fake_users.get(data.username)
    if not user or user["password"] != data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

   
    ts = time.time()
    signed_token = create_session_token(user["user_id"], ts)

    # сохраняем в простое хранилище для /user (5.1)
    sessions[signed_token] = user

    response.set_cookie(
        key="session_token",
        value=signed_token,
        httponly=True,
        max_age=300,
    )
    return {"message": "Login successful"}


@app.get("/user")
def get_user(session_token: Optional[str] = Cookie(None)):
    """Задание 5.1 — базовая проверка cookie."""
    if not session_token:
        raise HTTPException(status_code=401, detail="Unauthorized")

  
    user = sessions.get(session_token)
    if user:
        return {"name": user["name"], "email": user["email"]}

    # Пробуем подписанный токен
    token_data = verify_session_token(session_token)
    if token_data:
        user_info = _find_user_by_id(token_data["user_id"])
        if user_info:
            return {"name": user_info["name"], "email": user_info["email"]}

    raise HTTPException(status_code=401, detail="Unauthorized")



@app.get("/profile")
def get_profile(
    response: Response,
    session_token: Optional[str] = Cookie(None),
):
    if not session_token:
        response.status_code = 401
        return {"message": "Unauthorized"}

    token_data = verify_session_token(session_token)
    if not token_data:
        response.status_code = 401
        return {"message": "Invalid session"}

    user_id = token_data["user_id"]
    last_activity = token_data["timestamp"]
    now = time.time()
    elapsed = now - last_activity

    user_info = _find_user_by_id(user_id)
    if not user_info:
        response.status_code = 401
        return {"message": "Unauthorized"}

   
    if elapsed > 300: 
        response.status_code = 401
        response.delete_cookie("session_token")
        return {"message": "Session expired"}

    if 180 <= elapsed < 300:  # 3–5 мин — продлеваем
        new_token = create_session_token(user_id, now)
        sessions[new_token] = user_info
        response.set_cookie(
            key="session_token",
            value=new_token,
            httponly=True,
            max_age=300,
        )
   

    return {
        "user_id": user_id,
        "name": user_info["name"],
        "email": user_info["email"],
    }



@app.get("/headers")
def get_headers(
    user_agent: Optional[str] = Header(None),
    accept_language: Optional[str] = Header(None),
):
    if not user_agent or not accept_language:
        raise HTTPException(
            status_code=400, detail="Missing required headers"
        )

    try:
        headers = CommonHeaders(
            user_agent=user_agent, accept_language=accept_language
        )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "User-Agent": headers.user_agent,
        "Accept-Language": headers.accept_language,
    }


@app.get("/info")
def get_info(
    response: Response,
    user_agent: Optional[str] = Header(None),
    accept_language: Optional[str] = Header(None),
):
    if not user_agent or not accept_language:
        raise HTTPException(
            status_code=400, detail="Missing required headers"
        )

    try:
        headers = CommonHeaders(
            user_agent=user_agent, accept_language=accept_language
        )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    response.headers["X-Server-Time"] = datetime.now().strftime(
        "%Y-%m-%dT%H:%M:%S"
    )

    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": headers.user_agent,
            "Accept-Language": headers.accept_language,
        },
    }
