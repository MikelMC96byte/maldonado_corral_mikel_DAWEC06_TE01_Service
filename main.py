from datetime import date, datetime, timedelta
from importlib.metadata import metadata
from typing import List

import databases
import sqlalchemy
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from fastapi.openapi.utils import get_openapi
from passlib.context import CryptContext
from pydantic import BaseModel

SECRET_KEY = "c4e82df7988bf8f3f06bba53dc8e8a5eb4684ee055603e01d685fb49feb28064"
ALGORITHM = "HS256"
EXPIRE_TIME = 90

DATABASE_URL = "postgres://cducnogizlpzlu:6b2ec904c29a4ebfb1cd20ac753912b7b0008cc2285f48c9352aaf7068339d9f@ec2-99-80-170-190.eu-west-1.compute.amazonaws.com:5432/d6nggklh02cp6c"

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True),
    sqlalchemy.Column("name", sqlalchemy.String),
    sqlalchemy.Column("birthday", sqlalchemy.Date),
    sqlalchemy.Column("disabled", sqlalchemy.Boolean, default=False),
    sqlalchemy.Column("password", sqlalchemy.String)
)

posts = sqlalchemy.Table(
    "posts",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("header", sqlalchemy.String),
    sqlalchemy.Column("body", sqlalchemy.String),
    sqlalchemy.Column("user_id", sqlalchemy.Integer),
    sqlalchemy.ForeignKeyConstraint(['user_id'], ['users.id'])
)

'''
posts_likes = sqlalchemy.Table(
    "posts_likes",
    metadata,
    sqlalchemy.Column("user_id", sqlalchemy.Integer),
    sqlalchemy.Column("post_id", sqlalchemy.Integer),
    sqlalchemy.ForeignKeyConstraint(['user_id'], ['users.id']),
    sqlalchemy.ForeignKeyConstraint(['post_id'], ['posts.id'])
)
'''

comments = sqlalchemy.Table(
    "comments",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("text", sqlalchemy.String),
    sqlalchemy.Column("user_id", sqlalchemy.Integer),
    sqlalchemy.Column("post_id", sqlalchemy.Integer),
    sqlalchemy.Column("comment_id", sqlalchemy.Integer),
    sqlalchemy.ForeignKeyConstraint(['user_id'], ['users.id']),
    sqlalchemy.ForeignKeyConstraint(['post_id'], ['posts.id'])
)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str

class UserIn(BaseModel):
    username: str
    name: str
    birthday: date

class UserInfo(BaseModel):
    id: int
    username: str
    name: str
    birthday: date

class User(BaseModel):
    id: int
    username: str
    password: str
    name: str
    birthday: date
    disabled: bool

class PostIn(BaseModel):
    header: str
    body: str

class Post(BaseModel):
    id: int
    header: str
    body: str
    user_id: int

class CommentIn(BaseModel):
    text: str
    post_id: int
    comment_id: int

class Comment(BaseModel):
    id: int
    text: str
    user_id: int
    post_id: int
    comment_id: int

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

async def get_user(username: str):
    query = users.select().where(users.c.username == username)
    user = await database.fetch_one(query)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return User(
        id=user.id,
        username=user.username,
        password=user.password,
        name=user.name,
        birthday=user.birthday,
        disabled=user.disabled
    )

async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=EXPIRE_TIME)

    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Validation incorrect",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise HTTPException(401, detail="User")
            #raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise HTTPException(401, detail=JWTError)
        #raise credentials_exception
    user = await get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Disabled user")
    return current_user

# App events
@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# Auth
@app.post("/auth/register", tags=["Auth"])
async def register(username: str, password: str):
    query = users.insert().values(
        username = username,
        name = "",
        birthday = date.min,
        password = get_password_hash(password),
        disabled = 0
    )
    id_return = await database.execute(query)
    return {
        "id": id_return, 
        "username": username,
        "name": "",
        "birthday": date.min,
        "disabled": 0
    }

@app.post("/auth/login", tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(username=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_token(data={"username": user.username})
    return {"access_token": token, "token_type": "bearer"}

# Posts
@app.get("/posts/", response_model=List[Post], tags=["Posts"])
async def read_posts(current_user: User = Depends(get_current_active_user)):
    query = posts.select()
    result = await database.fetch_all(query)
    if result == None:
        raise HTTPException(status_code=404, detail="No posts found")
    return result

@app.post("/posts/", response_model=Post, tags=["Posts"])
async def create_post(post: PostIn, current_user: User = Depends(get_current_active_user)):
    query = posts.insert().values(
        header=post.header, 
        body=post.body, 
        user_id=current_user.id
    )
    id_return = await database.execute(query)
    query = posts.select().where(posts.c.id == id_return)
    return await database.fetch_one(query)

@app.get("/posts/{id}", response_model=Post, tags=["Posts"])
async def read_post(id: int, current_user: User = Depends(get_current_active_user)):
    query = posts.select().where(posts.c.id == id)
    result = await database.fetch_one(query)
    if result == None:
        raise HTTPException(status_code=404, detail="Post not found")
    return result

@app.delete("/posts/{id}", response_model=bool, tags=["Posts"])
async def delete_post(id: int, current_user: User = Depends(get_current_active_user)):
    query = posts.delete().where(posts.c.id == id, posts.c.user_id == current_user.id)
    return await database.execute(query)

# Users
@app.get("/users/", tags=["Users"])
async def read_users(current_user: User = Depends(get_current_active_user)):
    query = sqlalchemy.select(
            users.c.id, 
            users.c.username, 
            users.c.name, 
            users.c.birthday
        ).where(users.c.disabled.is_not(None))
    result = await database.fetch_all(query)
    if result == None:
        raise HTTPException(status_code=404, detail="No users found")
    return result

@app.get("/users/{id}", response_model=User, tags=["Users"])
async def read_any_user(id: int, current_user: User = Depends(get_current_active_user)):
    query = users.select().where(users.c.id == id)
    result = await database.fetch_one(query)
    if result == None:
        raise HTTPException(status_code=404, detail="User not found")
    return result

@app.get("/me", response_model=User, tags=["Users"])
async def read_my_user(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.put("/me", response_model=bool, tags=["Users"])
async def update_my_user(name: str, birthday: date, current_user: User = Depends(get_current_active_user)):
    query = users.update()\
        .where(users.c.id == current_user.id)\
        .values(
            name = name,
            birthday = birthday
        )
    return await database.execute(query)

@app.delete("/me", response_model=bool, tags=["Users"])
async def delete_my_user(current_user: User = Depends(get_current_active_user)):
    query = users.update()\
        .where(users.c.id == current_user.id)\
        .values(
            disabled=True
        )
    return await database.execute(query)

# Users & Posts
@app.get("/users/{id}/posts", response_model=List[Post], tags=["Users & Posts"])
async def get_users_all_posts(id: int, current_user: User = Depends(get_current_active_user)):
    query = posts.select()\
        .where(posts.c.user_id == id)
    result = await database.fetch_all(query)
    if result == None:
        raise HTTPException(status_code=404, detail="No posts found")
    return result

##############
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Blog API",
        version="3.1.0",
        description="This is my blog service for the backend",
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi