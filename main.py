from datetime import date, datetime, timedelta
from importlib.metadata import metadata
from typing import List, Optional

import databases
import sqlalchemy
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from fastapi.openapi.utils import get_openapi
from passlib.context import CryptContext
from pydantic import BaseModel
import os
import uvicorn

SECRET_KEY = "c4e82df7988bf8f3f06bba53dc8e8a5eb4684ee055603e01d685fb49feb28064"
ALGORITHM = "HS256"
EXPIRE_TIME = 90

DATABASE_URL = os.environ['DATABASE_URL']

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

class LoginJson(BaseModel):
    username: str
    password: str

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
    comment_id: Optional[int]

class Comment(BaseModel):
    id: int
    text: str
    user_id: int
    post_id: int
    comment_id: Optional[int]|None

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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

async def get_user_by_id(user_id: int):
    query = users.select().where(users.c.id == user_id)
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
        username: str = payload.get("sub")
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

@app.get("/", tags=["Wellcome"])
async def hello():
    return {
        "message": "Ohhh! Hello there! ;)"
    }

# Auth
@app.post("/auth/register", response_model=UserInfo, tags=["Auth"])
async def register(data: LoginJson):
    if data.username == "":
        raise HTTPException(status_code=400, detail="Username is empty")
    if data.password == "":
        raise HTTPException(status_code=400, detail="Password is empty")
    
    query = users.insert().values(
        username = data.username,
        name = "",
        birthday = date.min,
        password = get_password_hash(data.password),
        disabled = 0
    )
    
    try:
        user = await get_user(data.username)
    except HTTPException:
        id_return = await database.execute(query)
        return {
            "id": id_return, 
            "username": data.username,
            "name": "",
            "birthday": date.min,
            "disabled": 0
        }
    else:
        raise HTTPException(status_code=400, detail="User already exists")
   
@app.post("/auth/login", response_model=Token, tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username == "":
        raise HTTPException(status_code=400, detail="Username is empty")
    if form_data.password == "":
        raise HTTPException(status_code=400, detail="Password is empty")

    user = await authenticate_user(username=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.disabled == True:
        raise HTTPException(
            status_code=400,
            detail="Disabled user",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/jsonLogin", response_model=Token, tags=["Auth"])
async def login(data: LoginJson):
    if data.username == "":
        raise HTTPException(status_code=400, detail="Username is empty")
    if data.password == "":
        raise HTTPException(status_code=400, detail="Password is empty")

    user = await authenticate_user(username=data.username, password=data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.disabled == True:
        raise HTTPException(
            status_code=400,
            detail="Disabled user",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

# Posts
@app.get("/posts", response_model=List[Post], tags=["Posts"])
async def read_posts(current_user: User = Depends(get_current_active_user)):
    query = posts.select().order_by(posts.c.id.desc())
    result = await database.fetch_all(query)
    if result == None:
        raise HTTPException(status_code=404, detail="No posts found")
    return result

@app.post("/posts", response_model=Post, tags=["Posts"])
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

@app.put("/posts", response_model=Post, tags=["Posts"])
async def update_post(post: Post, current_user: User = Depends(get_current_active_user)):
    query = posts.update().where(posts.c.id == post.id).values(
        header=post.header, 
        body=post.body, 
        user_id=current_user.id
    )
    await database.execute(query)
    query = posts.select().where(posts.c.id == post.id)
    return await database.fetch_one(query)

@app.delete("/posts/{id}", response_model=bool, tags=["Posts"])
async def delete_post(id: int, current_user: User = Depends(get_current_active_user)):
    query = posts.delete().where(posts.c.id == id, posts.c.user_id == current_user.id)
    return await database.execute(query)

# Comments
@app.get("/posts/{id}/comments", response_model=List[Comment], tags=["Comments"])
async def read_coments_in_post(id:int, current_user: User = Depends(get_current_active_user)):
    query = comments.select()\
        .where(comments.c.post_id == id)\
        .order_by(comments.c.id)
    return await database.fetch_all(query)

@app.post("/posts/{id}/comments", response_model=Comment, tags=["Comments"])
async def create_comment_in_post(id:int, comment: CommentIn, current_user: User = Depends(get_current_active_user)):
    comment_id = None
    if comment.comment_id:
        comment_id = comment.comment_id
    query = comments.insert().values(
        text=comment.text,
        user_id=current_user.id,
        post_id=id,
        comment_id=comment_id
    )
    id_return = await database.execute(query)
    query = comments.select().where(comments.c.id == id_return)
    return await database.fetch_one(query)

@app.get("/posts/user/{username}", response_model=List[Post], tags=["Posts"])
async def get_users_all_posts(username: str, current_user: User = Depends(get_current_active_user)):
    query = users.select().where(users.c.username == username)
    result = await database.fetch_one(query)
    if result == None:
        raise HTTPException(status_code=404, detail="User not found")
    query = posts.select()\
        .where(posts.c.user_id == result.id)\
        .order_by(posts.c.id.desc())
    result = await database.fetch_all(query)
    if result == None:
        raise HTTPException(status_code=404, detail="No posts found")
    return result

@app.get("/comments/{id}", response_model=Comment, tags=["Comments"])
async def read_comment(id:int, current_user: User = Depends(get_current_active_user)):
    query = comments.select().where(comments.c.id == id)
    result = await database.fetch_one(query)
    if result == None:
        raise HTTPException(status_code=404, detail="Comment not found")
    return result

@app.put("/comments", response_model=Comment, tags=["Comments"])
async def update_comment(comment: Comment, current_user: User = Depends(get_current_active_user)):
    query = comments.update().where(comments.c.id == comment.id).values(
        text=comment.text,
        user_id=current_user.id
    )
    await database.execute(query)
    query = comments.select().where(comments.c.id == comment.id)
    return await database.fetch_one(query)

@app.delete("/comments/{id}", response_model=None, tags=["Comments"])
async def delete_comment(id:int, current_user: User = Depends(get_current_active_user)):
    query = comments.delete().where(comments.c.id == id).where(comments.c.user_id == current_user.id)
    return await database.execute(query)

# Users
@app.get("/users", response_model=List[UserInfo], tags=["Users"])
async def read_users(current_user: User = Depends(get_current_active_user)):
    query = sqlalchemy.select(
            users.c.id, 
            users.c.username, 
            users.c.name, 
            users.c.birthday
        ).where(users.c.disabled.is_not(True))
    result = await database.fetch_all(query)
    if result == None:
        raise HTTPException(status_code=404, detail="No users found")
    return result

@app.get("/users/{username}", response_model=UserInfo, tags=["Users"])
async def read_user_by_username(username: str, current_user: User = Depends(get_current_active_user)):
    query = sqlalchemy.select(
            users.c.id, 
            users.c.username, 
            users.c.name, 
            users.c.birthday
        ).where(users.c.username == username)\
        .where(users.c.disabled.is_not(True))
    result = await database.fetch_one(query)
    if result == None:
        raise HTTPException(status_code=404, detail="User not found")
    return result

@app.get("/users/id/{id}", tags=["Users"])
async def read_user_by_id(id: int, current_user: User = Depends(get_current_active_user)):
    query = sqlalchemy.select(
            users.c.id, 
            users.c.username, 
            users.c.name, 
            users.c.birthday
        ).where(users.c.id == id)\
        .where(users.c.disabled.is_not(True))
    result = await database.fetch_one(query)
    if result == None:
        raise HTTPException(status_code=404, detail="User not found")
    return result

@app.put("/users", response_model=bool, tags=["Users"])
async def update_my_user(user: UserIn, current_user: User = Depends(get_current_active_user)):
    query = users.update()\
        .where(users.c.id == current_user.id)\
        .values(
            name = user.name,
            birthday = user.birthday
        )
    return await database.execute(query)

@app.delete("/users", response_model=bool, tags=["Users"])
async def delete_my_user(current_user: User = Depends(get_current_active_user)):
    query = users.update()\
        .where(users.c.id == current_user.id)\
        .values(
            disabled=True
        )
    return await database.execute(query)

# Search
@app.get("/search", response_model=List[UserInfo], tags=["Search"])
async def search(q: str, current_user: User = Depends(get_current_active_user)):
    if q == "":
        return []
    query = sqlalchemy.select(
            users.c.id, 
            users.c.username, 
            users.c.name, 
            users.c.birthday
        ).where(users.c.username.ilike(f"%{q}%"))\
        .where(users.c.disabled.is_not(True))\
        .order_by(users.c.username.asc())
    result = await database.fetch_all(query)
    if result == None:
        raise HTTPException(status_code=404, detail="No results found")
    return result

##############
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Birt Social Network API",
        version="3.1.0",
        description="This is a backend Rest API service for an assingment made by <a href='https://github.com/MikelMC96byte' target='_blank'>Mikel Maldonado</a>",
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")