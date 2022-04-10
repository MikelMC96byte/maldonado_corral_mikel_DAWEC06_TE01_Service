from datetime import date
from importlib.metadata import metadata
from typing import List

import databases
import sqlalchemy
from fastapi import FastAPI
from pydantic import BaseModel


DATABASE_URL = "mysql://root:@localhost/app"

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True),
    sqlalchemy.Column("name", sqlalchemy.String),
    sqlalchemy.Column("birthday", sqlalchemy.Date),
    sqlalchemy.Column("disabled", sqlalchemy.Boolean, default=False)
)

posts = sqlalchemy.Table(
    "posts",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("header", sqlalchemy.String),
    sqlalchemy.Column("body", sqlalchemy.Text),
    sqlalchemy.Column("user_id", sqlalchemy.Integer),
    sqlalchemy.Column("likes", sqlalchemy.Integer, default=0),
    sqlalchemy.Column("dislikes", sqlalchemy.Integer, default=0),
    sqlalchemy.ForeignKeyConstraint(['user_id'], ['users.id'])
)

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
    sqlalchemy.Column("text", sqlalchemy.Text),
    sqlalchemy.Column("user_id", sqlalchemy.Integer),
    sqlalchemy.column("post_id", sqlalchemy.Integer),
    sqlalchemy.Column("comment_id", sqlalchemy.Integer),
    sqlalchemy.Column("likes", sqlalchemy.Integer, default=0),
    sqlalchemy.Column("dislikes", sqlalchemy.Integer, default=0),
    sqlalchemy.ForeignKeyConstraint(['user_id'], ['users.id']),
    sqlalchemy.ForeignKeyConstraint(['post_id'], ['posts.id'])
)
'''

class UserIn(BaseModel):
    username: str
    name: str
    birthday: date

class User(BaseModel):
    id: int
    username: str
    name: str
    birthday: date
    disabled: bool

class PostIn(BaseModel):
    header: str
    body: str
    user_id: int

class Post(BaseModel):
    id: int
    header: str
    body: str
    user_id: int
    likes: int
    dislikes: int

class CommentIn(BaseModel):
    text: str
    user_id: int
    post_id: int
    comment_id: int

class Comment(BaseModel):
    id: int
    text: str
    user_id: int
    post_id: int
    comment_id: int
    likes: int
    dislikes: int

class PostLike(BaseModel):
    user_id: int
    post_id: int

app = FastAPI()


@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


@app.get("/posts/", response_model=List[Post])
async def get_posts():
    query = posts.select()
    return await database.fetch_all(query)

@app.post("/posts/", response_model=Post)
async def create_post(post: PostIn):
    query = posts.insert().values(
        header=post.header, 
        body=post.body, 
        user_id=post.user_id,
        likes=0,
        dislikes=0
    )
    id_return = await database.execute(query)
    query = posts.select().where(posts.c.id == id_return)
    return await database.fetch_one(query)

@app.get("/posts/{id}", response_model=Post)
async def get_post(id: int):
    query = posts.select().where(posts.c.id == id)
    return await database.fetch_one(query)

@app.delete("/posts/{id}")
async def delete_post(id: int):
    query = posts.delete().where(posts.c.id == id)
    return await database.execute(query)

@app.put("/posts/{id}/like/{user_id}")
async def like_a_post(id: int, user_id: int):
    query = posts.select().where(posts.c.id == id)
    post = database.fetch_one(query)
    post.likes += 1
    query = posts.update()\
        .where(posts.c.id == id)\
        .values(likes = post.likes)
    return await database.execute(query)

@app.put("/posts/{id}/dislike/{user_id}")
async def dislike_a_post(id: int, user_id: int):
    query = posts.select().where(posts.c.id == id)
    post = database.fetch_one(query)
    post.dislikes += 1
    query = posts.update()\
        .where(posts.c.id == id)\
        .values(dislikes = post.dislikes)
    return await database.execute(query)

@app.get("/users/", response_model=List[User])
async def get_users():
    query = users.select()
    return await database.fetch_all(query)

@app.post("/users/", response_model=User)
async def create_users(user: UserIn):
    query = users.insert().values(
        username = user.username,
        name = user.name,
        birthday = user.birthday
    )
    id_return = await database.execute(query)
    return {**user.dict(), "id": id_return}

@app.get("/users/{id}", response_model=User)
async def get_user(id: int):
    query = users.select().where(users.id == id)
    return await database.fetch_one(query)

@app.put("/users/{id}", response_model=User)
async def update_user(id: int, user: UserIn):
    query = users.update()\
        .where(users.id == id)\
        .values(
            username = user.username,
            name = user.name,
            birthday = user.birthday
        )
    return await database.execute(query)

@app.delete("/users/{id}")
async def delete_user(id: int):
    query = users.update()\
        .where(users.id == id)\
        .values(
            disabled=True
        )
    return await database.execute(query)

@app.get("/users/{id}/posts")
async def get_users_all_posts(id: int):
    query = posts.select()\
        .where(posts.c.user_id == id)
    return await database.fetch_all(query)

