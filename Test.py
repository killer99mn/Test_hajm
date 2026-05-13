import os
import time
import shutil
from typing import List, Dict, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, UploadFile, File, Form
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from passlib.hash import bcrypt
from jose import jwt
from datetime import datetime, timedelta # Import timedelta
from PIL import Image # برای پردازش عکس

# --- Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY", "your_super_secret_key_change_me_to_something_very_long_and_random")
ALGO = "HS256"
DATABASE_URL = "sqlite:///./chat_app.db" # Use this for local testing
# For production, consider PostgreSQL: "postgresql://user:password@host:port/dbname"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "mp4", "mov", "txt", "pdf", "zip"}
MAX_IMAGE_SIZE = (300, 300) # Max size for profile picture thumbnail

# --- Database Setup ---
# Supports SQLite, PostgreSQL, MySQL etc.
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    profile_picture_url = Column(String, nullable=True)
    is_active = Column(Boolean, default=True) # Tracks if user is currently connected via WebSocket
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships for future features:
    messages = relationship("Message", back_populates="sender")
    chat_participants = relationship("ChatParticipant", back_populates="user")

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    chat_id = Column(Integer, ForeignKey("chats.id")) # The conversation this message belongs to
    message_type = Column(String, default="text") # e.g., "text", "image", "video", "audio", "file"
    file_url = Column(String, nullable=True) # Path to the uploaded file
    timestamp = Column(DateTime, default=datetime.utcnow)

    sender = relationship("User", back_populates="messages")
    chat = relationship("Chat", back_populates="messages")

class Chat(Base): # Represents a conversation: direct chat, group, or channel
    __tablename__ = "chats"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=True) # Name for groups/channels
    is_group = Column(Boolean, default=False)
    is_channel = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    messages = relationship("Message", back_populates="chat")
    chat_participants = relationship("ChatParticipant", back_populates="chat")

class ChatParticipant(Base): # Link table for many-to-many relationship between User and Chat
    __tablename__ = "chat_participants"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    chat_id = Column(Integer, ForeignKey("chats.id"))
    joined_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="chat_participants")
    chat = relationship("Chat", back_populates="chat_participants")

# Create database tables
Base.metadata.create_all(bind=engine)

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Dependency Injection ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Security Utilities ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGO)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGO])
        username = payload.get("sub")
        if username is None:
            return None
        return username
    except Exception as e:
        print(f"Token verification error: {e}")
        return None

# Dependency to get the current authenticated user
def get_current_user(token: str = Depends(verify_token), db: Session = Depends(get_db)) -> Optional[User]:
    if token is None:
        return None # Not authenticated
    user = db.query(User).filter(User.username == token).first()
    if not user:
        return None # User not found
    return user

# --- API Endpoints ---

@app.post("/register")
def register_user(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = bcrypt.hash(password)
    new_user = User(username=username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}

@app.post("/login")
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not bcrypt.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload_profile_picture")
async def upload_profile_picture(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Check file extension
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in {".png", ".jpg", ".jpeg", ".gif"}:
        raise HTTPException(status_code=400, detail="Invalid file type. Only images are allowed.")

    # Generate a unique filename
    filename = f"profile_{current_user.username}_{int(time.time())}{file_ext}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        # Read and save the file temporarily
        contents = await file.read()
        with open(filepath, "wb") as f:
            f.write(contents)

        # Process image: resize and save thumbnail
        img = Image.open(filepath)
        img.thumbnail(MAX_IMAGE_SIZE)
        img.save(filepath) # Overwrite with thumbnail

        # Remove old profile picture if exists
        if current_user.profile_picture_url and os.path.exists(current_user.profile_picture_url):
            try:
                os.remove(current_user.profile_picture_url)
            except OSError as e:
                print(f"Error removing old profile picture: {e}")

        # Update user's profile picture URL in DB
        current_user.profile_picture_url = filepath
        db.commit()
        db.refresh(current_user)

        return {"message": "Profile picture updated", "url": filepath}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not upload and process file: {e}")

@app.get("/users/me/profile")
def read_users_me(current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return {
        "username": current_user.username,
        "profile_picture_url": current_user.profile_picture_url,
        "is_active": current_user.is_active,
        "created_at": current_user.created_at
    }

# --- WebSocket Chat Logic ---
active_connections: Dict[str, WebSocket] = {} # {username: websocket_connection}
online_users_cache: Dict[str, Dict] = {} # Cache user details for broadcasting status

async def get_user_from_token_ws(token: str, db: Session) -> Optional[User]:
    """Helper to get user from token for WebSocket connections."""
    username = verify_token(token)
    if not username:
        return None
    user = db.query(User).filter(User.username == username).first()
    return user

async def broadcast_user_status(username: str, status: str, db: Session):
    """Broadcasts user online/offline status to all connected clients."""
    message = {"type": "user_status", "username": username, "status": status}

    # Update user's active status in DB
    user = db.query(User).filter(User.username == username).first()
    if user:
        user.is_active = (status == "online")
        db.commit()
        db.refresh(user)

    # Update cache
    if status == "online":
        user_details = db.query(User).filter(User.username == username).first()
        if user_details:
            online_users_cache[username] = {
                "username": username,
                "profile_url": user_details.profile_picture_url,
                "is_active": True
            }
    elif username in online_users_cache:
        del online_users_cache[username]

    # Send status to all currently connected clients
    for user_ws in active_connections.values():
        try:
            await user_ws.send_json(message)
        except Exception as e:
            print(f"Error sending status to a client: {e}")

@app.websocket("/ws/{token}")
async def websocket_endpoint(ws: WebSocket, token: str, db: Session = Depends(get_db)):
    user = await get_user_from_token_ws(token, db)
    if not user:
        await ws.close(code=1008, reason="Invalid token")
        return

    username = user.username
    active_connections[username] = ws
    print(f"User {username} connected.")

    # Inform the newly connected user about who else is online
    await ws.send_json({"type": "online_users_list", "users": list(online_users_cache.values())})
    await broadcast_user_status(username, "online", db) # Broadcast to everyone else that this user is now online

    try:
        while True:
            data = await ws.receive_json()
            msg_type = data.get("type")

            if msg_type == "send_message":
                content = data.get("content")
                target_username = data.get("to") # For direct chat (PV)
                chat_id = data.get("chat_id")    # For group/channel messages

                if not content: continue

                sender_db = db.query(User).filter(User.username == username).first()
                if not sender_db: continue # Should not happen if token is valid

                # --- Message Routing Logic ---
                if target_username: # Direct Message (PV)
                    recipient_ws = active_connections.get(target_username)
                    recipient_db = db.query(User).filter(User.username == target_username).first()

                    if not recipient_db:
                        await ws.send_json({"type": "error", "message": f"User {target_username} not found."})
                        continue

                    # Create or find a direct chat entry
                    # For simplicity, we'll assume a chat is created on the fly or fetched.
                    # A real implementation would manage direct chat relationships more robustly.
                    # We need a 'chat_id' for the Message model, so let's simulate finding/creating one.
                    direct_chat = db.query(Chat).filter(
                        Chat.is_group == False, Chat.is_channel == False,
                        Chat.name == None # Direct chats might not have names
                    ).join(ChatParticipant, Chat.id == ChatParticipant.chat_id).filter(
                        ChatParticipant.user_id == sender_db.id
                    ).join(ChatParticipant, Chat.id == ChatParticipant.chat_id).filter(
                        ChatParticipant.user_id == recipient_db.id
                    ).first()

                    if not direct_chat:
                        # Create a new direct chat if one doesn't exist
                        direct_chat = Chat()
                        db.add(direct_chat)
                        db.commit()
                        db.refresh(direct_chat)
                        # Add both users as participants
                        db.add(ChatParticipant(user_id=sender_db.id, chat_id=direct_chat.id))
                        db.add(ChatParticipant(user_id=recipient_db.id, chat_id=direct_chat.id))
                        db.commit()

                    message_to_save = Message(
                        content=content,
                        sender_id=sender_db.id,
                        chat_id=direct_chat.id,
                        message_type="text",
                        timestamp=datetime.utcnow()
                    )
                    db.add(message_to_save)
                    db.commit()
                    db.refresh(message_to_save)

                    # Send to sender
                    await ws.send_json({
                        "type": "message",
                        "chat_id": direct_chat.id,
                        "from": username,
                        "content": content,
                        "timestamp": message_to_save.timestamp.isoformat() + "Z",
                        "message_type": "text"
                    })

                    # Send to recipient if online
                    if recipient_ws:
                        await recipient_ws.send_json({
                            "type": "message",
                            "chat_id": direct_chat.id,
                            "from": username,
                            "content": content,
                            "timestamp": message_to_save.timestamp.isoformat() + "Z",
                            "message_type": "text"
                        })

                elif chat_id: # Group or Channel message
                    chat = db.query(Chat).filter(Chat.id == chat_id).first()
                    if not chat:
                        await ws.send_json({"type": "error", "message": f"Chat with ID {chat_id} not found."})
                        continue

                    # Verify user is a participant in this chat
                    participant = db.query(ChatParticipant).filter(
                        ChatParticipant.chat_id == chat_id,
                        ChatParticipant.user_id == sender_db.id
                    ).first()
                    if not participant:
                        await ws.send_json({"type": "error", "message": "You are not a member of this chat."})
                        continue

                    # Save message to DB
                    message_to_save = Message(
                        content=content,
                        sender_id=sender_db.id,
                        chat_id=chat_id,
                        message_type="text", # Default to text
                        timestamp=datetime.utcnow()
                    )
                    db.add(message_to_save)
                    db.commit()
                    db.refresh(message_to_save)

                    # Broadcast to all participants in the chat
                    chat_participants = db.query(ChatParticipant).filter(ChatParticipant.chat_id == chat_id).all()
                    for participant_link in chat_participants:
                        participant_user = db.query(User).filter(User.id == participant_link.user_id).first()
                        if participant_user and participant_user.username in active_connections:
                            await active_connections[participant_user.username].send_json({
                                "type": "message",
                                "chat_id": chat_id,
                                "from": username,
                                "content": content,
                                "timestamp": message_to_save.timestamp.isoformat() + "Z",
                                "message_type": "text" # For now, just text
                            })
                else:
                    await ws.send_json({"type": "error", "message": "Invalid message target (no 'to' or 'chat_id' provided)."})

            elif msg_type == "get_online_users":
                # Send the list of currently online users (from cache)
                await ws.send_json({"type": "online_users_list", "users": list(online_users_cache.values())})

            # --- Add more message types here for file uploads, creating groups/channels, etc. ---

    except WebSocketDisconnect:
        print(f"User {username} disconnected.")
        await broadcast_user_status(username, "offline", db)
        if username in active_connections:
            del active_connections[username]
        # User's is_active status is updated in broadcast_user_status
    except Exception as e:
        print(f"Error processing WebSocket for {username}: {e}")
        await ws.send_json({"type": "error", "message": f"An internal error occurred: {e}"})
        await broadcast_user_status(username, "offline", db) # Assume disconnected on error
        if username in active_connections:
            del active_connections[username]

# --- File Upload Endpoint ---
# Endpoint for uploading files (images, videos, general files) into a specific chat
@app.post("/upload_file/{chat_id}")
async def upload_chat_file(
    chat_id: int,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # 1. Check if user is a participant in the chat
    participant = db.query(ChatParticipant).filter(
        ChatParticipant.chat_id == chat_id,
        ChatParticipant.user_id == current_user.id
    ).first()
    if not participant:
        raise HTTPException(status_code=403, detail="You are not a member of this chat.")

    # 2. Validate file type
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="File type not allowed.")

    # Determine message type
    message_type = "file"
    if file_ext in {".png", ".jpg", ".jpeg", ".gif"}:
        message_type = "image"
    elif file_ext in {".mp4", ".mov"}:
        message_type = "video"
    elif file_ext in {".mp3", ".wav", ".ogg"}: # Add audio types if needed
        message_type = "audio"

    # 3. Save the file
    filename = f"{chat_id}_{current_user.username}_{int(time.time())}{file_ext}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    try:
        with open(filepath, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # 4. Save message to DB
        new_message = Message(
            content=file.filename, # Use filename as content for display
            sender_id=current_user.id,
            chat_id=chat_id,
            message_type=message_type,
            file_url=filepath,
            timestamp=datetime.utcnow()
        )
        db.add(new_message)
        db.commit()
        db.refresh(new_message)

        # 5. Notify chat participants via WebSocket
        chat_participants_links = db.query(ChatParticipant).filter(ChatParticipant.chat_id == chat_id).all()
        for participant_link in chat_participants_links:
            participant_user = db.query(User).filter(User.id == participant_link.user_id).first()
            if participant_user and participant_user.username in active_connections:
                await active_connections[participant_user.username].send_json({
                    "type": "message",
                    "chat_id": chat_id,
                    "from": current_user.username,
                    "content": file.filename,
                    "message_type": message_type,
                    "file_url": filepath, # Send the path for the client to display/download
                    "timestamp": new_message.timestamp.isoformat() + "Z"
                })

        return {"message": "File uploaded successfully", "file_url": filepath}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not upload file: {e}")

# --- Placeholder Endpoints for Group/Channel Creation ---
# These are simplified examples. A full implementation would need more logic.

@app.post("/create_chat")
async def create_chat(
    name: str = Form(None), # Optional name for groups/channels
    is_group: bool = Form(False),
    is_channel: bool = Form(False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")
    if not is_group and not is_channel:
        raise HTTPException(status_code=400, detail="Chat must be a group or channel.")
    if not name and (is_group or is_channel):
        raise HTTPException(status_code=400, detail="Group/Channel name is required.")

    new_chat = Chat(name=name, is_group=is_group, is_channel=is_channel)
    db.add(new_chat)
    db.commit()
    db.refresh(new_chat)

    # Add the creator as the first participant
    participant = ChatParticipant(user_id=current_user.id, chat_id=new_chat.id)
    db.add(participant)
    db.commit()

    return {"message": f"{'Group' if is_group else 'Channel'} created successfully", "chat_id": new_chat.id, "name": name}

@app.post("/add_participant/{chat_id}")
async def add_participant_to_chat(
    chat_id: int,
    username_to_add: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Check if the current user is an admin/creator (logic to be added for admin roles)
    # For now, allow any participant to add others (simplified)
    is_participant = db.query(ChatParticipant).filter(
        ChatParticipant.chat_id == chat_id,
        ChatParticipant.user_id == current_user.id
    ).first()
    if not is_participant:
        raise HTTPException(status_code=403, detail="You are not a member of this chat.")

    user_to_add = db.query(User).filter(User.username == username_to_add).first()
    if not user_to_add:
        raise HTTPException(status_code=404, detail="User to add not found.")

    # Check if already a participant
    existing_participant = db.query(ChatParticipant).filter(
        ChatParticipant.chat_id == chat_id,
        ChatParticipant.user_id == user_to_add.id
    ).first()
    if existing_participant:
        raise HTTPException(status_code=400, detail="User is already in this chat.")

    new_participant = ChatParticipant(user_id=user_to_add.id, chat_id=chat_id)
    db.add(new_participant)
    db.commit()

    # Notify the added user (if they are online) and other chat members
    chat = db.query(Chat).filter(Chat.id == chat_id).first()
    if chat:
        added_user_ws = active_connections.get(user_to_add.username)
        if added_user_ws:
            await added_user_ws.send_json({
                "type": "chat_added",
                "chat_id": chat_id,
                "chat_name": chat.name,
                "message": f"You have been added to the {chat.name or 'chat'}."
            })

        # Broadcast to other members of the chat
        chat_members_links = db.query(ChatParticipant).filter(ChatParticipant.chat_id == chat_id).all()
        for member_link in chat_members_links:
            member_user = db.query(User).filter(User.id == member_link.user_id).first()
            if member_user and member_user.username in active_connections and member_user.username != user_to_add.username:
                await active_connections[member_user.username].send_json({
                    "type": "user_joined_chat",
                    "chat_id": chat_id,
                    "username": user_to_add.username,
                    "message": f"{user_to_add.username} has joined the chat."
                })

    return {"message": f"User {username_to_add} added to chat {chat_id}"}

# --- To run this server ---
# 1. Save this code as main.py
# 2. Install dependencies: pip install -r requirements.txt (if you create one) or run the pip install commands provided earlier.
# 3. Run the server: uvicorn main:app --reload --host 0.0.0.0 --port 8000
#    - Use --reload for development. Remove it for production.
#    - Ensure you change SECRET_KEY and potentially DATABASE_URL for production.
   
