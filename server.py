from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# JWT Configuration
SECRET_KEY = os.environ.get('JWT_SECRET', 'nocodeapp-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

# Password hashing
# Use pbkdf2_sha256 to avoid bcrypt native backend issues in the dev environment
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Configure CORS - Allow all origins for mobile app access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===================== MODELS =====================

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    created_at: datetime

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class ComponentData(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str  # text, image, button, input, card, list, grid, form, gallery
    props: Dict[str, Any] = {}
    style: Dict[str, Any] = {}
    children: List[str] = []  # IDs of child components
    order: int = 0

class ScreenData(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    components: List[ComponentData] = []
    backgroundColor: str = "#ffffff"
    order: int = 0

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    template_id: Optional[str] = None

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    screens: Optional[List[ScreenData]] = None
    settings: Optional[Dict[str, Any]] = None

class ProjectResponse(BaseModel):
    id: str
    user_id: str
    name: str
    description: str
    screens: List[ScreenData]
    settings: Dict[str, Any]
    template_id: Optional[str]
    created_at: datetime
    updated_at: datetime

class TemplateResponse(BaseModel):
    id: str
    name: str
    description: str
    category: str
    thumbnail: str
    screens: List[ScreenData]
    settings: Dict[str, Any]

# ===================== SMS/MMS FORWARDING SETTINGS MODELS =====================

class TelegramSettings(BaseModel):
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""
    forward_sms: bool = True
    forward_mms: bool = True
    include_sender_info: bool = True
    include_timestamp: bool = True

class EmailSettings(BaseModel):
    enabled: bool = False
    recipient_email: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    use_tls: bool = True
    forward_sms: bool = True
    forward_mms: bool = True
    include_sender_info: bool = True
    include_timestamp: bool = True
    email_subject_prefix: str = "[SMS/MMS Forward]"

class PhoneForwardingSettings(BaseModel):
    enabled: bool = False
    forward_to_number: str = ""
    forward_sms: bool = True
    forward_mms: bool = True
    include_original_sender: bool = True
    add_prefix_message: bool = True
    prefix_text: str = "Forwarded from: "

class ForwardingSettings(BaseModel):
    telegram: TelegramSettings = TelegramSettings()
    email: EmailSettings = EmailSettings()
    phone: PhoneForwardingSettings = PhoneForwardingSettings()

class ForwardingSettingsUpdate(BaseModel):
    telegram: Optional[TelegramSettings] = None
    email: Optional[EmailSettings] = None
    phone: Optional[PhoneForwardingSettings] = None

class ForwardingSettingsResponse(BaseModel):
    id: str
    user_id: str
    telegram: TelegramSettings
    email: EmailSettings
    phone: PhoneForwardingSettings
    updated_at: datetime

# ===================== HELPER FUNCTIONS =====================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def serialize_user(user: dict) -> UserResponse:
    return UserResponse(
        id=str(user["_id"]),
        email=user["email"],
        name=user["name"],
        created_at=user["created_at"]
    )

def serialize_project(project: dict) -> ProjectResponse:
    return ProjectResponse(
        id=str(project["_id"]),
        user_id=str(project["user_id"]),
        name=project["name"],
        description=project.get("description", ""),
        screens=[ScreenData(**s) for s in project.get("screens", [])],
        settings=project.get("settings", {}),
        template_id=project.get("template_id"),
        created_at=project["created_at"],
        updated_at=project["updated_at"]
    )

# ===================== DEFAULT TEMPLATES =====================

DEFAULT_TEMPLATES = [
    {
        "id": "task-manager",
        "name": "Task Manager",
        "description": "Organize your tasks with categories and priorities",
        "category": "business",
        "thumbnail": "task",
        "screens": [
            {
                "id": "home",
                "name": "Tasks",
                "backgroundColor": "#1a1a2e",
                "components": [
                    {"id": "1", "type": "heading", "props": {"text": "My Tasks", "level": 1}, "style": {"color": "#ffffff", "marginBottom": 20}, "children": [], "order": 0},
                    {"id": "2", "type": "card", "props": {"title": "Work", "subtitle": "5 tasks"}, "style": {"backgroundColor": "#16213e", "marginBottom": 12}, "children": [], "order": 1},
                    {"id": "3", "type": "card", "props": {"title": "Personal", "subtitle": "3 tasks"}, "style": {"backgroundColor": "#16213e", "marginBottom": 12}, "children": [], "order": 2},
                    {"id": "4", "type": "button", "props": {"text": "Add Task", "variant": "primary"}, "style": {"backgroundColor": "#e94560", "marginTop": 20}, "children": [], "order": 3}
                ],
                "order": 0
            }
        ],
        "settings": {"primaryColor": "#e94560", "theme": "dark"}
    },
    {
        "id": "notes-app",
        "name": "Notes",
        "description": "Simple and elegant note-taking app",
        "category": "personal",
        "thumbnail": "note",
        "screens": [
            {
                "id": "home",
                "name": "Notes",
                "backgroundColor": "#fef9ef",
                "components": [
                    {"id": "1", "type": "heading", "props": {"text": "Notes", "level": 1}, "style": {"color": "#2d2d2d", "marginBottom": 20}, "children": [], "order": 0},
                    {"id": "2", "type": "input", "props": {"placeholder": "Search notes...", "icon": "search"}, "style": {"marginBottom": 16}, "children": [], "order": 1},
                    {"id": "3", "type": "card", "props": {"title": "Meeting Notes", "subtitle": "Today"}, "style": {"backgroundColor": "#fff8dc", "marginBottom": 12}, "children": [], "order": 2},
                    {"id": "4", "type": "card", "props": {"title": "Shopping List", "subtitle": "Yesterday"}, "style": {"backgroundColor": "#e8f5e9", "marginBottom": 12}, "children": [], "order": 3},
                    {"id": "5", "type": "button", "props": {"text": "New Note", "variant": "primary", "icon": "plus"}, "style": {"backgroundColor": "#ff9800", "marginTop": 20}, "children": [], "order": 4}
                ],
                "order": 0
            }
        ],
        "settings": {"primaryColor": "#ff9800", "theme": "light"}
    },
    {
        "id": "photo-gallery",
        "name": "Photo Gallery",
        "description": "Showcase your photos beautifully",
        "category": "social",
        "thumbnail": "image",
        "screens": [
            {
                "id": "home",
                "name": "Gallery",
                "backgroundColor": "#121212",
                "components": [
                    {"id": "1", "type": "heading", "props": {"text": "My Gallery", "level": 1}, "style": {"color": "#ffffff", "marginBottom": 20}, "children": [], "order": 0},
                    {"id": "2", "type": "grid", "props": {"columns": 2, "gap": 8}, "style": {}, "children": ["3", "4", "5", "6"], "order": 1},
                    {"id": "3", "type": "image", "props": {"placeholder": True}, "style": {"borderRadius": 8, "aspectRatio": 1}, "children": [], "order": 2},
                    {"id": "4", "type": "image", "props": {"placeholder": True}, "style": {"borderRadius": 8, "aspectRatio": 1}, "children": [], "order": 3},
                    {"id": "5", "type": "image", "props": {"placeholder": True}, "style": {"borderRadius": 8, "aspectRatio": 1}, "children": [], "order": 4},
                    {"id": "6", "type": "image", "props": {"placeholder": True}, "style": {"borderRadius": 8, "aspectRatio": 1}, "children": [], "order": 5},
                    {"id": "7", "type": "button", "props": {"text": "Add Photo", "variant": "primary", "icon": "camera"}, "style": {"backgroundColor": "#9c27b0", "marginTop": 20}, "children": [], "order": 6}
                ],
                "order": 0
            }
        ],
        "settings": {"primaryColor": "#9c27b0", "theme": "dark"}
    },
    {
        "id": "contact-list",
        "name": "Contact List",
        "description": "Manage your business contacts",
        "category": "business",
        "thumbnail": "users",
        "screens": [
            {
                "id": "home",
                "name": "Contacts",
                "backgroundColor": "#f5f5f5",
                "components": [
                    {"id": "1", "type": "heading", "props": {"text": "Contacts", "level": 1}, "style": {"color": "#333333", "marginBottom": 16}, "children": [], "order": 0},
                    {"id": "2", "type": "input", "props": {"placeholder": "Search contacts...", "icon": "search"}, "style": {"marginBottom": 16}, "children": [], "order": 1},
                    {"id": "3", "type": "list", "props": {"items": []}, "style": {}, "children": ["4", "5", "6"], "order": 2},
                    {"id": "4", "type": "card", "props": {"title": "John Doe", "subtitle": "john@example.com", "avatar": True}, "style": {"backgroundColor": "#ffffff", "marginBottom": 8}, "children": [], "order": 3},
                    {"id": "5", "type": "card", "props": {"title": "Jane Smith", "subtitle": "jane@example.com", "avatar": True}, "style": {"backgroundColor": "#ffffff", "marginBottom": 8}, "children": [], "order": 4},
                    {"id": "6", "type": "card", "props": {"title": "Bob Wilson", "subtitle": "bob@example.com", "avatar": True}, "style": {"backgroundColor": "#ffffff", "marginBottom": 8}, "children": [], "order": 5},
                    {"id": "7", "type": "button", "props": {"text": "Add Contact", "variant": "primary", "icon": "user-plus"}, "style": {"backgroundColor": "#2196f3", "marginTop": 16}, "children": [], "order": 6}
                ],
                "order": 0
            }
        ],
        "settings": {"primaryColor": "#2196f3", "theme": "light"}
    }
]

# ===================== AUTH ROUTES =====================

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    print(f"[REGISTER] Received registration for email: {user_data.email}")
    # Check if user exists
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        print(f"[REGISTER] Email already exists: {user_data.email}")
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_doc = {
        "email": user_data.email,
        "password": get_password_hash(user_data.password),
        "name": user_data.name,
        "created_at": datetime.utcnow()
    }
    print(f"[REGISTER] Inserting user document for: {user_data.email}")
    result = await db.users.insert_one(user_doc)
    user_doc["_id"] = result.inserted_id
    print(f"[REGISTER] User created successfully with ID: {result.inserted_id}")
    
    # Create token
    token = create_access_token({"sub": str(result.inserted_id)})
    
    return TokenResponse(
        access_token=token,
        user=serialize_user(user_doc)
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_access_token({"sub": str(user["_id"])})
    
    return TokenResponse(
        access_token=token,
        user=serialize_user(user)
    )

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return serialize_user(current_user)

# ===================== PROJECT ROUTES =====================

@api_router.get("/projects", response_model=List[ProjectResponse])
async def get_projects(current_user: dict = Depends(get_current_user)):
    projects = await db.projects.find({"user_id": current_user["_id"]}).sort("updated_at", -1).to_list(100)
    return [serialize_project(p) for p in projects]

@api_router.post("/projects", response_model=ProjectResponse)
async def create_project(project_data: ProjectCreate, current_user: dict = Depends(get_current_user)):
    # Get template if specified
    screens = []
    settings = {"primaryColor": "#007AFF", "theme": "light"}
    
    if project_data.template_id:
        template = next((t for t in DEFAULT_TEMPLATES if t["id"] == project_data.template_id), None)
        if template:
            screens = [ScreenData(**s).dict() for s in template["screens"]]
            settings = template["settings"]
    else:
        # Default blank screen
        screens = [ScreenData(id="main", name="Home", components=[], backgroundColor="#ffffff", order=0).dict()]
    
    project_doc = {
        "user_id": current_user["_id"],
        "name": project_data.name,
        "description": project_data.description or "",
        "screens": screens,
        "settings": settings,
        "template_id": project_data.template_id,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    result = await db.projects.insert_one(project_doc)
    project_doc["_id"] = result.inserted_id
    
    return serialize_project(project_doc)

@api_router.get("/projects/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str, current_user: dict = Depends(get_current_user)):
    try:
        project = await db.projects.find_one({"_id": ObjectId(project_id), "user_id": current_user["_id"]})
    except:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return serialize_project(project)

@api_router.put("/projects/{project_id}", response_model=ProjectResponse)
async def update_project(project_id: str, project_data: ProjectUpdate, current_user: dict = Depends(get_current_user)):
    try:
        project = await db.projects.find_one({"_id": ObjectId(project_id), "user_id": current_user["_id"]})
    except:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    update_data = {"updated_at": datetime.utcnow()}
    if project_data.name is not None:
        update_data["name"] = project_data.name
    if project_data.description is not None:
        update_data["description"] = project_data.description
    if project_data.screens is not None:
        update_data["screens"] = [s.dict() for s in project_data.screens]
    if project_data.settings is not None:
        update_data["settings"] = project_data.settings
    
    await db.projects.update_one({"_id": ObjectId(project_id)}, {"$set": update_data})
    
    updated_project = await db.projects.find_one({"_id": ObjectId(project_id)})
    return serialize_project(updated_project)

@api_router.delete("/projects/{project_id}")
async def delete_project(project_id: str, current_user: dict = Depends(get_current_user)):
    try:
        result = await db.projects.delete_one({"_id": ObjectId(project_id), "user_id": current_user["_id"]})
    except:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return {"message": "Project deleted successfully"}

# ===================== TEMPLATE ROUTES =====================

@api_router.get("/templates", response_model=List[TemplateResponse])
async def get_templates():
    return [TemplateResponse(**t) for t in DEFAULT_TEMPLATES]

@api_router.get("/templates/{template_id}", response_model=TemplateResponse)
async def get_template(template_id: str):
    template = next((t for t in DEFAULT_TEMPLATES if t["id"] == template_id), None)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return TemplateResponse(**template)

# ===================== FORWARDING SETTINGS ROUTES =====================

def serialize_forwarding_settings(settings: dict) -> ForwardingSettingsResponse:
    return ForwardingSettingsResponse(
        id=str(settings["_id"]),
        user_id=str(settings["user_id"]),
        telegram=TelegramSettings(**settings.get("telegram", {})),
        email=EmailSettings(**settings.get("email", {})),
        phone=PhoneForwardingSettings(**settings.get("phone", {})),
        updated_at=settings.get("updated_at", datetime.utcnow())
    )

@api_router.get("/settings/forwarding", response_model=ForwardingSettingsResponse)
async def get_forwarding_settings(current_user: dict = Depends(get_current_user)):
    settings = await db.forwarding_settings.find_one({"user_id": current_user["_id"]})
    
    if not settings:
        # Create default settings
        default_settings = {
            "user_id": current_user["_id"],
            "telegram": TelegramSettings().dict(),
            "email": EmailSettings().dict(),
            "phone": PhoneForwardingSettings().dict(),
            "updated_at": datetime.utcnow()
        }
        result = await db.forwarding_settings.insert_one(default_settings)
        default_settings["_id"] = result.inserted_id
        return serialize_forwarding_settings(default_settings)
    
    return serialize_forwarding_settings(settings)

@api_router.put("/settings/forwarding", response_model=ForwardingSettingsResponse)
async def update_forwarding_settings(
    settings_data: ForwardingSettingsUpdate,
    current_user: dict = Depends(get_current_user)
):
    existing = await db.forwarding_settings.find_one({"user_id": current_user["_id"]})
    
    update_data = {"updated_at": datetime.utcnow()}
    
    if settings_data.telegram is not None:
        update_data["telegram"] = settings_data.telegram.dict()
    if settings_data.email is not None:
        update_data["email"] = settings_data.email.dict()
    if settings_data.phone is not None:
        update_data["phone"] = settings_data.phone.dict()
    
    if existing:
        await db.forwarding_settings.update_one(
            {"user_id": current_user["_id"]},
            {"$set": update_data}
        )
    else:
        # Create new settings
        new_settings = {
            "user_id": current_user["_id"],
            "telegram": settings_data.telegram.dict() if settings_data.telegram else TelegramSettings().dict(),
            "email": settings_data.email.dict() if settings_data.email else EmailSettings().dict(),
            "phone": settings_data.phone.dict() if settings_data.phone else PhoneForwardingSettings().dict(),
            "updated_at": datetime.utcnow()
        }
        await db.forwarding_settings.insert_one(new_settings)
    
    updated = await db.forwarding_settings.find_one({"user_id": current_user["_id"]})
    return serialize_forwarding_settings(updated)

@api_router.patch("/settings/forwarding/telegram", response_model=ForwardingSettingsResponse)
async def update_telegram_settings(
    telegram_data: TelegramSettings,
    current_user: dict = Depends(get_current_user)
):
    existing = await db.forwarding_settings.find_one({"user_id": current_user["_id"]})
    
    if existing:
        await db.forwarding_settings.update_one(
            {"user_id": current_user["_id"]},
            {"$set": {"telegram": telegram_data.dict(), "updated_at": datetime.utcnow()}}
        )
    else:
        new_settings = {
            "user_id": current_user["_id"],
            "telegram": telegram_data.dict(),
            "email": EmailSettings().dict(),
            "phone": PhoneForwardingSettings().dict(),
            "updated_at": datetime.utcnow()
        }
        await db.forwarding_settings.insert_one(new_settings)
    
    updated = await db.forwarding_settings.find_one({"user_id": current_user["_id"]})
    return serialize_forwarding_settings(updated)

@api_router.patch("/settings/forwarding/email", response_model=ForwardingSettingsResponse)
async def update_email_settings(
    email_data: EmailSettings,
    current_user: dict = Depends(get_current_user)
):
    existing = await db.forwarding_settings.find_one({"user_id": current_user["_id"]})
    
    if existing:
        await db.forwarding_settings.update_one(
            {"user_id": current_user["_id"]},
            {"$set": {"email": email_data.dict(), "updated_at": datetime.utcnow()}}
        )
    else:
        new_settings = {
            "user_id": current_user["_id"],
            "telegram": TelegramSettings().dict(),
            "email": email_data.dict(),
            "phone": PhoneForwardingSettings().dict(),
            "updated_at": datetime.utcnow()
        }
        await db.forwarding_settings.insert_one(new_settings)
    
    updated = await db.forwarding_settings.find_one({"user_id": current_user["_id"]})
    return serialize_forwarding_settings(updated)

@api_router.patch("/settings/forwarding/phone", response_model=ForwardingSettingsResponse)
async def update_phone_settings(
    phone_data: PhoneForwardingSettings,
    current_user: dict = Depends(get_current_user)
):
    existing = await db.forwarding_settings.find_one({"user_id": current_user["_id"]})
    
    if existing:
        await db.forwarding_settings.update_one(
            {"user_id": current_user["_id"]},
            {"$set": {"phone": phone_data.dict(), "updated_at": datetime.utcnow()}}
        )
    else:
        new_settings = {
            "user_id": current_user["_id"],
            "telegram": TelegramSettings().dict(),
            "email": EmailSettings().dict(),
            "phone": phone_data.dict(),
            "updated_at": datetime.utcnow()
        }
        await db.forwarding_settings.insert_one(new_settings)
    
    updated = await db.forwarding_settings.find_one({"user_id": current_user["_id"]})
    return serialize_forwarding_settings(updated)

# ===================== ROOT ROUTE =====================

@api_router.get("/")
async def root():
    return {"message": "No-Code Mobile App Builder API", "version": "1.0"}

# Include router
app.include_router(api_router)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
