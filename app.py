import os
import urllib.parse
import requests
import asyncio
import threading
import discord

from discord.ext import tasks, commands
from flask import Flask, redirect, render_template, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

# -------------------- Flask --------------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change_me")

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, "court.db")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + db_path
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# -------------------- Discord config (ENV) --------------------
GUILD_ID = int(os.getenv("GUILD_ID", "0"))

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI", "")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")

# Роли суда (ID ролей Discord -> название роли на сайте)
ROLE_MAP = {
    os.getenv("ROLE_PVS_ID", ""): "Председатель Верховного Суда",
    os.getenv("ROLE_VS_ID", ""): "Верховный Судья",
    os.getenv("ROLE_KA_ID", ""): "Кассационный судья",
    os.getenv("ROLE_YD_ID", ""): "Судья по Уголовным и Административным делам",
    os.getenv("ROLE_GK_ID", ""): "Судья по гражданским делам",
}

# Суды и префиксы дел
COURTS = {
    "Верховный Суд": "GH",
    "Кассационный Суд": "KA",
    "Суд по Уголовным и Административным делам": "YD",
    "Суд по гражданским делам": "GK",
}

# -------------------- DB models --------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(50), unique=True, index=True)
    username = db.Column(db.String(120))
    role = db.Column(db.String(120), default="Гражданин")


class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_num = db.Column(db.String(50), unique=True, index=True)  # GK-001
    court = db.Column(db.String(120))  # текст
    prefix = db.Column(db.String(10))  # GK/KA/...
    title = db.Column(db.String(200))  # процесс
    payload = db.Column(db.Text)       # JSON строка с полями (истец/ответчик/суть/дата/подпись)
    author_id = db.Column(db.String(50), index=True)
    status = db.Column(db.String(50), default="Новый")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class DiscordQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    discord_id = db.Column(db.String(50))
    role_name = db.Column(db.String(120))
    status = db.Column(db.String(20), default="pending")


# -------------------- Discord bot --------------------
intents = discord.Intents.default()
intents.members = True
intents.guilds = True
intents.guild_messages = True

bot = commands.Bot(command_prefix="!", intents=intents)

@tasks.loop(seconds=8)
async def process_queue():
    with app.app_context():
        tasks_to_do = DiscordQueue.query.filter_by(status="pending").all()
        if not tasks_to_do:
            return

        guild = bot.get_guild(GUILD_ID)
        if not guild:
            return

        for t in tasks_to_do:
            try:
                member = await guild.fetch_member(int(t.discord_id))
                role = discord.utils.get(guild.roles, name=t.role_name)
                if role is None:
                    role = await guild.create_role(name=t.role_name)
                await member.add_roles(role, reason="Case role")
                t.status = "done"
            except Exception as e:
                print("queue error:", e)
                t.status = "error"

        db.session.commit()

@bot.event
async def on_ready():
    print("Bot ready:", bot.user)
    if not process_queue.is_running():
        process_queue.start()


def run_bot():
    asyncio.run(bot.start(DISCORD_BOT_TOKEN))

# -------------------- Helpers --------------------
def auth_url():
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds.members.read",
    }
    return "https://discord.com/api/oauth2/authorize?" + urllib.parse.urlencode(params)

def get_user_role_from_member(member_json: dict) -> str:
    roles = member_json.get("roles", [])
    for rid in roles:
        if rid in ROLE_MAP and ROLE_MAP[rid]:
            return ROLE_MAP[rid]
    return "Гражданин"

def require_login():
    if "user_id" not in session:
        return False
    return True

def current_user():
    if not require_login():
        return None
    return User.query.filter_by(discord_id=session["user_id"]).first()

def is_pvs(user: User) -> bool:
    return user and user.role == "Председатель Верховного Суда"

def next_case_num(prefix: str) -> str:
    last = Case.query.filter_by(prefix=prefix).order_by(Case.id.desc()).first()
    if not last:
        n = 1
    else:
        try:
            n = int(last.case_num.split("-")[1]) + 1
        except Exception:
            n = 1
    return f"{prefix}-{n:03d}"

def visible_cases_for(user: User):
    q = Case.query.order_by(Case.created_at.desc())
    if user.role == "Гражданин":
        return q.filter_by(author_id=user.discord_id).all()

    # судьи видят дела своего суда (по префиксу)
    role_to_prefix = {
        "Кассационный судья": "KA",
        "Председатель Верховного Суда": "GH",
        "Верховный Судья": "GH",
        "Судья по Уголовным и Административным делам": "YD",
        "Судья по гражданским делам": "GK",
    }
    pref = role_to_prefix.get(user.role)
    if pref:
        return q.filter_by(prefix=pref).all()
    return q.filter_by(author_id=user.discord_id).all()

# -------------------- Routes --------------------
@app.route("/")
def index():
    if not require_login():
        return render_template("login.html", url=auth_url())

    user = current_user()
    if not user:
        session.clear()
        return render_template("login.html", url=auth_url())

    cases = visible_cases_for(user)
    return render_template("index.html", user=user, courts=list(COURTS.keys()), cases=cases)

@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "No code", 400

    token_resp = requests.post("https://discord.com/api/v10/oauth2/token", data={
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI
    }).json()

    access_token = token_resp.get("access_token")
    if not access_token:
        return "OAuth failed", 400

    headers = {"Authorization": f"Bearer {access_token}"}
    u = requests.get("https://discord.com/api/v10/users/@me", headers=headers).json()
    m = requests.get(f"https://discord.com/api/v10/users/@me/guilds/{GUILD_ID}/member", headers=headers).json()

    discord_id = u["id"]
    username = m.get("nick") or u.get("global_name") or u.get("username")
    role = get_user_role_from_member(m)

    user = User.query.filter_by(discord_id=discord_id).first()
    if not user:
        user = User(discord_id=discord_id, username=username, role=role)
        db.session.add(user)
    else:
        user.username = username
        user.role = role
    db.session.commit()

    session["user_id"] = discord_id
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/api/create_case", methods=["POST"])
def api_create_case():
    if not require_login():
        return jsonify({"error": "unauthorized"}), 401

    user = current_user()
    data = request.get_json(silent=True) or {}

    court = data.get("court")
    title = data.get("title")
    payload = data.get("payload")  # строка JSON (мы храним как есть)

    if court not in COURTS:
        return jsonify({"error": "bad_court"}), 400
    if not title:
        return jsonify({"error": "bad_title"}), 400
    if not payload:
        return jsonify({"error": "bad_payload"}), 400

    prefix = COURTS[court]
    case_num = next_case_num(prefix)

    c = Case(
        case_num=case_num,
        court=court,
        prefix=prefix,
        title=title,
        payload=payload,
        author_id=user.discord_id,
        status="Новый"
    )
    db.session.add(c)

    # выдать роль с номером дела в Discord
    db.session.add(DiscordQueue(discord_id=user.discord_id, role_name=case_num))
    db.session.commit()

    return jsonify({"ok": True, "case_num": case_num})

@app.route("/admin")
def admin():
    if not require_login():
        return redirect("/")
    user = current_user()
    if not is_pvs(user):
        return "Доступ запрещён", 403
    return render_template("admin.html", user=user)

@app.route("/api/admin/roles")
def api_admin_roles():
    user = current_user()
    if not is_pvs(user):
        return jsonify({"error": "forbidden"}), 403

    guild = bot.get_guild(GUILD_ID)
    if not guild:
        return jsonify([])

    roles = []
    for r in sorted(guild.roles, key=lambda x: x.position, reverse=True):
        if r.name == "@everyone":
            continue
        roles.append({"id": r.id, "name": r.name})
    return jsonify(roles)

@app.route("/api/admin/members")
def api_admin_members():
    user = current_user()
    if not is_pvs(user):
        return jsonify({"error": "forbidden"}), 403

    guild = bot.get_guild(GUILD_ID)
    if not guild:
        return jsonify([])

    out = []
    # fetch_members может быть тяжёлым, но для маленького сервера ок
    async def get_members():
        members = []
        async for m in guild.fetch_members(limit=None):
            roles = [r.name for r in m.roles if r.name != "@everyone"]
            members.append({"id": str(m.id), "name": m.display_name, "roles": roles})
        return members

    fut = asyncio.run_coroutine_threadsafe(get_members(), bot.loop)
    out = fut.result()
    return jsonify(out)

@app.route("/api/admin/set_role", methods=["POST"])
def api_admin_set_role():
    user = current_user()
    if not is_pvs(user):
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    member_id = data.get("member_id")
    role_id = data.get("role_id")
    action = data.get("action")  # add/remove

    if not member_id or not role_id or action not in ("add", "remove"):
        return jsonify({"error": "bad_request"}), 400

    async def do():
        guild = bot.get_guild(GUILD_ID)
        if not guild:
            return "guild_not_found"
        try:
            member = await guild.fetch_member(int(member_id))
            role = guild.get_role(int(role_id))
            if not role:
                return "role_not_found"
            if action == "add":
                await member.add_roles(role, reason="Admin panel")
            else:
                await member.remove_roles(role, reason="Admin panel")
            return "ok"
        except Exception as e:
            print("set_role error:", e)
            return "error"

    fut = asyncio.run_coroutine_threadsafe(do(), bot.loop)
    return jsonify({"result": fut.result()})


# -------------------- Start --------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    threading.Thread(target=run_bot, daemon=True).start()
    # локально можно: flask run; на Render будет gunicorn
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
