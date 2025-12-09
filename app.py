import os
import datetime
import math
import requests
from collections import defaultdict
from typing import List, Dict, Optional, Any

from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from flask_cors import CORS
from sqlalchemy import desc, func, and_
from sqlalchemy.exc import IntegrityError # Para lidar com erros de banco

# ============================================================
# ⚙️ CONFIGURAÇÃO
# ============================================================

class Config:
    # Banco local SQLite (troca depois por Postgres se quiser)
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///wesafe.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT (troca em produção)
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "mude-este-segredo-para-algo-bem-forte")
    JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(hours=1)

    # Mapbox
    MAPBOX_TOKEN = os.getenv("MAPBOX_TOKEN", "COLOQUE_SEU_TOKEN_DA_MAPBOX_AQUI")
    MAPBOX_PROFILE = "mapbox/driving"
    MAPBOX_ALTERNATIVES = True # Importante para rotas seguras

app = Flask(__name__)
app.config.from_object(Config)

# CORS só para /api/*
CORS(app, resources={r"/api/*": {"origins": "*"}})

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Variáveis globais de configuração
MAPBOX_TOKEN = app.config["MAPBOX_TOKEN"]
MAPBOX_PROFILE = app.config["MAPBOX_PROFILE"]
MAPBOX_ALTERNATIVES = app.config["MAPBOX_ALTERNATIVES"]

# ============================================================
# 🚨 CLASSES DE ERRO (Padronização de Resposta)
# ============================================================

class APIError(Exception):
    status_code = 400
    def __init__(self, message, status_code=None):
        super().__init__()
        self.message = message
        if status_code is not None:
            self.status_code = status_code

@app.errorhandler(APIError)
def handle_api_error(error):
    response = jsonify({"error": error.message})
    response.status_code = error.status_code
    return response

# ============================================================
# 💾 MODELS
# ============================================================

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    # Adicionando index=True para performance e unique=True para integridade
    email = db.Column(db.String(180), unique=True, index=True, nullable=False) 
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)


class Report(db.Model):
    """
    Relato de segurança enviado pelo usuário.
    risk_level: 1 (Tranquilo/Baixo), 2 (Médio/Alerta), 3 (Perigoso/Alto)
    """
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.Integer, nullable=False)  # 1, 2, 3
    comment = db.Column(db.String(500), nullable=True)
    neighborhood = db.Column(db.String(100), nullable=True) # Contexto de localização
    city = db.Column(db.String(100), nullable=True)         # Contexto de localização
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True) # Adicionado index para o filtro de tempo
    
    user = db.relationship("User", backref="reports", lazy=True)

# ============================================================
# 🛠️ FUNÇÕES UTILITÁRIAS DE CÁLCULO DE RISCO
# ============================================================

# Constantes para a distância Haversine
R_EARTH_METERS = 6371000
BASE_SCORES = {1: 1.5, 2: 5.0, 3: 9.0} # Pontuação base de risco (0-10)

def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Distância aproximada em metros entre dois pontos lat/lng."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)

    a = (
        math.sin(dphi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R_EARTH_METERS * c


def _time_of_day_weight(dt: datetime.datetime) -> float:
    """
    Aplica peso de risco baseado no horário.
    Ajustado para refletir picos na madrugada e início da noite.
    """
    hour = dt.hour
    
    # 0h - 4h: Madrugada (Peso Máximo)
    if 0 <= hour < 5:
        return 1.8 
    
    # 22h - 23h: Noite avançada
    if 22 <= hour <= 23:
        return 1.6 
    
    # 18h - 21h: Início da noite/Escurecendo
    if 18 <= hour < 22:
        return 1.4 
        
    # 17h - 18h: Fim de Tarde
    if 17 <= hour < 18:
        return 1.25
    
    # 5h - 7h: Início da manhã
    if 5 <= hour < 7:
        return 1.2
        
    # 7h - 17h: Dia/Horário comercial (Peso normal/próximo de 1.0)
    if 7 <= hour < 17:
        return 1.1 if 7 <= hour < 9 else 1.0
    
    return 1.0 # Padrão

def _decay_time_weight(created_at: datetime.datetime) -> float:
    """Aplica decaimento exponencial de peso baseado no tempo decorrido (horas)."""
    now = datetime.datetime.utcnow()
    hours_diff = (now - created_at).total_seconds() / 3600.0
    
    # Fator de decaimento: 0.05 faz o peso cair para ~0.3 em 24h e ~0.1 em 48h.
    decay_factor = 0.05 
    weight = math.exp(-decay_factor * hours_diff)
    
    # Garante que o peso mínimo seja 0.1 para relatos muito antigos.
    return max(0.1, weight)

def _density_weight(reports_count: int, radius_m: int = 200) -> float:
    """
    NOVO: Aplica peso de risco baseado na densidade de reports.
    Pondera áreas que, mesmo com reports de risco baixo, tem muitos reports
    num pequeno raio.
    """
    if reports_count < 2:
        return 1.0
    
    # Peso máximo de 1.5 (50% de aumento) para 15+ reports.
    max_reports_for_full_weight = 15
    max_weight = 1.5
    
    # Usa a raiz quadrada para um crescimento que desacelera (diminishing returns)
    # Aumenta o peso do score em áreas de alta densidade
    weight = 1.0 + (max_weight - 1.0) * math.sqrt(min(reports_count, max_reports_for_full_weight) / max_reports_for_full_weight)
    
    return weight

def _get_risk_category(score: float) -> Dict[str, Any]:
    """
    Categoriza a pontuação de risco (0-10) em nível e cor.
    Cor 'orange' para risco Médio/Alerta.
    """
    if score >= 7.0:
        return {"level": "Alto", "color_code": "red"} 
    if score >= 4.0:
        return {"level": "Médio", "color_code": "orange"} # COR LARANJA AQUI!
    if score >= 1.0:
        return {"level": "Baixo", "color_code": "yellowgreen"}
    return {"level": "Muito Baixo", "color_code": "green"} 


def _get_nearby_reports(lat: float, lng: float, radius_m: int = 200, limit: int = 800) -> List[Report]:
    """Busca relatórios próximos, priorizando os mais recentes e otimizando com filtro de tempo."""
    
    # Otimização: Filtra reports recentes (ex: últimas 72 horas) no SQL para acelerar.
    # O filtro por tempo evita que o Haversine seja rodado em reports de 2 anos atrás.
    time_limit = datetime.datetime.utcnow() - datetime.timedelta(hours=72)
    
    reports = (
        db.session.execute(
            db.select(Report)
            .where(Report.created_at >= time_limit)
            .order_by(desc(Report.created_at))
            .limit(limit)
        ).scalars().all()
    )

    nearby: List[Report] = []
    
    # Pré-filtro (bounding box) para otimizar o cálculo Haversine
    degree_radius = radius_m / R_EARTH_METERS * (180 / math.pi) 

    for r in reports:
        if (abs(r.latitude - lat) > degree_radius * 2 or 
            abs(r.longitude - lng) > degree_radius * 2):
            continue
            
        dist = haversine_distance(lat, lng, r.latitude, r.longitude)
        if dist <= radius_m:
            nearby.append(r)
            
    return nearby

def calculate_risk_score(lat: float, lng: float, radius_m: int = 200) -> Dict[str, Any]:
    """Calcula o risco médio (0-10) num raio em torno de um ponto (lat, lng)."""
    # Limita o número de reports processados para manter o desempenho.
    nearby = _get_nearby_reports(lat, lng, radius_m=radius_m, limit=800)[:80]

    if not nearby:
        return {"risk_score": 0.0, "reports_count": 0}

    scores = []
    # NOVO: Calcula o peso de densidade da área UMA VEZ
    density_w = _density_weight(len(nearby), radius_m) 

    for r in nearby:
        base = BASE_SCORES.get(r.risk_level, 5.0)

        time_weight = _decay_time_weight(r.created_at)
        tod_weight = _time_of_day_weight(r.created_at)

        # O final_score agora incorpora a densidade da área (mais cruzamento de dados)
        final_score = base * time_weight * tod_weight * density_w
        scores.append(final_score)

    risk_score = sum(scores) / len(scores)
    risk_score = max(0.0, min(10.0, risk_score)) # Limita entre 0 e 10

    return {"risk_score": risk_score, "reports_count": len(nearby)}

# ============================================================
# 🗺️ FUNÇÕES DE GEOGRAFIA E ROTA
# ============================================================

def reverse_geocode(lat: float, lng: float) -> Dict[str, Optional[str]]:
    """
    Busca o nome do bairro e cidade usando a API de Geocoding Reversa da Mapbox.
    NOVO: Tenta buscar a localização específica (rua, POI)
    """
    if MAPBOX_TOKEN == "COLOQUE_SEU_TOKEN_DA_MAPBOX_AQUI":
        app.logger.warning("MAPBOX_TOKEN não configurado. Geocoding reverso desativado.")
        return {"neighborhood": None, "city": None, "specific_location": None}

    base_url = "https://api.mapbox.com/geocoding/v5/mapbox.places"
    url = f"{base_url}/{lng},{lat}.json"

    params = {
        "access_token": MAPBOX_TOKEN,
        # Foca em bairros, cidades e ponto específico (address)
        "types": "address,locality,place,neighborhood", 
        "limit": 1
    }

    try:
        resp = requests.get(url, params=params, timeout=5)
        resp.raise_for_status()
        data = resp.json()

        neighborhood = None
        city = None
        specific_location = None

        if data.get("features"):
            feature = data["features"][0]
            context = feature.get("context", [])
            
            # Se o primeiro resultado for um endereço específico (não bairro/cidade), usa-o
            if feature.get("text") and not any(t in feature.get("place_type", []) for t in ["neighborhood", "locality", "place"]):
                specific_location = feature["text"]

            for item in context:
                if 'neighborhood' in item['id']:
                    neighborhood = item['text']
                elif 'place' in item['id'] or 'locality' in item['id']:
                    if not city: 
                        city = item['text']
            
            # Se o feature principal for bairro e não tiver pego do context
            if feature.get("place_type") and ("neighborhood" in feature["place_type"] or "locality" in feature["place_type"]) and not neighborhood:
                neighborhood = feature["text"]


        return {"neighborhood": neighborhood, "city": city, "specific_location": specific_location}

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Erro no Geocoding Reverso: {e}")
        return {"neighborhood": None, "city": None, "specific_location": None}

# ... (Funções mapbox_route, enrich_route_with_risk e find_safest_route mantidas) ...

# ... (Resto do código mantido: compute_hotspots, rotas /api/register, /api/login, /api/report, /api/risk, /api/hotspots) ...

# ============================================================
# ⚙️ ROTAS / ENDPOINTS
# ============================================================

# Serve o frontend principal
@app.route("/")
def home():
    # Retorna o template (crie um arquivo 'inicio.html' na pasta 'templates')
    return render_template("inicio.html")


# ---------- AUTH ----------

@app.post("/api/register")
def register():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        raise APIError("Email e password são obrigatórios.")

    if User.query.filter_by(email=email).first():
        raise APIError("Email já registrado.", 409) # 409 Conflict

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "usuário criado com sucesso"}), 201


@app.post("/api/login")
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        raise APIError("Email e password são obrigatórios.")

    # Busca otimizada pelo índice do email
    user = User.query.filter_by(email=email).first() 
    if not user or not user.check_password(password):
        raise APIError("Credenciais inválidas.", 401) # 401 Unauthorized

    token = create_access_token(identity=user.id)
    return jsonify({"access_token": token, "user_id": user.id})


# ---------- REPORTS / RISCO ----------

@app.post("/api/report")
@jwt_required(optional=True)
def create_report():
    user_id = get_jwt_identity()
    data = request.get_json() or {}

    try:
        lat = float(data.get("latitude"))
        lng = float(data.get("longitude"))
        risk_level = int(data.get("risk_level"))
        comment = data.get("comment", "")
    except (TypeError, ValueError):
        raise APIError("latitude, longitude e risk_level devem ser numéricos.")

    if risk_level not in (1, 2, 3):
        raise APIError("risk_level deve ser 1 (baixo), 2 (médio) ou 3 (alto).")
    
    # Geocoding Reverso para contexto de bairro (agora mais detalhado)
    location_data = reverse_geocode(lat, lng)

    report = Report(
        user_id=user_id,
        latitude=lat,
        longitude=lng,
        risk_level=risk_level,
        comment=comment[:500],
        neighborhood=location_data.get("neighborhood"),
        city=location_data.get("city")
    )
    
    try:
        db.session.add(report)
        db.session.commit()
    except IntegrityError:
          db.session.rollback()
          raise APIError("Erro ao salvar relato no banco de dados.", 500)

    return jsonify({
        "message": "Relato registrado com sucesso", 
        "id": report.id,
        "context": location_data # Inclui o novo 'specific_location'
    }), 201

# ... (Rotas /api/risk e /api/hotspots mantidas) ...

# ---------- ROTA SEGURA (AVANÇADO) ----------

# ... (A rota /api/safe_route e suas funções auxiliares mapbox_route, enrich_route_with_risk e find_safest_route mantidas) ...

@app.cli.command("init-db")
def init_db_command():
    """
    Comando pra criar o banco:
      flask --app app.py init-db
    """
    with app.app_context():
        db.create_all()
        print("Banco criado / atualizado.")
        
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)