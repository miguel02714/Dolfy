import os
import datetime
import math
import requests
from typing import List, Dict, Optional, Any

from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity, unset_jwt_cookies
)
from flask_cors import CORS
from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError # Para lidar com erros de banco

# ============================================================
# ⚙️ CONFIGURAÇÃO
# ============================================================

class Config:
    """Configurações centrais da aplicação."""
    # Banco local SQLite
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///wesafe.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False 

    # JWT 
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "mude-este-segredo-para-algo-bem-forte")
    JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(hours=1)
    
    # Mapbox
    # !! OBRIGATÓRIO: TROQUE ESTE VALOR POR UM TOKEN VÁLIDO DA MAPBOX !!
    MAPBOX_TOKEN = os.getenv("MAPBOX_TOKEN", "pk.eyJ1IjoicGxhY2Vob2xkZXIiLCJhIjoiY2x3ajVxanhyMW4yMTJpcnNhZG14amJvYSJ9.J5v0L-H5v0L-H5v0L-H5v0L")
    MAPBOX_PROFILE = "mapbox/driving"
    MAPBOX_ALTERNATIVES = True 

app = Flask(__name__)
app.config.from_object(Config)

# Configurações globais
CORS(app, resources={r"/api/*": {"origins": "*"}})
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

MAPBOX_TOKEN = app.config["MAPBOX_TOKEN"]
MAPBOX_PROFILE = app.config["MAPBOX_PROFILE"]
MAPBOX_ALTERNATIVES = app.config["MAPBOX_ALTERNATIVES"]

# ============================================================
# 🚨 CLASSES DE ERRO (Padronização de Resposta)
# ============================================================

class APIError(Exception):
    """Classe de erro personalizada para respostas HTTP da API."""
    status_code = 400
    def __init__(self, message, status_code=None):
        super().__init__()
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        app.logger.error(f"API Error ({self.status_code}): {self.message}")

@app.errorhandler(APIError)
def handle_api_error(error):
    """Manipulador global de exceções da API."""
    response = jsonify({"error": error.message})
    response.status_code = error.status_code
    return response

# ============================================================
# 💾 MODELS
# ============================================================

class User(db.Model):
    """Modelo do Usuário."""
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False, default="Usuário WeSafe")
    email = db.Column(db.String(255), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    reports = db.relationship("Report", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password: str):
        """Gera e armazena o hash da senha."""
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        """Verifica a senha informada com o hash armazenado."""
        return bcrypt.check_password_hash(self.password_hash, password)

class Report(db.Model):
    """Relato de segurança enviado pelo usuário."""
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True) 
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.Integer, nullable=False)  # 1 (Baixo), 2 (Médio), 3 (Alto)
    comment = db.Column(db.String(500), nullable=True)
    neighborhood = db.Column(db.String(100), nullable=True) 
    city = db.Column(db.String(100), nullable=True)         
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True) 
    specific_location = db.Column(db.String(255), nullable=True) 

# ============================================================
# 🛠️ FUNÇÕES UTILITÁRIAS DE CÁLCULO DE RISCO
# ============================================================

R_EARTH_METERS = 6371000
BASE_SCORES = {1: 1.5, 2: 5.0, 3: 9.0} 

def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Distância aproximada em metros (Fórmula Haversine)."""
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
    """Aplica peso de risco baseado no horário."""
    hour = dt.hour
    if 0 <= hour < 5: return 1.8 
    if 22 <= hour <= 23: return 1.6 
    if 18 <= hour < 22: return 1.4 
    if 17 <= hour < 18: return 1.25
    if 5 <= hour < 7: return 1.2
    if 7 <= hour < 17: return 1.1 if 7 <= hour < 9 else 1.0
    return 1.0 

def _decay_time_weight(created_at: datetime.datetime) -> float:
    """Aplica decaimento exponencial de peso baseado no tempo decorrido (horas)."""
    now = datetime.datetime.utcnow()
    hours_diff = (now - created_at).total_seconds() / 3600.0
    decay_factor = 0.05 
    weight = math.exp(-decay_factor * hours_diff)
    return max(0.1, weight)

def _density_weight(reports_count: int, radius_m: int = 200) -> float:
    """Aplica peso de risco baseado na densidade de reports na área."""
    if reports_count < 2: return 1.0
    max_reports_for_full_weight = 15
    max_weight = 1.5
    weight = 1.0 + (max_weight - 1.0) * math.sqrt(min(reports_count, max_reports_for_full_weight) / max_reports_for_full_weight)
    return weight

def _get_risk_category(score: float) -> Dict[str, Any]:
    """Categoriza a pontuação de risco (0-10) em nível e cor."""
    if score >= 7.0: return {"level": "Alto", "color_code": "red"} 
    if score >= 4.0: return {"level": "Médio", "color_code": "orange"}
    if score >= 1.0: return {"level": "Baixo", "color_code": "yellowgreen"}
    return {"level": "Muito Baixo", "color_code": "green"} 

def _get_nearby_reports(lat: float, lng: float, radius_m: int = 200, limit: int = 800) -> List[Report]:
    """Busca relatórios próximos (max 72h de idade) para cálculo de risco."""
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
    # Pré-filtro (bounding box)
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
    nearby = _get_nearby_reports(lat, lng, radius_m=radius_m, limit=800)[:80]

    if not nearby:
        return {"risk_score": 0.0, "reports_count": 0, "risk_category": _get_risk_category(0.0)}

    scores = []
    density_w = _density_weight(len(nearby), radius_m) 

    for r in nearby:
        base = BASE_SCORES.get(r.risk_level, 5.0)
        time_weight = _decay_time_weight(r.created_at)
        tod_weight = _time_of_day_weight(r.created_at)
        final_score = base * time_weight * tod_weight * density_w
        scores.append(final_score)

    risk_score = sum(scores) / len(scores)
    risk_score = max(0.0, min(10.0, risk_score)) # Limita entre 0 e 10

    return {
        "risk_score": round(risk_score, 2), 
        "reports_count": len(nearby),
        "risk_category": _get_risk_category(risk_score)
    }

# ============================================================
# 🗺️ FUNÇÕES DE GEOGRAFIA E ROTA
# ============================================================

def reverse_geocode(lat: float, lng: float) -> Dict[str, Optional[str]]:
    """Busca nome do bairro, cidade e localização específica usando Mapbox."""
    if MAPBOX_TOKEN == "pk.eyJ1IjoicGxhY2Vob2xkZXIiLCJhIjoiY2x3ajVxanhyMW4yMTJpcnNhZG14amJvYSJ9.J5v0L-H5v0L-H5v0L-H5v0L":
        app.logger.warning("MAPBOX_TOKEN não configurado corretamente. Geocoding reverso desativado.")
        return {"neighborhood": None, "city": None, "specific_location": None}

    base_url = "https://api.mapbox.com/geocoding/v5/mapbox.places"
    url = f"{base_url}/{lng},{lat}.json"

    params = {
        "access_token": MAPBOX_TOKEN,
        "types": "address,locality,place,neighborhood", 
        "language": "pt", 
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
            
            # Tenta pegar a localização específica primeiro
            if feature.get("place_type") and ("address" in feature["place_type"] or "poi" in feature["place_type"]):
                specific_location = feature.get("text")
            elif feature.get("text") and not any(t in feature.get("place_type", []) for t in ["neighborhood", "locality", "place"]):
                 specific_location = feature["text"]


            for item in context:
                if 'neighborhood' in item['id']:
                    neighborhood = item['text']
                elif 'place' in item['id'] or 'locality' in item['id']:
                    if not city: 
                        city = item['text']
            
            if not specific_location and feature.get("place_type") and ("neighborhood" in feature["place_type"] or "locality" in feature["place_type"]):
                specific_location = feature["text"]


        return {"neighborhood": neighborhood, "city": city, "specific_location": specific_location}

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Erro no Geocoding Reverso: {e}")
        return {"neighborhood": None, "city": None, "specific_location": None}

def mapbox_route(origin: List[float], destination: List[float], alternative: bool = False) -> Optional[Dict[str, Any]]:
    """Função MOCK para buscar rota na Mapbox (para implementações futuras)."""
    app.logger.info(f"MOCK - Buscando rota Mapbox: {origin} -> {destination}")
    # Simula a resposta do Mapbox Directions API
    return {
        "distance": 5000, 
        "duration": 600, 
        "geometry_coords": [[origin[1], origin[0]], [destination[1], destination[0]]],
        "alternatives": [{"distance": 5500, "duration": 650, "geometry_coords": []}] if alternative else []
    } 

def enrich_route_with_risk(route_data: Dict[str, Any]) -> Dict[str, Any]:
    """Função MOCK para calcular o risco ao longo da rota."""
    # Simula o cálculo de risco. Em uma implementação real, isso calcularia 
    # o risco de vários pontos ao longo da 'geometry_coords'.
    
    # Exemplo: Simula um risco mais alto para a rota alternativa.
    if route_data["type"] == "alternative":
        simulated_risk = 0.3
    else:
        simulated_risk = 0.2

    # Score de 0.0 a 10.0
    simulated_score = 10.0 * simulated_risk 

    route_data["total_risk_score"] = round(simulated_score, 2)
    route_data["risk_category"] = _get_risk_category(simulated_score)
    return route_data

def find_safest_route(origin: List[float], destination: List[float]) -> Dict[str, Any]:
    """Busca a rota padrão e alternativas, calculando o risco para cada uma."""
    
    # 1. Rota Padrão e Alternativas (do Mapbox)
    route_data = mapbox_route(origin, destination, alternative=MAPBOX_ALTERNATIVES)
    if not route_data:
        raise APIError("Não foi possível encontrar a rota.", 503)
        
    # 2. Enriquecimento de Risco
    enriched_main_route = enrich_route_with_risk({
        "type": "main",
        "distance": route_data["distance"],
        "duration": route_data["duration"],
        "coords": route_data["geometry_coords"]
    })
    
    safest_route = enriched_main_route
    alternative_routes = []
    
    for alt in route_data.get("alternatives", []):
        enriched_alt = enrich_route_with_risk({
            "type": "alternative",
            "distance": alt["distance"],
            "duration": alt["duration"],
            "coords": alt["geometry_coords"]
        })
        alternative_routes.append(enriched_alt)
        
        # Compara e define a mais segura (menor risco)
        if enriched_alt["total_risk_score"] < safest_route["total_risk_score"]:
            safest_route = enriched_alt
            
    return {
        "safest_route": safest_route,
        "main_route": enriched_main_route,
        "alternatives": alternative_routes
    }

# ============================================================
# ⚙️ ROTAS / ENDPOINTS
# ============================================================

# ---------- HOME / STATUS ----------

@app.route("/")
def home():
    """Rota principal (ex: página inicial do frontend)."""
    return render_template("inicio.html")

@app.get("/api/status")
def status():
    """Verifica a saúde da API e do banco de dados."""
    try:
        db.session.execute(db.select(User).limit(1)).scalar_one_or_none()
        db_status = "ok"
    except Exception:
        db_status = "error"
    
    return jsonify({
        "status": "online",
        "database": db_status,
        "api_version": "1.0.0",
        "mapbox_configured": MAPBOX_TOKEN != "pk.eyJ1IjoicGxhY2Vob2xkZXIiLCJhIjoiY2x3ajVxanhyMW4yMTJpcnNhZG14amJvYSJ9.J5v0L-H5v0L-H5v0L-H5v0L"
    })

# ---------- AUTH (Clean) ----------

@app.post("/api/register")
def register():
    """Registra um novo usuário (email, password)."""
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        raise APIError("Email e password são obrigatórios.", 400)
        
    if len(password) < 8:
         raise APIError("A senha deve ter pelo menos 8 caracteres.", 400)

    if db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none():
        raise APIError("Email já registrado.", 409)

    user = User(email=email) # Nome usa o default
    user.set_password(password)
    
    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
          db.session.rollback()
          raise APIError("Erro interno ao salvar usuário.", 500)

    return jsonify({
        "message": "Usuário registrado com sucesso", 
        "user_id": user.id
    }), 201


@app.post("/api/login")
def login():
    """Realiza login e retorna o token JWT."""
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        raise APIError("Email e password são obrigatórios.", 400)

    user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none() 
    if not user or not user.check_password(password):
        raise APIError("Credenciais inválidas.", 401)

    token = create_access_token(identity=user.id)
    
    return jsonify({
        "access_token": token, 
        "user_id": user.id
    })

@app.post("/api/logout")
@jwt_required()
def logout():
    """Revoga o token JWT (apenas indica ao cliente para descartar)."""
    response = jsonify({"message": "Logout bem-sucedido"})
    unset_jwt_cookies(response)
    return response


# ---------- REPORTS / RISCO ----------

@app.post("/api/report")
@jwt_required(optional=True)
def create_report():
    """Registra um novo relato de segurança (pode ser anônimo)."""
    user_id = get_jwt_identity() 
    data = request.get_json() or {}

    try:
        lat = float(data.get("latitude"))
        lng = float(data.get("longitude"))
        risk_level = int(data.get("risk_level"))
        comment = data.get("comment", "")
    except (TypeError, ValueError):
        raise APIError("latitude, longitude e risk_level devem ser numéricos.", 400)

    if risk_level not in (1, 2, 3):
        raise APIError("risk_level deve ser 1 (baixo), 2 (médio) ou 3 (alto).", 400)
    
    location_data = reverse_geocode(lat, lng)

    report = Report(
        user_id=user_id,
        latitude=lat,
        longitude=lng,
        risk_level=risk_level,
        comment=comment[:500],
        neighborhood=location_data.get("neighborhood"),
        city=location_data.get("city"),
        specific_location=location_data.get("specific_location")
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
        "context": location_data 
    }), 201


@app.get("/api/risk")
def get_risk_score():
    """Calcula a pontuação de risco para um ponto específico (lat, lng)."""
    try:
        lat = float(request.args.get("lat"))
        lng = float(request.args.get("lng"))
        radius_m = int(request.args.get("radius", 200)) 
    except (TypeError, ValueError):
        raise APIError("lat, lng e radius devem ser numéricos.", 400)
        
    if radius_m > 1000:
        raise APIError("O raio máximo permitido é 1000 metros.", 400)

    result = calculate_risk_score(lat, lng, radius_m)
    return jsonify(result)

@app.get("/api/hotspots")
def get_hotspots():
    """Busca os relatos mais recentes (hotspots) para visualização em mapas."""
    time_limit = datetime.datetime.utcnow() - datetime.timedelta(days=7)
    
    reports = db.session.execute(
        db.select(Report)
        .where(Report.created_at >= time_limit)
        .order_by(desc(Report.created_at))
        .limit(500)
    ).scalars().all()

    hotspots = []
    for r in reports:
        category = _get_risk_category(BASE_SCORES.get(r.risk_level, 5.0))
        
        hotspots.append({
            "id": r.id,
            "lat": r.latitude,
            "lng": r.longitude,
            "risk_level": r.risk_level,
            "color": category["color_code"],
            "created_at": r.created_at.isoformat()
        })
        
    return jsonify({
        "count": len(hotspots),
        "hotspots": hotspots
    })

# ---------- ROTA SEGURA (AVANÇADO) ----------

@app.get("/api/safe_route")
def get_safe_route():
    """Endpoint que busca e compara a rota mais segura com base nos reports (MOCK)."""
    try:
        o_lat = float(request.args.get("o_lat"))
        o_lng = float(request.args.get("o_lng"))
        d_lat = float(request.args.get("d_lat"))
        d_lng = float(request.args.get("d_lng"))
    except (TypeError, ValueError):
        raise APIError("Coordenadas de origem e destino são obrigatórias e devem ser numéricas.", 400)

    origin = [o_lat, o_lng]
    destination = [d_lat, d_lng]
    
    result = find_safest_route(origin, destination)
    
    return jsonify(result)


# ============================================================
# ⚙️ COMANDOS E EXECUÇÃO
# ============================================================

@app.cli.command("init-db")
def init_db_command():
    """Comando para criar o banco de dados: flask --app app.py init-db"""
    with app.app_context():
        db.create_all()
        print("Banco criado / atualizado (sqlite:///wesafe.db).")
        
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="127.0.0.1", port=5000)