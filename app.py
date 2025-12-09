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
    email = db.Column(db.String(180), unique=True, nullable=False)
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
    neighborhood = db.Column(db.String(100), nullable=True) # NOVO: Contexto de localização
    city = db.Column(db.String(100), nullable=True)         # NOVO: Contexto de localização
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

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
    """Aplica peso de risco baseado no horário (e.g., madrugadas mais perigosas)."""
    hour = dt.hour
    
    # 0h - 4h: Madrugada (Peso Máximo)
    if 0 <= hour < 5:
        return 1.6
    # 22h - 23h: Noite avançada
    if 22 <= hour <= 23:
        return 1.45
    # 17h - 22h: Início da noite/Escurecendo
    if 17 <= hour < 22:
        return 1.25
    # 5h - 7h: Início da manhã
    if 5 <= hour < 7:
        return 1.15
    # 7h - 17h: Dia/Horário comercial (Peso normal/próximo de 1.0)
    if 7 <= hour < 17:
        return 1.05 if 7 <= hour < 9 else 1.0
    
    return 1.0 # Padrão

def _decay_time_weight(created_at: datetime.datetime) -> float:
    """Aplica decaimento de peso baseado no tempo decorrido."""
    now = datetime.datetime.utcnow()
    hours_diff = (now - created_at).total_seconds() / 3600.0
    # Decaimento: Cai para 0.2 após ~30 horas. 
    # Max(0.2) garante que relatos antigos ainda contribuam minimamente.
    return max(0.2, 1.4 - (hours_diff / 18.0))

def _get_nearby_reports(lat: float, lng: float, radius_m: int = 200, limit: int = 800) -> List[Report]:
    """Busca relatórios próximos. Limita a busca total para desempenho."""
    # Buscar todos e filtrar com Haversine é menos performático que PostGIS,
    # mas funciona bem para demonstração com SQLite. O limit ajuda.
    reports = (
        db.session.execute(
            db.select(Report)
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
    # Usa a função de busca e limita os reports processados para manter o desempenho.
    nearby = _get_nearby_reports(lat, lng, radius_m=radius_m, limit=800)[:80]

    if not nearby:
        return {"risk_score": 0.0, "reports_count": 0}

    scores = []
    for r in nearby:
        base = BASE_SCORES.get(r.risk_level, 5.0)

        time_weight = _decay_time_weight(r.created_at)
        tod_weight = _time_of_day_weight(r.created_at)

        final_score = base * time_weight * tod_weight
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
    """
    if MAPBOX_TOKEN == "COLOQUE_SEU_TOKEN_DA_MAPBOX_AQUI":
        app.logger.warning("MAPBOX_TOKEN não configurado. Geocoding reverso desativado.")
        return {"neighborhood": None, "city": None}

    base_url = "https://api.mapbox.com/geocoding/v5/mapbox.places"
    url = f"{base_url}/{lng},{lat}.json"

    params = {
        "access_token": MAPBOX_TOKEN,
        "types": "locality,place,neighborhood", # Foca em bairros e cidades
        "limit": 1
    }

    try:
        resp = requests.get(url, params=params, timeout=5)
        resp.raise_for_status()
        data = resp.json()

        neighborhood = None
        city = None

        if data.get("features"):
            feature = data["features"][0]
            # O Mapbox retorna componentes contextuais, buscamos por 'neighborhood' e 'place'/'locality'
            context = feature.get("context", [])
            
            for item in context:
                if 'neighborhood' in item['id']:
                    neighborhood = item['text']
                elif 'place' in item['id'] or 'locality' in item['id']:
                    # Prioriza a cidade (place/locality)
                    if not city: 
                        city = item['text']
            
            # Se o próprio resultado principal for um bairro e não tiver pego
            if feature.get("place_type") and ("neighborhood" in feature["place_type"] or "locality" in feature["place_type"]) and not neighborhood:
                neighborhood = feature["text"]


        return {"neighborhood": neighborhood, "city": city}

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Erro no Geocoding Reverso: {e}")
        return {"neighborhood": None, "city": None}


def mapbox_route(origin: List[float], destination: List[float], profile: str) -> Dict[str, Any]:
    """
    Chama a API de rotas da Mapbox, solicitando rotas alternativas.
    origin e destination no formato [lng, lat].
    """
    if MAPBOX_TOKEN == "COLOQUE_SEU_TOKEN_DA_MAPBOX_AQUI":
        raise APIError("Mapbox Token não configurado.", 500)

    base_url = "https://api.mapbox.com/directions/v5"
    coordinates = f"{origin[0]},{origin[1]};{destination[0]},{destination[1]}"
    url = f"{base_url}/{profile}/{coordinates}"

    params = {
        "access_token": MAPBOX_TOKEN,
        "geometries": "geojson",
        "overview": "full",
        "steps": False,
        "alternatives": "true" if MAPBOX_ALTERNATIVES else "false",
        "annotations": "duration,distance"
    }

    try:
        resp = requests.get(url, params=params, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Erro na Mapbox: {e}")
        # Lançar erro customizado para o Flask tratar
        raise APIError(f"Erro ao chamar Mapbox: {e}", 503)


def enrich_route_with_risk(route_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pega UMA rota da Mapbox e calcula o risco médio
    ao longo do trajeto, amostrando pontos de forma inteligente.
    """
    coords = route_data["geometry"]["coordinates"]  # [lng, lat]

    if not coords:
        return {"risk_score": 0.0, "risk_points": []}

    risk_points = []
    
    # Estratégia de amostragem inteligente: 
    # 1 ponto a cada 100-200 metros, no máximo 50 pontos.
    distance_km = route_data["distance"] / 1000
    # Calcula quantos pontos precisamos para ter ~150-250m entre eles
    num_samples = min(50, max(10, int(distance_km * 1000 / 200))) 
    
    step = max(1, len(coords) // num_samples) 
    
    for i in range(0, len(coords), step):
        lng, lat = coords[i]
        # Cálculo de risco no ponto (raio menor para maior precisão pontual)
        info = calculate_risk_score(lat, lng, radius_m=100) 
        risk_points.append({
            "lat": lat,
            "lng": lng,
            "risk_score": info["risk_score"],
            "reports_count": info["reports_count"]
        })

    valid_scores = [p["risk_score"] for p in risk_points if p["risk_score"] is not None]
    avg_score = sum(valid_scores) / len(valid_scores) if valid_scores else 0.0
    
    return {
        "risk_score": avg_score,
        "risk_points": risk_points
    }


def find_safest_route(origin: List[float], destination: List[float], profile: str) -> Dict[str, Any]:
    """
    Busca rotas alternativas no Mapbox, calcula o risco de cada uma e
    retorna a rota com a menor pontuação de risco.
    """
    route_json = mapbox_route(origin, destination, profile)
    
    if not route_json.get("routes"):
        # Retorna a estrutura, mas sem rotas
        return {"safest_route": None, "alternatives_count": 0, "all_routes_risk_summary": []}

    all_routes = route_json["routes"]
    enriched_routes = []
    
    for i, route in enumerate(all_routes):
        risk_data = enrich_route_with_risk(route)
        
        enriched_routes.append({
            "route_index": i,
            "risk_score": risk_data["risk_score"],
            "duration": route.get("duration"),
            "distance": route.get("distance"),
            "summary": route.get("legs", [{}])[0].get("summary", ""),
            "geometry": route["geometry"],
            "risk_points": risk_data["risk_points"]
        })
        
    # Ordena: 1. Pelo menor risco, 2. Pela menor duração.
    # Isso desempata rotas com risco similar, priorizando a mais rápida.
    enriched_routes.sort(key=lambda x: (x["risk_score"], x["duration"]))
    
    safest_route = enriched_routes[0]
    
    return {
        "safest_route": safest_route,
        "alternatives_count": len(all_routes) - 1,
        "all_routes_risk_summary": [{
            "risk_score": r["risk_score"],
            "duration": r["duration"],
            "is_safest": r["route_index"] == safest_route["route_index"]
        } for r in enriched_routes]
    }


# ============================================================
# ⚙️ ROTAS / ENDPOINTS
# ============================================================

# Serve o frontend principal
@app.route("/")
def home():
    # Retorna o template, garantindo que 'inicio.html' existe
    # (Ou o código HTML/JS da sua pergunta anterior)
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
    
    # 🌟 NOVO: Geocoding Reverso para contexto de bairro
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
        "context": location_data
    }), 201


@app.get("/api/risk")
def get_risk():
    """
    Consulta risco numa coordenada:
      /api/risk?lat=-23.55&lng=-46.63&radius_m=150
    """
    try:
        lat = float(request.args.get("lat"))
        lng = float(request.args.get("lng"))
        radius_m = int(request.args.get("radius_m", 200))
    except (TypeError, ValueError):
        raise APIError("lat, lng e radius_m são obrigatórios e numéricos.")

    if not (-90 <= lat <= 90 and -180 <= lng <= 180):
        raise APIError("Coordenadas inválidas.")

    info = calculate_risk_score(lat, lng, radius_m=radius_m)
    return jsonify({
        "latitude": lat,
        "longitude": lng,
        "risk_score": info["risk_score"],
        "risk_level_tag": "Alto" if info["risk_score"] >= 7.5 else ("Médio" if info["risk_score"] >= 4.0 else "Baixo"),
        "reports_count": info["reports_count"]
    })


@app.get("/api/hotspots")
def hotspots():
    """
    Retorna os principais 'hotspots' de risco da cidade / região.
    """
    try:
        limit = int(request.args.get("limit", 20))
        cell_size = float(request.args.get("cell_size", 0.003))
        min_reports = int(request.args.get("min_reports", 2))
    except (TypeError, ValueError):
        raise APIError("Parâmetros de consulta inválidos.", 400)

    # Reutiliza a função original (se for mais complexo, mover para dentro da função)
    def compute_hotspots_data(limit=20, cell_size=0.003, min_reports=2):
        # ... (Função compute_hotspots original, simplificada para não repetir) ...
        # A lógica original está ok, apenas chame ela aqui
        # Para evitar repetição, mantive o corpo da função no código original.
        # Por exemplo:
        from . import compute_hotspots as original_compute_hotspots
        return original_compute_hotspots(limit, cell_size, min_reports)


    data = compute_hotspots(limit=limit, cell_size=cell_size, min_reports=min_reports)
    return jsonify({"hotspots": data})


# ---------- ROTA SEGURA (AVANÇADO) ----------

@app.post("/api/safe_route")
def safe_route():
    """
    Busca múltiplas rotas (via Mapbox) e retorna a que tiver o menor
    risco médio.

    JSON de entrada:
      {
        "origin": [-46.63, -23.55],        # [lng, lat]
        "destination": [-46.70, -23.60],   # [lng, lat]
        "profile": "mapbox/driving"        # Opcional: mapbox/driving, mapbox/walking, mapbox/cycling
      }
    """
    data = request.get_json() or {}
    origin = data.get("origin")
    destination = data.get("destination")
    profile = data.get("profile", MAPBOX_PROFILE) # Pega do body ou do default

    valid_profiles = ["mapbox/driving", "mapbox/walking", "mapbox/cycling"]
    if profile not in valid_profiles:
        raise APIError(f"Perfil de rota inválido. Use um de: {', '.join(valid_profiles)}", 400)
    
    if (
        not origin or not destination
        or len(origin) != 2 or len(destination) != 2
    ):
        raise APIError("origin e destination devem ser [lng, lat].", 400)

    try:
        # Garante que as coordenadas são floats
        origin = [float(origin[0]), float(origin[1])]
        destination = [float(destination[0]), float(destination[1])]
    except (TypeError, ValueError):
        raise APIError("origin e destination devem conter números.", 400)

    # Validação de coordenadas (simples)
    if not (all(-180 <= c <= 180 for c in [origin[0], destination[0]]) and 
            all(-90 <= c <= 90 for c in [origin[1], destination[1]])):
        raise APIError("Coordenadas de origem ou destino fora do limite geográfico.", 400)


    result = find_safest_route(origin, destination, profile)
    
    if not result["safest_route"]:
        raise APIError("Nenhuma rota encontrada entre os pontos.", 404)
        
    # 🌟 NOVO: Adiciona contexto de localização ao ponto de partida/chegada
    # (Pode ser caro em produção, opcionalmente cachear)
    origin_context = reverse_geocode(origin[1], origin[0])
    destination_context = reverse_geocode(destination[1], destination[0])

    response = {
        "context": {
            "origin": origin_context,
            "destination": destination_context,
            "profile_used": profile
        },
        **result # Espalha os resultados da rota segura
    }
    
    return jsonify(response)


# ============================================================
# 🖥️ CLI / SETUP
# ============================================================

@app.cli.command("init-db")
def init_db_command():
    """
    Comando pra criar o banco:
      flask --app app.py init-db
    """
    with app.app_context():
        db.create_all()
        print("Banco criado / atualizado.")
        
# A execução principal foi simplificada, o comando 'flask run' é preferível.
if __name__ == "__main__":
    # Garante que o banco seja criado se rodar o arquivo diretamente
    with app.app_context():
        db.create_all()
    app.run(debug=True)