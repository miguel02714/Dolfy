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
from sqlalchemy.orm import class_mapper

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

# CORS só para /api/* (o HTML pode vir do próprio Flask ou de outro host)
CORS(app, resources={r"/api/*": {"origins": "*"}})

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

MAPBOX_TOKEN = app.config["MAPBOX_TOKEN"]
MAPBOX_PROFILE = app.config["MAPBOX_PROFILE"]
MAPBOX_ALTERNATIVES = app.config["MAPBOX_ALTERNATIVES"]

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
    Relato de segurança enviado pelo usuário:
    - risk_level: 1 (tranquilo), 2 (médio), 3 (perigoso)
    """
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.Integer, nullable=False)  # 1, 2, 3
    comment = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    user = db.relationship("User", backref="reports", lazy=True)


# ============================================================
# 🛠️ FUNÇÕES UTILITÁRIAS DE CÁLCULO DE RISCO
# ============================================================

# Constantes para a distância Haversine
R_EARTH_METERS = 6371000

def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Distância aproximada em metros entre dois pontos lat/lng.
    """
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
    Dá um peso diferente dependendo do horário (e.g., madrugadas são mais perigosas).
    A curva de peso é mais detalhada.
    """
    hour = dt.hour
    
    # Madrugada (0h - 4h): Peso Máximo
    if 0 <= hour < 5:
        return 1.6
    # Início da Manhã/Noite (5h - 7h, 22h - 23h)
    if 5 <= hour < 7:
        return 1.15 # Início da movimentação, ainda pode ser arriscado
    if 22 <= hour <= 23:
        return 1.45 # Noite avançada
    # Horário Comercial/Dia Claro (9h - 17h): Peso Normal
    if 9 <= hour < 17:
        return 1.0
    # Horário de Pico/Início da Noite (17h - 22h)
    if 17 <= hour < 22:
        return 1.25 # Escurecendo, ainda com movimento
    # Manhã (7h - 9h)
    if 7 <= hour < 9:
        return 1.05
    
    # Padrão, se algo falhar
    return 1.0 


def _get_nearby_reports(lat: float, lng: float, radius_m: int = 200, limit: int = 800) -> List[Report]:
    """
    Busca relatórios próximos. Para maior eficiência, em uma aplicação real, 
    deveria usar índices geoespaciais (PostGIS, etc.) ou uma consulta que 
    pré-filtre por bbox antes de calcular a Haversine.
    """
    # A consulta bruta está otimizada o suficiente para um SQLite simples.
    reports = (
        db.session.execute(
            db.select(Report)
            .order_by(desc(Report.created_at))
            .limit(limit)
        ).scalars().all()
    )

    nearby: List[Report] = []
    
    # Otimização: pré-filtro por bounding box (apenas para fins de demonstração,
    # em bancos mais robustos a query SQL faria isso)
    # 1 grau de lat é ~111km. 200m é ~0.0018 graus.
    degree_radius = radius_m / R_EARTH_METERS * (180 / math.pi) 

    for r in reports:
        # Pré-filtro (pode pular o cálculo Haversine se estiver muito longe)
        if (abs(r.latitude - lat) > degree_radius * 1.5 or 
            abs(r.longitude - lng) > degree_radius * 1.5):
            continue
            
        dist = haversine_distance(lat, lng, r.latitude, r.longitude)
        if dist <= radius_m:
            nearby.append(r)
            
    return nearby


def calculate_risk_score(lat: float, lng: float, radius_m: int = 200) -> Dict[str, Any]:
    """
    Calcula o risco médio em torno de um ponto (lat, lng),
    pegando relatos num raio (em metros).

    A pontuação base foi ajustada e o decaimento temporal está mais agressivo.
    """
    # Busca relatórios próximos (max 80 para a média, mas busca até 800)
    nearby = _get_nearby_reports(lat, lng, radius_m=radius_m, limit=800)
    nearby = nearby[:80] # Limita a 80 relatórios para o cálculo final

    if not nearby:
        return {"risk_score": 0.0, "reports_count": 0}

    now = datetime.datetime.utcnow()
    scores = []

    # Mapeamento da pontuação base:
    # 1 (tranquilo) -> 1.5 (quase nulo)
    # 2 (médio) -> 5.0 
    # 3 (perigoso) -> 9.0 
    BASE_SCORES = {1: 1.5, 2: 5.0, 3: 9.0}

    for r in nearby:
        base = BASE_SCORES.get(r.risk_level, 5.0)

        # Decaimento por tempo (em horas). Mais agressivo.
        hours_diff = (now - r.created_at).total_seconds() / 3600.0
        # Peso do tempo: Cai para 0.2 após ~30 horas.
        time_weight = max(0.2, 1.4 - (hours_diff / 18.0))

        # Peso por horário
        tod_weight = _time_of_day_weight(r.created_at)

        final_score = base * time_weight * tod_weight
        scores.append(final_score)

    risk_score = sum(scores) / len(scores)
    # Limita entre 0 e 10
    risk_score = max(0.0, min(10.0, risk_score))

    return {"risk_score": risk_score, "reports_count": len(nearby)}


# ============================================================
# 🗺️ FUNÇÕES DE ROTA (MAPBOX)
# ============================================================

def mapbox_route(origin: List[float], destination: List[float]) -> Dict[str, Any]:
    """
    Chama a API de rotas da Mapbox, solicitando rotas alternativas.
    origin e destination no formato [lng, lat].
    """
    if MAPBOX_TOKEN == "COLOQUE_SEU_TOKEN_DA_MAPBOX_AQUI":
        raise RuntimeError("Defina o MAPBOX_TOKEN antes de usar /api/safe_route")

    base_url = "https://api.mapbox.com/directions/v5"
    coordinates = f"{origin[0]},{origin[1]};{destination[0]},{destination[1]}"
    url = f"{base_url}/{MAPBOX_PROFILE}/{coordinates}"

    params = {
        "access_token": MAPBOX_TOKEN,
        "geometries": "geojson",
        "overview": "full",
        "steps": False, # Desativar passos grandes
        "alternatives": "true" if MAPBOX_ALTERNATIVES else "false", # Habilita rotas alternativas
        "annotations": "duration,distance"
    }

    try:
        resp = requests.get(url, params=params, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Erro na Mapbox: {e}")
        raise RuntimeError(f"Erro ao chamar Mapbox: {e}")


def enrich_route_with_risk(route_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pega UMA rota da Mapbox e calcula o risco médio
    ao longo do trajeto, amostrando alguns pontos.

    Retorna:
      { "risk_score": 0-10, "risk_points": [...] }
    """
    route = route_data
    coords = route["geometry"]["coordinates"]  # [lng, lat]

    if not coords:
        return {"risk_score": None, "risk_points": []}

    # Amostras ao longo da rota
    risk_points = []
    # No máx ~25-40 pontos por rota.
    step = max(1, len(coords) // 40) 
    
    for i in range(0, len(coords), step):
        lng, lat = coords[i]
        # Cálculo de risco no ponto (raio menor, mais focado)
        info = calculate_risk_score(lat, lng, radius_m=150) 
        risk_points.append({
            "lat": lat,
            "lng": lng,
            "risk_score": info["risk_score"],
            "reports_count": info["reports_count"]
        })

    # Média final
    valid_scores = [p["risk_score"] for p in risk_points if p["risk_score"] is not None]
    avg_score = sum(valid_scores) / len(valid_scores) if valid_scores else 0.0
    
    return {
        "risk_score": avg_score,
        "risk_points": risk_points
    }


def find_safest_route(origin: List[float], destination: List[float]) -> Dict[str, Any]:
    """
    Busca rotas alternativas no Mapbox, calcula o risco de cada uma e
    retorna a rota com a menor pontuação de risco.
    """
    route_json = mapbox_route(origin, destination)
    
    if not route_json.get("routes"):
        return {"route": route_json, "risk_score": None, "risk_points": []}

    all_routes = route_json["routes"]
    enriched_routes = []
    
    # Processa todas as rotas
    for i, route in enumerate(all_routes):
        # A rota Mapbox precisa do "geometry" no mesmo nível da rota, 
        # então enriquecemos um objeto com os dados da rota + risco
        risk_data = enrich_route_with_risk(route)
        
        enriched_routes.append({
            "route_index": i,
            "risk_score": risk_data["risk_score"],
            "duration": route.get("duration"),
            "distance": route.get("distance"),
            "summary": route.get("legs", [{}])[0].get("summary"),
            "geometry": route["geometry"],
            "risk_points": risk_data["risk_points"]
        })
        
    # Ordena: 1. Pelo menor risco, 2. Pela menor duração
    # Se o risco for igual, o tempo de viagem é o desempate.
    enriched_routes.sort(key=lambda x: (x["risk_score"], x["duration"]))
    
    # A rota mais segura é a primeira
    safest_route = enriched_routes[0]
    
    # Retorna o resultado da rota mais segura e lista as alternativas
    return {
        "safest_route": safest_route,
        "alternatives_count": len(all_routes) - 1,
        "all_routes_risk_summary": [{
            "risk_score": r["risk_score"],
            "duration": r["duration"]
        } for r in enriched_routes]
    }


def compute_hotspots(limit=20, cell_size=0.003, min_reports=2):
    """
    Agrupa relatos em 'células' (grid de latitude/longitude) e
    calcula um risco médio por célula.
    """
    # Consulta mais otimizada, apenas o essencial
    reports = db.session.execute(
        db.select(Report.latitude, Report.longitude, Report.risk_level, Report.created_at)
        .order_by(desc(Report.created_at))
        .limit(2000) # Mais dados para a heatmap
    ).all()

    if not reports:
        return []

    cells = defaultdict(list)
    for r in reports:
        cell_lat = round(r.latitude / cell_size) * cell_size
        cell_lng = round(r.longitude / cell_size) * cell_size
        cells[(cell_lat, cell_lng)].append(r)

    hotspots = []
    now = datetime.datetime.utcnow()
    BASE_SCORES = {1: 1.5, 2: 5.0, 3: 9.0}

    for (cell_lat, cell_lng), reps in cells.items():
        if len(reps) < min_reports:
            continue

        scores = []
        for r in reps:
            base = BASE_SCORES.get(r.risk_level, 5.0)
            
            hours_diff = (now - r.created_at).total_seconds() / 3600.0
            time_weight = max(0.2, 1.4 - (hours_diff / 18.0))
            
            tod_weight = _time_of_day_weight(r.created_at)
            scores.append(base * time_weight * tod_weight)

        if not scores:
            continue

        risk = sum(scores) / len(scores)
        risk = max(0.0, min(10.0, risk))

        hotspots.append({
            "lat": cell_lat,
            "lng": cell_lng,
            "risk_score": risk,
            "reports_count": len(reps),
        })

    # ordena dos mais perigosos para os menos
    hotspots.sort(key=lambda x: x["risk_score"], reverse=True)
    return hotspots[:limit]


# ============================================================
# ⚙️ ROTAS / ENDPOINTS
# ============================================================

# Serve o frontend principal
@app.route("/")
def home():
    # Retorna o template, garantindo que 'inicio.html' existe
    return render_template("inicio.html")


# ---------- AUTH ----------

@app.post("/api/register")
def register():
    # ... (lógica de registro original) ...
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "email e password são obrigatórios"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "email já registrado"}), 400

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "usuário criado com sucesso"}), 201


@app.post("/api/login")
def login():
    # ... (lógica de login original) ...
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "email e password são obrigatórios"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "credenciais inválidas"}), 401

    token = create_access_token(identity=user.id)
    return jsonify({"access_token": token, "user_id": user.id})


# ---------- REPORTS / RISCO ----------

@app.post("/api/report")
@jwt_required(optional=True)
def create_report():
    # ... (lógica de criação de report original) ...
    user_id = get_jwt_identity()
    data = request.get_json() or {}

    lat = data.get("latitude")
    lng = data.get("longitude")
    risk_level = data.get("risk_level")
    comment = data.get("comment", "")

    if lat is None or lng is None or risk_level not in (1, 2, 3):
        return jsonify({"error": "latitude, longitude e risk_level (1/2/3) são obrigatórios"}), 400

    report = Report(
        user_id=user_id,
        latitude=float(lat),
        longitude=float(lng),
        risk_level=int(risk_level),
        comment=comment[:500]
    )
    db.session.add(report)
    db.session.commit()

    return jsonify({"message": "relato registrado com sucesso", "id": report.id})


@app.get("/api/risk")
def get_risk():
    """
    Consulta risco numa coordenada:
      /api/risk?lat=-23.55&lng=-46.63
    """
    try:
        lat = float(request.args.get("lat"))
        lng = float(request.args.get("lng"))
    except (TypeError, ValueError):
        return jsonify({"error": "lat e lng são obrigatórios e numéricos"}), 400

    info = calculate_risk_score(lat, lng, radius_m=200)
    return jsonify({
        "latitude": lat,
        "longitude": lng,
        "risk_score": info["risk_score"],
        "reports_count": info["reports_count"]
    })


@app.get("/api/hotspots")
def hotspots():
    """
    Retorna os principais 'hotspots' de risco da cidade / região.
    """
    limit = int(request.args.get("limit", 20))
    data = compute_hotspots(limit=limit)
    return jsonify({"hotspots": data})


# ---------- ROTA SEGURA (AVANÇADO) ----------

@app.post("/api/safe_route")
def safe_route():
    """
    Busca múltiplas rotas (via Mapbox) e retorna a que tiver o menor
    risco médio.

    JSON de entrada:
      {
        "origin": [-46.63, -23.55],
        "destination": [-46.70, -23.60]
      }
    """
    data = request.get_json() or {}
    origin = data.get("origin")
    destination = data.get("destination")

    if (
        not origin or not destination
        or len(origin) != 2 or len(destination) != 2
    ):
        return jsonify({"error": "origin e destination devem ser [lng, lat]"}), 400

    try:
        origin = [float(origin[0]), float(origin[1])]
        destination = [float(destination[0]), float(destination[1])]
    except (TypeError, ValueError):
        return jsonify({"error": "origin e destination devem conter números"}), 400

    try:
        # Usa a nova função que calcula e compara o risco entre as rotas
        result = find_safest_route(origin, destination)
        return jsonify(result)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        app.logger.exception("Erro desconhecido ao processar rota segura")
        return jsonify({"error": "Erro interno ao calcular rota segura"}), 500


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