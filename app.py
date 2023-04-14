from flask import Flask, request, jsonify
from models import db, User
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors  import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['JWT_SECRET_KEY'] = "super-secreta"
db.init_app(app)

migrate = Migrate(app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

@app.route("/")
def home():
    return "Hola Mundo"

# USER

# POST

@app.route("/users", methods=["POST"])
def create_user():
    # Obtiene los datos del usuario de la solicitud
    name = request.json.get("name")
    last_name = request.json.get("last_name")
    email = request.json.get("email")
    phone = request.json.get("phone")
    password = request.json.get("password")
    password_hash = generate_password_hash(password)
    password = password_hash

    # Verifica si el correo ya existe en la base de datos
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify("El correo ya existe en la base de datos"), 400

    # Crea un nuevo objeto User
    new_user = User(name=name, last_name=last_name, email=email,
                    phone=phone, password=password)

    # Agrega el usuario a la sesión de la base de datos
    db.session.add(new_user)
    db.session.commit()

    # Devuelve una respuesta con código de estado HTTP 201
    return jsonify("Usuario guardado"), 201

# LOGIN


@app.route("/login", methods=["POST"])
def login():
    email = request.json.get("email")
    password = request.json.get("password")
    user = User.query.filter_by(email=email).first()
    if user is not None:
        is_valid = check_password_hash(user.password, password)
        if is_valid:
            access_token = create_access_token(identity=email)
            return jsonify({
                "token": access_token,
                "user_id": user.id,
                "email": user.email,

            }), 200
        else:
            return jsonify("La contraseña es incorrecta"), 400
    else:
        return jsonify("El usuario no existe o la información es inválida"), 400


# GET

@app.route("/users/list", methods=["GET"])
def get_users():
    users = User.query.all()
    result = []
    for user in users:
        result.append(user.serialize())
    return jsonify(result)

# GET USER BY ID


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user is not None:
        return jsonify(user.serialize())
    else:
        return jsonify("Usuario no encontrado"), 404


# PUT & DELETE

@app.route("/users/<int:id>", methods=["PUT", "DELETE"])
@jwt_required
def update_user(id):    
    user = User.query.get(id)    
    if user is not None:
        if request.method == "DELETE":
            db.session.delete(user)
            db.session.commit()
            return jsonify("Usuario eliminado"), 204

        else:
            user.name = request.json.get("name")
            user.last_name = request.json.get("last_name")
            user.phone = request.json.get("phone")
            user.email = request.json.get("email", user.email)
            user.rol_id = request.json.get("rol_id", user.rol_id)
            user.password = request.json.get("password", user.password)

            db.session.commit()
            return jsonify("Usuario actualizado"), 200
    return jsonify("Usuario no encontrado"), 404


if __name__=="__main__":
    app.run(host="localhost", port="8080")