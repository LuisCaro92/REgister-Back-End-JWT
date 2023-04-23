from flask import Flask, request, jsonify
from models import db, User
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors  import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['JWT_SECRET_KEY'] = "secret_key"
db.init_app(app)

migrate = Migrate(app, db)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
CORS(app)

@app.route("/")
def home():
    return "Test"


@app.route("/users", methods=["POST"])
def create_user():
    name = request.json.get("name")
    last_name = request.json.get("last_name")
    email = request.json.get("email")
    phone = request.json.get("phone")
    password = request.json.get("password")
    password_hash = generate_password_hash(password)
    password = password_hash

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify("Email not valid"), 400

    new_user = User(name=name, last_name=last_name, email=email,
                    phone=phone, password=password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify("User created"), 201



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
            return jsonify("Password incorrect"), 400
    else:
        return jsonify("Not valid"), 400


# GET

@app.route("/users/list", methods=["GET"])
def get_users():
    users = User.query.all()
    result = []
    for user in users:
        result.append(user.serialize())
    return jsonify(result)


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user is not None:
        return jsonify(user.serialize())
    else:
        return jsonify("User not found"), 404


@app.route("/users/<int:id>", methods=["PUT", "DELETE"])
def update_user(id):    
    user = User.query.get(id)    
    if user is not None:
        if request.method == "DELETE":
            db.session.delete(user)
            db.session.commit()
            return jsonify("User deleted"), 204

        else:
            user.name = request.json.get("name")
            user.last_name = request.json.get("last_name")
            user.phone = request.json.get("phone")
            user.email = request.json.get("email", user.email)
            user.password = request.json.get("password", user.password)

            db.session.commit()
            return jsonify("User updated"), 200
    return jsonify("User not found"), 404


if __name__=="__main__":
    app.run(host="localhost", port="3000")