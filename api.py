from flask import Flask, jsonify, request
import jwt
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
SECRET_KEY = 'your_secret_key'

users = [
    {"id": 1, "name": "David Peterson", "email": "david@gmail.com", "role": "Admin"},
    {"id": 2, "name": "Emma Johnson", "email": "emma@gmail.com", "role": "User"},
    {"id": 3, "name": "Olivia Brown", "email": "olivia@gmail.com", "role": "User"},
    {"id": 4, "name": "Liam White", "email": "liam@gmail.com", "role": "User"},
    {"id": 5, "name": "Sophia Adams", "email": "sophia@gmail.com", "role": "User"}
]

def generate_token(user):
    payload = {
        'user_id': user['id'],
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        try:
            decoded = jwt.decode(token.split()[1], SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        return f(decoded, *args, **kwargs)
    return decorated

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapped(decoded, *args, **kwargs):
            if decoded['role'] != role:
                return jsonify({'message': 'Permission denied'}), 403
            return f(decoded, *args, **kwargs)
        return wrapped
    return decorator

@app.route("/api/users", methods=["GET"])
@token_required
@role_required("Admin")
def get_users(decoded):
    return jsonify(users)

@app.route("/api/users", methods=["POST"])
@token_required
def create_user(decoded):
    new_user = request.json
    new_user["id"] = max([u["id"] for u in users], default=0) + 1
    users.append(new_user)
    return jsonify(new_user), 201

@app.route("/api/users/<int:user_id>", methods=["PATCH"])
@token_required
def update_user(decoded, user_id):
    user = next((u for u in users if u["id"] == user_id), None)
    if user:
        user.update(request.json)
        return jsonify(user)
    return jsonify({"error": "User not found"}), 404

@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@token_required
@role_required("Admin")
def delete_user(decoded, user_id):
    global users
    user = next((u for u in users if u["id"] == user_id), None)
    if not user:
        return jsonify({"error": "User not found"}), 404
    users = [u for u in users if u["id"] != user_id]
    return jsonify({"message": "User deleted"})

@app.route("/api/login", methods=["POST"])
def login():
    auth = request.json
    user = next((u for u in users if u['email'] == auth.get("email")), None)
    if user:
        token = generate_token(user)
        return jsonify({"token": token})
    return jsonify({"message": "Invalid credentials"}), 401

if __name__ == "__main__":
    app.run(debug=True)
