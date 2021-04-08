from flask import Flask, request,jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from flask_cors import CORS, cross_origin
from flask import session
import pymysql
import datetime
import time

app = Flask(__name__)
CORS(app)
db = SQLAlchemy()

app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:sdp150516@localhost:3306/todo'


@app.before_first_request
def createTable():
    db.create_all()
    db.session.commit()


class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(70), nullable=False)
    lastname = db.Column(db.String(70), nullable=False)
    phone = db.Column(db.String(10), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200))
    admin = db.Column(db.Boolean)


class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(70), nullable=False)
    subname = db.Column(db.String(70), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        print(token)

        if not token:

            return jsonify({'message': 'a valid token is missing'})

        try:
            print("hello checked")
            data = jwt.decode(token, app.config['SECRET_KEY'])
            print("check")
            print(data)
            current_user = Users.query.filter_by(id=data['id']).first()

            abc = current_user.name

            print("+++++++++++")
            print(abc)
            print("+++++++++++")
            # a = session(abc)

        except Exception as err:
            print("+++===========")
            print(err)
            print("+++===========")

            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator



@app.route('/register', methods=['POST'])
def signup_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = Users(name=data['name'],lastname=data['lastname'],phone=data['phone'],username=data['username'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['POST'])
def login_user():
    auth = request.get_json()
    user = Users.query.filter_by(username=auth.get("username")).first()
    print(user)
    if check_password_hash(user.password, auth.get("password")):
        token = jwt.encode({'id': user.id, 'admin': user.admin, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/add_task', methods=['POST'])
@token_required
def create_task(current_user):
    user_id = current_user.id
    print("*******")
    print(user_id)
    data = request.get_json()
    new_task = Task(name=data['name'],
                    subname=data['subname'],user_id=user_id)
    db.session.add(new_task)
    db.session.commit()

    return jsonify({'message': 'new task created'})

@app.route('/task/all', methods=['GET'])
@token_required
def get_task(current_user):
    user_id = current_user.id
    print("%%^^&&&&&")
    print(user_id)
    tasks = Task.query.filter_by(user_id=user_id).all()

    list_of_task = []
    for task in tasks:

        task_data = {}
        task_data['id'] = task.id
        task_data['name'] = task.name
        task_data['subname'] = task.subname
        list_of_task.append(task_data)

    return jsonify(list_of_task)



@app.route('/task/<id>', methods=['PUT'])
@token_required
def update_task(current_user,id):
    task = request.get_json()
    get_task = Task.query.filter_by(id=id).first()

    if task.get('name'):
        get_task.name = task['name']
    if task.get('subname'):
        get_task.subname = task['subname']

    db.session.add(get_task)
    db.session.commit()

    return make_response(jsonify({"task": task}))

@app.route('/task/<task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user,task_id):
    task = Task.query.filter_by(id=task_id).first()
    if not task:
        return jsonify({'message': 'Task does not exist'})
    db.session.delete(task)
    db.session.commit()

    return jsonify({'message': 'Task deleted'})




if __name__ == '__main__':
    db.init_app(app)
    app.run()
