
# A very simple Flask Hello World app for you to get started with...

from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from firebase_admin import credentials, initialize_app, db
from flask_login import login_required, current_user, login_user, logout_user, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# init SQLAlchemy so we can use it later in our models
sqldb = SQLAlchemy()


app = Flask(__name__)
app.config['SECRET_KEY'] = 'orq2uqeTH@cWD6'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqldb.sqlite'
sqldb.init_app(app)


login_manager = LoginManager()
login_manager.login_view = 'app.login'
login_manager.init_app(app)

class User(UserMixin, sqldb.Model):
    id = sqldb.Column(sqldb.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    name = sqldb.Column(sqldb.String(100), unique=True)
    password = sqldb.Column(sqldb.String(100))
    email = sqldb.Column(sqldb.String(1000))



@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))



# Initialize Firestore DB
cred = credentials.Certificate('/home/pauler/mysite/key.json')
default_app = initialize_app(cred, {
    'databaseURL':'https://pauler-kapunyito-default-rtdb.europe-west1.firebasedatabase.app/'
    })

## get the root
ref = db.reference("/")
print(ref.get())

##default_app = initialize_app(cred)
##db = firestore.client()
##todo_ref = db.collection('todos')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    userName = request.form.get('user')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False


    user = User.query.filter_by(name=userName).first()


    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    #if not user==user_app or not pass_app==password:
    if not user or not check_password_hash(user.password, password):
    #if not user==user_app or not check_password_hash(pass_app, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('login')) # if user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('pauler'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
def hello_pauler():
    return redirect(url_for('login'))


@app.route('/pauler')
@login_required
def pauler():
    return render_template('pauler.html')


@app.route('/update', methods=['POST'])
@login_required
def update():

    """
        update() : Update document in Firestore collection with request body
        Ensure you pass a custom ID as part of json body in post request
        e.g. json={'id': '1', 'title': 'Write a blog post today'}
    """
    try:
        users_ref =db.reference("/board1/outputs")
        users_ref.child('digital').update({"14":1})


        return jsonify({"success": True}), 200
    except Exception as e:
        return f"An Error Occured: {e}"

@app.route('/list', methods=['GET'])
def read():
    """
        read() : Fetches documents from Firestore collection as JSON
        todo : Return document that matches query ID
        all_todos : Return all documents

    """
    try:
        # Check if ID was passed to URL query
        todo_id = request.args.get('id')
        if todo_id:
            todo = ref.get()
            return jsonify(todo), 200
        else:
            all_todos = [doc for doc in ref.stream()]
            return jsonify(all_todos), 200
    except Exception as e:
        return f"An Error Occured: {e}"

