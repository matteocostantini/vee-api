from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, abort
from flask_restx import Api, Resource, fields, Namespace
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import datetime
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from authlib.oauth2.rfc6749 import grants
from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.oauth2.rfc6750 import BearerTokenValidator
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jobs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Cambia con una chiave segreta sicura

CORS(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@app.route('/', methods=['POST', 'GET'])
@login_required
def main_page():
    return render_template('index.html')

authorizations = {
    'Bearer Auth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': 'Add "Bearer " before your token'
    }
}



api = Api(app, version='1.0', title='Job Data API',
          description='API per gestire i dati dei job',
          doc='/docs/api',
          authorizations=authorizations,
          security='Bearer Auth')

jobs_ns = Namespace('jobs', description='Operazioni API sui job')
auth_ns = Namespace('auth', description='Operazioni di autenticazione')

job_model = api.model('Job', {
    'start_time': fields.String(required=True, description='Ora di inizio'),
    'end_time': fields.String(required=True, description='Ora di fine'),
    'state': fields.String(required=True, description='Stato del job'),
    'details': fields.String(required=True, description='Dettagli del job'),
    'job_id': fields.String(required=True, description='ID del job'),
    'job_name': fields.String(required=True, description='Nome del job'),
    'processed': fields.String(required=True, description='Dati processati'),
    'read': fields.String(required=True, description='Dati letti'),
    'transferred': fields.String(required=True, description='Dati trasferiti'),
    'speed': fields.String(required=True, description='Velocità di elaborazione'),
    'source_load': fields.String(required=True, description='Carico sorgente'),
    'source_processing_load': fields.String(required=True, description='Carico CPU sorgente'),
    'network_load': fields.String(required=True, description='Carico rete'),
    'target_load': fields.String(required=True, description='Carico destinazione'),
    'bottleneck': fields.String(required=True, description='Collo di bottiglia'),
    'duration': fields.String(required=True, description='Durata del job')
})

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.String, nullable=False)
    end_time = db.Column(db.String, nullable=False)
    state = db.Column(db.String, nullable=False)
    details = db.Column(db.String, nullable=False)
    job_id = db.Column(db.String, nullable=False)
    job_name = db.Column(db.String, nullable=False)
    processed = db.Column(db.String, nullable=False)
    read = db.Column(db.String, nullable=False)
    transferred = db.Column(db.String, nullable=False)
    speed = db.Column(db.String, nullable=False)
    source_load = db.Column(db.String, nullable=False)
    source_processing_load = db.Column(db.String, nullable=False)
    network_load = db.Column(db.String, nullable=False)
    target_load = db.Column(db.String, nullable=False)
    bottleneck = db.Column(db.String, nullable=False)
    duration = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class RevokedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String, nullable=False, unique=True)
    revoked_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

class OAuth2Client(db.Model, OAuth2ClientMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

with app.app_context():
    db.create_all()

def is_token_revoked(token):
    return RevokedToken.query.filter_by(token=token).first() is not None

def ip_whitelisted(f):
    def decorator(*args, **kwargs):
        whitelist = ['127.0.0.1']  # Replace with the IP you want to allow
        if request.remote_addr not in whitelist:
            return abort(403)
        return f(*args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            if not next_page or not is_safe_url(next_page):
                return redirect(url_for('main_page'))
            return redirect(next_page)
        flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/jobs')
@ip_whitelisted
@login_required
def jobs():
    return render_template('jobs.html')

@jobs_ns.route('/jobs_data')
class JobsData(Resource):
    #@jobs_ns.doc(security='Bearer Auth')
    @jobs_ns.response(200, 'Success')
    @jobs_ns.response(401, 'Non autorizzato')
    @login_required
    def get(self):
        """Restituisce i dati dei job in formato paginabile per DataTables"""
 #       auth_header = request.headers.get('Authorization')
 #       if not auth_header:
 #           return {'error': 'Unauthorized'}, 401
        
  #      token = auth_header.split(" ")[1]
  #      if is_token_revoked(token):
  #          return {'error': 'Unauthorized'}, 401

  #      try:
 #           jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
  #      except jwt.ExpiredSignatureError:
   #         return {'error': 'Token expired'}, 401
  #      except jwt.InvalidTokenError:
    #        return {'error': 'Invalid token'}, 401

        draw = request.args.get('draw', type=int)
        start = request.args.get('start', type=int)
        length = request.args.get('length', type=int)

        query = Job.query
        total_records = query.count()
        jobs = query.offset(start).limit(length).all()

        jobs_list = [{'id': job.id, 'start_time': job.start_time, 'end_time': job.end_time,
                      'state': job.state, 'details': job.details, 'job_id': job.job_id,
                      'job_name': job.job_name, 'processed': job.processed, 'read': job.read,
                      'transferred': job.transferred, 'speed': job.speed, 'source_load': job.source_load,
                      'source_processing_load': job.source_processing_load, 'network_load': job.network_load,
                      'target_load': job.target_load, 'bottleneck': job.bottleneck, 'duration': job.duration,
                      'created_at': job.created_at.isoformat()} for job in jobs]

        return {
            'draw': draw,
            'recordsTotal': total_records,
            'recordsFiltered': total_records,
            'data': jobs_list
        }, 200

@jobs_ns.route('/')
class JobResource(Resource):
    @jobs_ns.doc(security='Bearer Auth')
    @jobs_ns.expect(job_model, validate=True)
    @jobs_ns.response(200, 'Dati ricevuti con successo')
    @jobs_ns.response(401, 'Non autorizzato')
    @jobs_ns.response(400, 'Payload non valido')
    def post(self):
        """Riceve i dati del job"""
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return {'error': 'Unauthorized'}, 401
        
        token = auth_header.split(" ")[1]
        if is_token_revoked(token):
            return {'error': 'Unauthorized'}, 401

        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return {'error': 'Token expired'}, 401
        except jwt.InvalidTokenError:
            return {'error': 'Invalid token'}, 401

        job_data = request.get_json()
        if not job_data:
            return {'error': 'Invalid payload'}, 400

        new_job = Job(
            start_time=job_data['start_time'],
            end_time=job_data['end_time'],
            state=job_data['state'],
            details=job_data['details'],
            job_id=job_data['job_id'],
            job_name=job_data['job_name'],
            processed=job_data['processed'],
            read=job_data['read'],
            transferred=job_data['transferred'],
            speed=job_data['speed'],
            source_load=job_data['source_load'],
            source_processing_load=job_data['source_processing_load'],
            network_load=job_data['network_load'],
            target_load=job_data['target_load'],
            bottleneck=job_data['bottleneck'],
            duration=job_data['duration']
        )
        db.session.add(new_job)
        db.session.commit()
        
        return {'message': 'Dati ricevuti con successo'}, 200

    @jobs_ns.doc(security='Bearer Auth')
    @jobs_ns.response(200, 'Success')
    @jobs_ns.response(401, 'Non autorizzato')
    def get(self):
        """Restituisce l'elenco dei job"""
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return {'error': 'Unauthorized'}, 401
        
        token = auth_header.split(" ")[1]
        if is_token_revoked(token):
            return {'error': 'Unauthorized'}, 401

        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return {'error': 'Token expired'}, 401
        except jwt.InvalidTokenError:
            return {'error': 'Invalid token'}, 401

        jobs = Job.query.all()
        jobs_list = [{'id': job.id, 'start_time': job.start_time, 'end_time': job.end_time,
                      'state': job.state, 'details': job.details, 'job_id': job.job_id,
                      'job_name': job.job_name, 'processed': job.processed, 'read': job.read,
                      'transferred': job.transferred, 'speed': job.speed, 'source_load': job.source_load,
                      'source_processing_load': job.source_processing_load, 'network_load': job.network_load,
                      'target_load': job.target_load, 'bottleneck': job.bottleneck, 'duration': job.duration,
                      'created_at': job.created_at} for job in jobs]
        return jsonify(jobs_list)

auth_model = api.model('Auth', {
    'username': fields.String(required=True, description='Nome utente'),
    'password': fields.String(required=True, description='Password')
})

@auth_ns.route('/login')
class UserLogin(Resource):
    @auth_ns.expect(auth_model)
    def post(self):
        """Effettua il login e restituisce un token"""
        auth_data = request.get_json()
        username = auth_data.get('username')
        password = auth_data.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            token = jwt.encode({'username': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                               app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({'token': token})
        return {'error': 'Invalid credentials'}, 401

@auth_ns.route('/register')
class UserRegister(Resource):
    @auth_ns.expect(auth_model)
    def post(self):
        """Registra un nuovo utente"""
        auth_data = request.get_json()
        username = auth_data.get('username')
        password = auth_data.get('password')

        if User.query.filter_by(username=username).first():
            return {'error': 'User already exists'}, 400

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return {'message': 'User registered successfully'}, 201

@auth_ns.route('/logout')
class UserLogout(Resource):
    @auth_ns.doc(security='Bearer Auth')
    @auth_ns.response(200, 'Logged out successfully')
    @auth_ns.response(401, 'Non autorizzato')
    def post(self):
        """Effettua il logout e revoca il token"""
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return {'error': 'Unauthorized'}, 401
        
        token = auth_header.split(" ")[1]
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return {'error': 'Token expired'}, 401
        except jwt.InvalidTokenError:
            return {'error': 'Invalid token'}, 401

        revoked_token = RevokedToken(token=token)
        db.session.add(revoked_token)
        db.session.commit()
        return {'message': 'Logged out successfully'}, 200

client_model = api.model('Client', {
    'client_name': fields.String(required=True, description='Nome dell\'applicazione')
})

@auth_ns.route('/create_client')
class CreateClient(Resource):
    @auth_ns.doc(security='Bearer Auth')
    @auth_ns.expect(client_model)
    @auth_ns.response(201, 'Client created successfully')
    @auth_ns.response(401, 'Non autorizzato')
    def post(self):
        """Crea una nuova applicazione OAuth2"""
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return {'error': 'Unauthorized'}, 401
        
        token = auth_header.split(" ")[1]
        if is_token_revoked(token):
            return {'error': 'Unauthorized'}, 401

        try:
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return {'error': 'Token expired'}, 401
        except jwt.InvalidTokenError:
            return {'error': 'Invalid token'}, 401

        user = User.query.filter_by(username=decoded_token['username']).first()
        if not user:
            return {'error': 'User not found'}, 401

        client_data = request.get_json()
        client_id = f"{user.id}-{int(datetime.datetime.utcnow().timestamp())}"
        client_secret = generate_password_hash(client_id + app.config['SECRET_KEY'], method='sha256')

        new_client = OAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            client_name=client_data['client_name'],
            user_id=user.id
        )
        db.session.add(new_client)
        db.session.commit()

        return {
            'client_id': client_id,
            'client_secret': client_secret,
            'client_name': client_data['client_name']
        }, 201

api.add_namespace(auth_ns, path='/api/auth')
api.add_namespace(jobs_ns, path='/api/jobs')

if __name__ == '__main__':
    app.run(debug=True, port=5000)

