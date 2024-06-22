from flask import Blueprint, request, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        email = data.get('email')
        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash('Utilisateur déjà existant', 'danger')
            return redirect(url_for('main.register'))

        # Définition du rôle par défaut comme 'patient' si aucun n'est spécifié dans le formulaire
        role = data.get('role', 'patient')

        new_user = User(
            username=data.get('username'),
            email=email,
            password=generate_password_hash(data.get('password')),
            role=role
        )
        db.session.add(new_user)
        db.session.commit()

        # Connexion automatique de l'utilisateur après l'inscription réussie
        login_user(new_user)

        flash('Inscription réussie', 'success')

        if new_user.role == 'doctor':
            return redirect(url_for('main.doctor_dashboard'))
        elif new_user.role == 'patient':
            return redirect(url_for('main.patient_dashboard'))
        else:
            return redirect(url_for('main.index'))

    return render_template('register.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        email = data.get('email')
        password = data.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Connexion réussie', 'success')
            if user.role == 'doctor':
                return redirect(url_for('main.doctor_dashboard'))
            elif user.role == 'patient':
                return redirect(url_for('main.patient_dashboard'))
            else:
                return redirect(url_for('main.index'))
        else:
            flash('Échec de la connexion. Veuillez vérifier vos informations.', 'danger')

    return render_template('login.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@bp.route('/doctor_dashboard')
@login_required
def doctor_dashboard():
    if current_user.role != 'doctor':
        flash('Accès interdit', 'danger')
        return redirect(url_for('main.index'))
    return render_template('doctor.html')

@bp.route('/patient_dashboard')
@login_required
def patient_dashboard():
    if current_user.role != 'patient':
        flash('Accès interdit', 'danger')
        return redirect(url_for('main.index'))
    return render_template('patient.html')
