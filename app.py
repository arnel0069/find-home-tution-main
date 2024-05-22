from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.utils import secure_filename
import os
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
import logging
from flask_wtf.csrf import generate_csrf
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

# Configurations
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///coaching.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['SECRET_KEY'] = 'your_secret_key'

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

logging.basicConfig(level=logging.DEBUG)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Tutor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(150), db.ForeignKey('user.email'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    father_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    aadhaar = db.Column(db.String(12), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    qualification = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    working_time = db.Column(db.Time, nullable=False)
    address = db.Column(db.String(100), nullable=False)
    cv = db.Column(db.String(255))
    profile_picture = db.Column(db.String(255))

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    father_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    class_name = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(50), nullable=False)
    tuition_fees = db.Column(db.String(50), nullable=False)
    timing = db.Column(db.Time, nullable=False)
    address = db.Column(db.String(20), nullable=False)

class AppliedStudent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    user_email = db.Column(db.String(150), db.ForeignKey('user.email'), nullable=False)
    student = db.relationship('Student', backref=db.backref('applied_students', lazy=True))
    user = db.relationship('User', backref=db.backref('applied_students', lazy=True))
    name = db.Column(db.String(100), nullable=False)
    father_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15), nullable=False)

# Forms
class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Pagination Function
def paginate(records, page, per_page=8):
    start_index = (page - 1) * per_page
    end_index = start_index + per_page
    return records[start_index:end_index]

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email address already exists. Please use a different email.', 'danger')
            return redirect(url_for('signup'))  # Redirect back to the signup page
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred while creating your account. Please try again.', 'danger')
            return redirect(url_for('signup'))  # Redirect back to the signup page
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/')
def home():
    response = make_response(render_template('home.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

@app.route('/student', methods=['GET', 'POST'])
def student():
    if request.method == 'POST':
        name = request.form['name']
        father_name = request.form['fatherName']
        phone = request.form['phone']
        class_name = request.form['class']
        subject = request.form['subject']
        tuition_fees = request.form['fees']
        timing = datetime.strptime(request.form['timing'], '%H:%M').time()
        address = request.form['houseNo']

        new_student = Student(
            name=name,
            father_name=father_name,
            phone=phone,
            class_name=class_name,
            subject=subject,
            tuition_fees=tuition_fees,
            timing=timing,
            address=address,
        )
        db.session.add(new_student)
        db.session.commit()

        return redirect(url_for('thankyou'))

    return render_template('student.html')

@app.route('/tutor', methods=['GET', 'POST'])
@login_required  # Ensure the user is logged in
def tutor():
    if request.method == 'POST':
        name = request.form['name']
        father_name = request.form['fatherName']
        phone = request.form['phone']
        aadhaar = request.form['aadhaar']
        email = request.form['email']
        qualification = request.form['qualification']
        experience = request.form['experience']
        dob = datetime.strptime(request.form['dob'], '%Y-%m-%d').date()
        working_time = datetime.strptime(request.form['workingTime'], '%H:%M').time()
        address = request.form['Address']

        cv_path = None
        if 'cv' in request.files:
            cv_file = request.files['cv']
            if cv_file.filename != '':
                filename = secure_filename(cv_file.filename)
                cv_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                cv_path = filename

        profile_picture_path = None
        if 'profile-picture' in request.files:
            profile_picture_file = request.files['profile-picture']
            if profile_picture_file.filename != '':
                profile_picture_filename = secure_filename(profile_picture_file.filename)
                profile_picture_file.save(os.path.join(app.config['UPLOAD_FOLDER'], profile_picture_filename))
                profile_picture_path = profile_picture_filename

        # Ensure user_email is set to the current user's email
        new_tutor = Tutor(
            user_email=current_user.email,  # Set user_email to the logged-in user's email
            name=name,
            father_name=father_name,
            phone=phone,
            aadhaar=aadhaar,
            email=email,
            qualification=qualification,
            experience=experience,
            dob=dob,
            working_time=working_time,
            address=address,
            cv=cv_path,
            profile_picture=profile_picture_path
        )
        db.session.add(new_tutor)
        db.session.commit()

        return redirect(url_for('thankyou'))

    return render_template('tutor.html')

@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')

@app.route('/feeds')
@login_required  # Ensure the user is logged in
def feeds():
    page = request.args.get('page', 1, type=int)
    students = Student.query.paginate(page=page, per_page=10)
    
    applied_student_ids = []
    if current_user.is_authenticated:
        applied_students = AppliedStudent.query.filter_by(user_email=current_user.email).all()
        applied_student_ids = [applied.student_id for applied in applied_students]
        logging.debug(f'Applied Student IDs: {applied_student_ids}')
    
    csrf_token = generate_csrf()
    return render_template('feeds.html', students=students, applied_student_ids=applied_student_ids, csrf_token=csrf_token)

@app.route('/apply_now', methods=['POST'])
@login_required
def apply_now():
    if request.method == 'POST':
        student_id = request.form['student_id']
        student = Student.query.get(student_id)
        if student:
            applied_student = AppliedStudent(
                student_id=student_id,
                user_email=current_user.email,
                name=student.name,
                father_name=student.father_name,
                phone=student.phone
            )
            db.session.add(applied_student)
            db.session.commit()
            flash('You have successfully applied!', 'success')
        else:
            flash('Error: Student not found.', 'danger')
        return redirect(url_for('feeds'))

@app.route('/search_tutors', methods=['GET'])
def search_tutors():
    page = request.args.get('page', 1, type=int)
    tutors = Tutor.query.paginate(page=page, per_page=9)
    return render_template('search_tutors.html', tutors=tutors)

@app.route('/contactus')
def contactus():
    return render_template('contactus.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)
