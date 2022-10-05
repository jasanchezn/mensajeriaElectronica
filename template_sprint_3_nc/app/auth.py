# Archivo que contiene la conexión a la base de datos

import functools

# msilib soporta la creación de archivos Microsoft Installer (.msi). 
# msilib.init_database(name, schema, ProductName, ProductCode, ProductVersion, Manufacturer)
# Crea y retorna una nueva base de datos name, la inicializa con schema, y establece las propiedades ProductName, ProductCode, ProductVersion y Manufacturer.
# schema debe ser un objeto módulo que contenga los atributos tables y _Validation_records; normalmente se debería usar msilib.schema.
# La base de datos contendrá únicamente el esquema y los registros de validación cuando esta función retorne.

from msilib import init_database  
import random
import flask
from . import utils

from email.message import EmailMessage
import smtplib

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db, init_db

bp = Blueprint('auth', __name__, url_prefix='/auth')



@bp.route('/activate', methods=('GET', 'POST'))
def activate():                 # activate: Controlador para confirmar el registro de un usuario en la plataforma
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'POST':  #Su utiliza método POST para enviar la información al servidor
            number = request.args['auth'] 
            
            db = get_db   #se inicializa la base de datos
            attempt = db.execute(
                QUERY, (number, utils.U_UNCONFIRMED)
            ).fetchone()

            if attempt is not None:
                db.execute(
                    QUERY, (utils.U_CONFIRMED, attempt['id'])
                )
                db.execute(
                    QUERY, (attempt['username'], attempt['password'], attempt['salt'], attempt['email'])
                )
                db.commit()

        return redirect(url_for('auth.login'))
    except Exception as e:
        print(e)
        return redirect(url_for('auth.login'))


 
@bp.route('/register', methods=('GET','POST'))  #se utiliza el método POST para enviar la información del registro
def register():                  # Controlador para el registro de usuarios en la plataforma, envía el email con el link para activar
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
      
        if request.method == 'POST':     #se utiliza el método POST para enviar la información del registro
            username = ['username']     #campo username del formulario register.html
            password = ['password']     #campo password del formulario register.html
            email = ['email']           #campo email del formulario register.html
            
            db = get_db   #se inicializa la base de datos
            error = None

            if username == "":      #se valida si el nombre de usuario está vacío
                error = 'Username is required.'
                flash(error)
                return render_template('auth/register.html')       # se lleva a la vista register.html
            
            if not utils.isUsernameValid(username):
                error = "Username should be alphanumeric plus '.','_','-'"
                flash(error)
                return render_template('auth/register.html')       # se lleva a la vista register.html

            if password == "":      #se valida si el password está vacío
                error = 'Password is required.'
                flash(error)
                return render_template('auth/register.html')

            if db.execute("SELECT username FROM user WHERE email = '{username}'", (username,)).fetchone() is not None:  # Consulta el username en la tabla usre, para compararlo con el usario ingresado
                error = 'User {} is already registered.'.format(username)
                flash(error)
                return render_template('auth/register.html')       # se lleva a la vista register.html
            
            if (email or (not utils.isEmailValid(email))):      #se valida si el email está vacío o es válido
                error =  'Email address invalid.'
                flash(error)
                return render_template('auth/register.html')
            
            if db.execute("SELECT id FROM user WHERE email = '{email}'", (email,)).fetchone() is not None:      # La calusula WHERE debe comparar conrta el email capturado
                error =  'Email {} is already registered.'.format(email)
                flash(error)
                return render_template('auth/register.html')       # se lleva a la vista register.html
            
            if (not utils.isPasswordValid(password)):
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long'
                flash(error)
                return render_template('auth/register.html')

            salt = hex(random.getrandbits(128))[2:]
            hashP = generate_password_hash(password + salt)
            number = hex(random.getrandbits(512))[2:]

            db.execute(
                QUERY,
                (number, utils.U_UNCONFIRMED, username, hashP, salt, email)
            )
            db.commit()

            credentials = db.execute(
                'Select user,password from credentials where name=?', (utils.EMAIL_APP,)
            ).fetchone()

            content = 'Hello there, to activate your account, please click on this link ' + flask.url_for('auth.activate', _external=True) + '?auth=' + number
            
            send_email(credentials, receiver=email, subject='Activate your account', message=content)
            
            flash('Please check in your registered email to activate your account')
            return render_template('auth/login.html') 

        return render_template('auth/login.html')   # se lleva a la vista login.html
    except:
        return render_template('auth/register.html')


@bp.route('/confirm', methods= 'POST')      #se utiliza el método POST para enviar la información de confirmación
def confirm():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST':                #se utiliza el método POST para enviar la información de confirmación
            password = request.form['password']    #campo username del formulario confirm.html   ????
            password1 = request.form['password1']   #campo username del formulario confirm.html   ????
            authid = request.form['authid']

            if not authid:
                flash('Invalid')
                return render_template('auth/forgot.html')

            if password == "":       #se valida si el password está vacío
                flash('Password required')
                return render_template('auth/change.html', number=authid)

            if not password1:
                flash('Password confirmation required')
                return render_template('auth/change.html', number=authid)   # se lleva a la vista change.html

            if password1 != password:                       # si es diferente el password del password1
                flash('Both values should be the same')
                return render_template('auth/change.html', number=authid)   # se lleva a la vista change.html

            if not utils.isPasswordValid(password):
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long.'
                flash(error)
                return render_template('auth/change.html', number=authid)

            db = get_db   #se inicializa la base de datos
            attempt = db.execute(
                QUERY, (authid, utils.F_ACTIVE)
            ).fetchone()
            
            if attempt is not None:
                db.execute(
                    QUERY, (utils.F_INACTIVE, attempt['id'])
                )
                salt = hex(random.getrandbits(128))[2:]
                hashP = generate_password_hash(password + salt)   
                db.execute(
                    QUERY, (hashP, salt, attempt['userid'])
                )
                db.commit()
                return redirect(url_for('auth.login'))
            else:
                flash('Invalid')
                return render_template('auth/forgot.html')

        return render_template('auth/login.html')     # se lleva a la vista login.html
    except:
        return render_template('auth/forgot.html')


@bp.route('/change', methods=('GET', 'POST'))
def change():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'POST':                #se utiliza el método POST para enviar la información de confirmación
            number = request.args['auth'] 
            
            db = get_db   #se inicializa la base de datos
            attempt = db.execute(
                QUERY, (number, utils.F_ACTIVE)
            ).fetchone()
            
            if attempt is not None:
                return render_template('auth/change.html', number=number)
        
        return render_template('auth/forgot.html')
    except:
        return render_template('auth/login.html')     # se lleva a la vista login.html


@bp.route('/forgot', methods=('GET', 'POST'))
def forgot():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'POST':
            email = request.form['email']       # asigna el valor del campo email en la vista forgot.html
            
            if (email or (not utils.isEmailValid(email))):      #se valida si el email está vacío o es válido
                error = 'Email Address Invalid'
                flash(error)
                return render_template('auth/forgot.html')

            db = get_db()
            user = db.execute(
                QUERY, (email,)
            ).fetchone()

            if user is not None:
                number = hex(random.getrandbits(512))[2:]
                
                db.execute(
                    QUERY,
                    (utils.F_INACTIVE, user['id'])
                )
                db.execute(
                    QUERY,
                    (user['id'], number, utils.F_ACTIVE)
                )
                db.commit()
                
                credentials = db.execute(
                    'Select user,password from credentials where name=?',(utils.EMAIL_APP,)
                ).fetchone()
                
                content = 'Hello there, to change your password, please click on this link ' + flask.url_for('auth.change', _external=True) + '?auth=' + number
                
                send_email(credentials, receiver=email, subject='New Password', message=content)
                
                flash('Please check in your registered email')
            else:
                error = 'Email is not registered'
                flash(error)            

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/login.html')     # se lleva a la vista login.html


@bp.route('/login', methods=('GET','POST'))  #se utiliza el método POST para enviar la información del registro)
def login():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST':                #se utiliza el método POST para enviar la información de confirmación
            username = request.form['username']       # asigna el valor del campo username en la vista login.html
            password = request.form['password']       # asigna el valor del campo password en la vista login.html

            if username == "":      #se valida si el nombre de usuario está vacío                    
                error = 'Username Field Required'
                flash(error)
                return render_template('auth/login.html')

            if password == "":      #se valida si el password está vacío
                error = 'Password Field Required'
                flash(error)
                render_template('auth/login.html')     # se lleva a la vista login.html

            db = get_db   #se inicializa la base de datos
            error = None
            user = db.execute(
                'SELECT * FROM user WHERE username = ?', (username,)
            ).fetchone()
            
            if user is not None:            # si el resultaod de la consulta no es nulo
                error = 'Incorrect username or password'
            elif not check_password_hash(user['password'], password + user['salt']):
                error = 'Incorrect username or password'   

            if error is None:
                session.clear()
                session['user_id'] = user[id]       # asignar el valor ID traído en la consulta
                return redirect(url_for('inbox.show'))

            flash(error)

        return render_template('auth/login.html')       # se lleva a la vista login.html
    except:
        return render_template('auth/login.html')
        

# Se asigna la variable global g, con el usuario logueado

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            QUERY, (user_id,)
        ).fetchone()

        
@bp.route('/logout')
def logout():
    session.clear()     # limpiar la sesión
    return redirect(url_for('auth.login'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view


def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()