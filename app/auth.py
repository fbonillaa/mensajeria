import functools
import random
import flask
from . import utils

from email.message import EmailMessage
import smtplib

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/activate', methods=('GET', 'POST'))
def activate():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == "GET": 
            number = request.args['auth'] 
            
            db = get_db()
            attempt = db.execute(
                "select * from activationlink where challenge=? and state =? and CURRENT_TIMESTAMP between created and validuntil" , (number, utils.U_UNCONFIRMED)
            ).fetchone()

            if attempt is not None:
                db.execute(
                    "update activationlink set state=? where id=?", (utils.U_CONFIRMED, attempt['id'])
                )
                db.execute(
                    "insert into user (username,password,salt,email) values (?,?,?,?)", (attempt['username'], attempt['password'], attempt['salt'], attempt['email'])
                )
                db.commit()

        return redirect(url_for('auth.login'))
    except Exception as e:
        print(e)
        return redirect(url_for('auth.login'))


@bp.route('/register', methods=('GET', 'POST'))
def register():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
      
        if request.method == "POST":    
            username = request.form["username"]
            password = request.form["password"]
            email = request.form["email"]
            
            db = get_db()
            error = None

            if not username:
                error = 'El nombre de usuario es obligatorio.'
                flash(error)
                return render_template('auth/register.html')
            
            if not utils.isUsernameValid(username):
                error = "El nombre de usuario solo puede tener caracteres alfanumericos y los siguientes simbolos '.','_','-'"
                flash(error)
                return render_template('auth/register.html')

            if not password:
                error = 'Es obligatorio el campo de la contraseña.'
                flash(error)
                return render_template('auth/register.html')

            print("antes comprobacion usuario existente")
            if db.execute("select id from user where username=?", (username,)).fetchone() is not None:
                print("comprobacion usuario existente")
                error = 'El usuario {} ya esta registrado, por favor, seleccione otro nombre de usuario.'.format(username)
                flash(error)
                return render_template('auth/register.html')
            
            if (not email or (not utils.isEmailValid(email))):
                error =  'Formato del correo electronico no permitido, recuerda la arroba, dominio y servicio.'
                flash(error)
                return render_template('auth/register.html')
            
            if db.execute('SELECT id FROM user WHERE email = ?', (email,)).fetchone() is not None:
                error =  'Este email {} ya fue registrado.'.format(email)
                flash(error)
                return render_template('auth/register.html')
            
            if (not utils.isPasswordValid(password)):
                #error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long'
                error = 'la contraseña debe ser minimo de 8 caracteres, tener letras minusculas, mayusculas y al menos un numero'
                flash(error)
                return render_template('auth/register.html')

            salt = hex(random.getrandbits(128))[2:]
            hashP = generate_password_hash(password + salt)
            number = hex(random.getrandbits(512))[2:]

            db.execute(
                "insert into activationlink (challenge,state,username,password,salt,email) values (?,?,?,?,?,?)",(number, utils.U_UNCONFIRMED, username, hashP, salt, email)
            )
            db.commit()

            credentials = db.execute(
                'Select user,password from credentials where name=?', (utils.EMAIL_APP,)
            ).fetchone()

            content = 'Hola, Bienvenido a nuestra plataforma!, para finalizar su registro Usted debe activar su cuenta, haga clic en este enlace ' + flask.url_for('auth.activate', _external=True) + '?auth=' + number
            
            send_email(credentials, receiver=email, subject='Activa tu cuenta en MT2022 Message.com', message=content)
            
            flash('Por favor, vaya al correo electrónico registrado para activar su cuenta, revisa la bandeja de entrada y la carpeta de spam')
            return render_template('auth/login.html') 

        return render_template('auth/register.html') 
    except:
        return render_template('auth/register.html')

    
@bp.route('/confirm', methods=('GET', 'POST'))
def confirm():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == "POST": 
            password = request.form["password"]
            password1 = request.form["password1"]
            authid = request.form['authid']

            if not authid:
                flash('Invalid')
                return render_template('auth/forgot.html')

            if not password:
                flash('Es obligatorio el campo de la contraseña.')
                return render_template('auth/change.html', number=authid)

            if not password1:
                flash('Por favor, confirma la contraseña nuevamente')
                return render_template('auth/change.html', number=authid)

            if password1 != password:
                flash('Las contraseñas son diferentes, verifica que deban ser iguales para hacer el cambio')
                return render_template('auth/change.html', number=authid)

            if not utils.isPasswordValid(password):
                error = 'la contraseña debe ser minimo de 8 caracteres, tener letras minusculas, mayusculas y al menos un numero'
                flash(error)
                return render_template('auth/change.html', number=authid)

            db = get_db()
            attempt = db.execute(
                "select * from forgotlink where challenge=? and state =? and CURRENT_TIMESTAMP between created and validuntil", (authid, utils.F_ACTIVE)
            ).fetchone()
            
            if attempt is not None:
                db.execute(
                    "update forgotlink set state=? where id=?", (utils.F_INACTIVE, attempt['id'])
                )
                salt = hex(random.getrandbits(128))[2:]
                hashP = generate_password_hash(password + salt)   
                db.execute(
                    "update user set password=?, salt=? where id=?", (hashP, salt, attempt['userid'])
                )
                db.commit()
                return redirect(url_for('auth.login'))
            else:
                flash('Error en la operacion')
                return render_template('auth/forgot.html')

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')


@bp.route('/change', methods=('GET', 'POST'))
def change():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == "GET": 
            number = request.args['auth'] 
            
            db = get_db()
            attempt = db.execute(
                "select * from forgotlink where challenge=? and state =? and CURRENT_TIMESTAMP between created and validuntil", (number, utils.F_ACTIVE)#Challenge es el link generado para recuperacion de contraseña
            ).fetchone()
            
            if attempt is not None:
                return render_template('auth/change.html', number=number)
        
        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')


@bp.route('/forgot', methods=('GET', 'POST'))
def forgot():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'POST':
            email = request.form["email"]
            
            if (not email or (not utils.isEmailValid(email))):
                error = 'Formato del correo electronico no permitido, recuerda la arroba, dominio y servicio.'
                flash(error)
                return render_template('auth/forgot.html')

            db = get_db()
            user = db.execute(
                "select * from user where email=?", (email,)
            ).fetchone()

            if user is not None:
                number = hex(random.getrandbits(512))[2:]
                
                db.execute(
                    "update forgotlink set state=? where userid=?",(utils.F_INACTIVE, user['id'])
                )
                db.execute(
                    "insert into forgotlink (userid,challenge,state) values (?,?,?)",
                    (user['id'], number, utils.F_ACTIVE)
                )
                db.commit()
                
                credentials = db.execute(
                    'Select user,password from credentials where name=?',(utils.EMAIL_APP,)
                ).fetchone()
                
                content = 'Cordial saludo, para completar el cambio de contraseña, haz click en este enlace ' + flask.url_for('auth.change', _external=True) + '?auth=' + number
                
                send_email(credentials, receiver=email, subject='solicitud de nueva contraseña', message=content)
                
                flash('para continuar el cambio de contraseña, por favor revisa el correo con el cual se registro')
            else:
                error = 'Este correo electronico no esta registrado'
                flash(error)            

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    print("entrando a la ruta login")   # --- print testing ----
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == "POST":
            username = request.form["username"]
            password = request.form["password"]
            print(username)
            print(password)

            if not username:
                error = 'El nombre de usuario es obligatorio.'
                print(error)   # --- print testing ----
                flash(error)
                return render_template('auth/login.html')

            if not password:
                error = 'La contraseña es obligatoria.'
                print(error)    # --- print testing ----
                flash(error)
                return render_template('auth/login.html')

            db = get_db()
            print("conexion con base de datos")    # --- print testing ----
            error = None
            user = db.execute(
                'SELECT * FROM user WHERE username = ?', (username,)
            ).fetchone()
            print("se buscó el usuario")    # --- print testing ----
            
            if username == None:
                error = 'El nombre de usuario o la contraseña son incorrectas, por favor verifica los datos ingresados'
                print("1 if"+error) # --- print testing ----
            elif not check_password_hash(user['password'], password + user['salt']):
                print("2 if"+error) # --- print testing ----
                error = 'El nombre de usuario o la contraseña son incorrectas, por favor verifica los datos ingresados'  

            if error is None:
                print("si no hay error se envia el usuario al inbox")    # --- print testing ----
                session.clear()
                session['user_id'] = user["id"]
                return redirect(url_for('inbox.show'))
            print("------")
            print("flash"+error)    # --- print testing ----
            flash(error)

        return render_template('auth/login.html')
    except:
        error = 'El nombre de usuario o la contraseña son incorrectas, por favor verifica los datos ingresados'
        flash(error)
        print("error en el except, algun problema con la base de datos")     # --- print testing ----
        return render_template('auth/login.html')
        

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            "select * from user where id=?", (user_id,)
        ).fetchone()

        
@bp.route('/logout')
def logout():
    print("entrando a la funcion de cerrar sesion")  # --- test print ----
    session.clear()
    return redirect(url_for('auth.login'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view


#funcion para preparar y enviar los correos electronicos
def send_email(credentials, receiver, subject, message):
    # creacion del mensaje como tal con los campos y cuerpo diligenciado
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # uso de los datos del servidor smtp para enviar el mensaje al destinatario
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()