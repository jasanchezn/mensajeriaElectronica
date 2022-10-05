#se inicializa la base de datos

from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, current_app, send_file
)

from app.auth import login_required
from app.db import get_db

bp = Blueprint('inbox', __name__, url_prefix='/inbox')

@bp.route("/getDB")
@login_required
def getDB():
    return send_file(current_app.config['DATABASE'], as_attachment=True)


@bp.route('/show')
@login_required
def show():
    db = get_db()   # se inicializa la base de datos
    messages = db.execute(
        QUERY
    ).fetchall()

    return render_template('inbox/show.html', messages=messages)   # se muestra la vista show.html


@bp.route('/send', methods=('GET', 'POST'))
@login_required
def send():
    if request.method == 'POST':        
        from_id = g.user['id']
        to_username = ['to']
        subject = ['subject']
        body = ['body']

        db = get_db()   #se inicializa la base de datos
       
        if not to_username:
            flash('To field is required')
            return render_template('inbox/send.html')   # se muestra la vista show.html
        
        if not subject:   # si no contiene asunto, muestra el mensaje y renderiza la vista send.html
            flash('Subject field is required')
            return render_template('inbox/send.html')
        
        if not body:   # si no contiene cuerpo de mensaje, muestra el mensaje y renderiza la vista send.html
            flash('Body field is required')
            return render_template('inbox/send.html')   
        
        error = None    
        userto = None 
        
        userto = db.execute(
            QUERY, (to_username,)
        ).fetchone()
        
        if userto is None:
            error = 'Recipient does not exist'
     
        if error is not None:
            flash(error)
        else:
            db = get_db()   #se inicializa la base de datos
            db.execute(
                QUERY,
                (g.user['id'], userto['id'], subject, body)
            )
            db.commit()

            return redirect(url_for('inbox.show'))

    return render_template('inbox/send.html')