# -*- coding: utf-8 -*-
"""
    Buzzingbird
    ~~~~~~~~

    A microblogging application written with Flask and sqlite3, with
    support for encryption and private communication.

    Based off of the ideas of Hummingbird, with the code base modified
    from the minitwit Flask example project.

    :copyright: (c) 2013 by Austin Dworaczyk Wiltshire.
    :license: BSD, see LICENSE for more details.
"""
from __future__ import with_statement
import time
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash, _app_ctx_stack, jsonify
from werkzeug import check_password_hash, generate_password_hash


# configuration
DATABASE = '/tmp/buzzingbird.db'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = 'development key'

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('BUZZINGBIRD_SETTINGS', silent=True)


class TokenStatus:
    ACCEPTED, REQUESTED, APPROVED = range(3)


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db


@app.teardown_appcontext
def close_database(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()


def init_db():
    """Creates the database tables."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.commit()


def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = query_db('select user_id from user where username = ?',
                  [username], one=True)
    return rv[0] if rv else None


def get_username_from_user_id(user_id):
    '''Retrieves a username for a given user_id.'''
    rv = query_db('''select username from user where user_id = ?''',
            [user_id], one=True)
    return rv[0] if rv else None


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?',
                          [session['user_id']], one=True)


@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    if not g.user:
        return redirect(url_for('public_timeline'))

    followQuery = '''select username, token from follower, user
            where follower.whom_id = ? and follower.token_status = ?
            and follower.who_id = user.user_id'''

    approvedQuery = '''select username, token from follower, user
            where follower.who_id = ? and follower.token_status = ?
            and follower.whom_id = user.user_id'''

    followRequests = query_db(followQuery, [session['user_id'], TokenStatus.REQUESTED])
    approvedRequests = query_db(approvedQuery, [session['user_id'], TokenStatus.APPROVED])

    return render_template('timeline.html', messages=query_db('''
        select message.*, user.* from message, user
        where message.author_id = user.user_id and (
            user.user_id = ? or
            user.user_id in (select whom_id from follower
                                    where message.token = follower.token
                                    and who_id = ?))
        order by message.pub_date desc limit ?''',
        [session['user_id'], session['user_id'], PER_PAGE]),
        follow_requests=followRequests, approved_requests=approvedRequests)


@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    return render_template('timeline.html', messages=query_db('''
        select message.*, user.* from message, user
        where message.author_id = user.user_id
        order by message.pub_date desc limit ?''', [PER_PAGE]))


@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""
    profile_user = query_db('select * from user where username = ?',
                            [username], one=True)
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = query_db('''select 1 from follower where
            follower.who_id = ? and follower.whom_id = ?''',
            [session['user_id'], profile_user['user_id']],
            one=True) is not None
    return render_template('timeline.html', messages=query_db('''
            select message.*, user.* from message, user where
            user.user_id = message.author_id and user.user_id = ?
            order by message.pub_date desc limit ?''',
            [profile_user['user_id'], PER_PAGE]), followed=followed,
            profile_user=profile_user)


@app.route('/_get_public_key', methods=['GET'])
def get_public_key():
    '''AJAX request for a particular user's public key.'''

    if not g.user:
        abort(401)

    following_username = request.args.get('username', type=str)

    if not following_username:
        abort(400)

    publicKey = query_db('''select user.pub_key from user
            where username = ?''', [following_username], one=True)
    return jsonify(pub_key=publicKey[0])


@app.route('/_approve_token', methods=['GET'])
def approve_token():
    '''AJAX request to approve a particular follow request.'''

    if not g.user:
        abort(401)

    approved_username = request.args.get('approved_username', type=str)
    approved_token = request.args.get('approved_token', type=str)

    if not approved_username or not approved_token:
        abort(400)

    db = get_db()
    db.execute('''update follower set token_status = ?, token = ?
            where who_id = ? and whom_id = ?''',
            [TokenStatus.APPROVED, approved_token, get_user_id(approved_username), session['user_id']])
    db.commit()

    return jsonify(result="success")


@app.route('/_accept_token', methods=['GET'])
def accept_token():
    '''AJAX request which accepts the final form of the follow token
    and stores it in the DB as a form of follow registration.'''

    if not g.user:
        abort(401)

    following_username = request.args.get('username', type=str)
    following_token = request.args.get('token', type=str)

    if not following_username or not following_token:
        abort(400)

    db = get_db()
    db.execute('''update follower set token_status = ?, token = ?
            where who_id = ? and whom_id = ?''',
            [TokenStatus.ACCEPTED, following_token, session['user_id'], get_user_id(following_username)])
    db.commit()

    return jsonify(result="success")


@app.route('/<username>/follow', methods=['GET', 'POST'])
def follow_user(username):
    """Submits a follow request for the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)

    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = "You must enter a user to follow."
        elif not request.form['hashtag']:
            error = "You must enter a valid hashtag."
        elif not request.form['token']:
            error = "You must generate a valid token from your hashtag."
        else:
            db = get_db()
            db.execute('''insert into follower (who_id, whom_id, token_status, token) values (?, ?, ?, ?)''',
                [session['user_id'], whom_id, TokenStatus.REQUESTED, request.form['token']])
            db.commit()
            flash('You successfully submitted a follow request to %s.' % request.form['username'])
            return redirect(url_for('timeline'))
    return render_template('request_follow.html', followuser=username, error=error)


@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    db = get_db()
    db.execute('delete from follower where who_id=? and whom_id=?',
              [session['user_id'], whom_id])
    db.commit()
    flash('You are no longer following "%s"' % username)
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        db = get_db()
        db.execute('''insert into message (author_id, text, pub_date, token)
          values (?, ?, ?, ?)''', (session['user_id'], request.form['text'],
                                int(time.time()), request.form['token']))
        db.commit()
        flash('Your message was recorded')
    return redirect(url_for('timeline'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from user where
            username = ?''', [request.form['username']], one=True)
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user['user_id']
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                 '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        elif not request.form['pubkey']:
            error = 'The public key is not filled in.'
        else:
            db = get_db()
            db.execute('''insert into user (
              username, email, pw_hash, pub_key) values (?, ?, ?, ?)''',
              [request.form['username'], request.form['email'],
               generate_password_hash(request.form['password']),
               request.form['pubkey']])
            db.commit()
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))


# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url


if __name__ == '__main__':
    #init_db()
    app.debug = DEBUG
    app.run()
