#!/usr/bin/env python3
from flask import Flask, render_template, request, \
    redirect, jsonify, url_for, flash
from flask import session as login_session

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Item, Base

import random
import string

from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r')
                       .read())['web']['client_id']
APPLICATION_NAME = "Catalog App"

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)


# def require_login():
#     if 'username' not in login_session:
#         return redirect('/login')


@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'
           .format(access_token))
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(user_info_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;' \
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as {}s".format(login_session['username']))
    print("done!")
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')

    if access_token is None:
        flash('Access Token is None')
        return redirect(url_for('show_catalog'))

    print('In gdisconnect access token is {}'.format(access_token))
    print('User name is: {}'.format(login_session['username']))

    revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
                           params={'token': access_token},
                           headers={'content-type': 'application/json'})
    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        flash('Disconnected successfully logged out.')
    else:
        flash('User not logged in')

    return redirect(url_for('show_catalog'))


# home page, display categories and each category's latest item
@app.route('/')
@app.route('/catalog/')
def show_catalog():
    session = DBSession()
    categories = session.query(Category)
    items = session.query(Item)
    item_category_pairs = []
    for item in items:
        category = session.query(Category).filter_by(id=item.category_id).one()
        item_category_pairs.insert(0, (item, category))
    session.close()
    return render_template('catalog.html',
                           categories=categories,
                           itemCategoryPairs=item_category_pairs)


@app.route('/catalog/new/', methods=['GET', 'POST'])
def new_category():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        session = DBSession()
        new_cate = Category(name=request.form['name'])
        session.add(new_cate)
        session.commit()
        flash('New Category {} Created'.format(new_cate.name))
        session.close()
        return redirect(url_for('show_catalog'))
    else:
        return render_template('new_category.html')


@app.route('/catalog/<int:category_id>/edit/', methods=['GET', 'POST'])
def edit_category(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    session = DBSession()
    edited_category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            edited_category.name = request.form['name']
        session.add(edited_category)
        session.commit()
        flash('Category {} Edited'.format(edited_category.name))
        session.close()
        return redirect(url_for('show_catalog'))
    else:
        return render_template('edit_category.html', category=edited_category)


@app.route('/catalog/<int:category_id>/delete/', methods=['GET', 'POST'])
def delete_category(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    session = DBSession()
    deleted_category = \
        session.query(Category).filter_by(id=category_id).one()
    category_items = \
        session.query(Item).filter_by(category_id=category_id).all()
    if request.method == 'POST':
        session.delete(deleted_category)
        for item in category_items:
            session.delete(item)
        session.commit()
        flash('Category {} Deleted'.format(deleted_category.name))
        session.close()
        return redirect(url_for('show_catalog'))
    else:
        return render_template('delete_category.html',
                               category=deleted_category)


@app.route('/catalog/<int:category_id>/')
@app.route('/catalog/<int:category_id>/items/')
def show_items(category_id):
    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    session.close()
    return render_template('items.html', category=category, items=items)


@app.route('/catalog/<int:category_id>/items/<int:item_id>/')
def show_item_detail(category_id, item_id):
    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    session.close()
    return render_template('item_detail.html', category=category, item=item)


@app.route('/catalog/<int:category_id>/items/new/', methods=['GET', 'POST'])
def new_item(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        item = Item(
            name=request.form['name'],
            description=request.form['description'],
            category_id=category_id,
        )
        session.add(item)
        session.commit()
        flash('New Item {} Created'.format(item.name))
        session.close()
        return redirect(url_for('show_items', category_id=category_id))
    else:
        return render_template('new_item.html', category=category)


@app.route('/catalog/<int:category_id>/items/<int:item_id>/edit/',
           methods=['GET', 'POST'])
def edit_item(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    session = DBSession()
    edited_item = session.query(Item).filter_by(id=item_id).one()
    categories = session.query(Category)
    if request.method == 'POST':
        if request.form['name']:
            edited_item.name = request.form['name']
        if request.form['description']:
            edited_item.description = request.form['description']
        if request.form['category']:
            edited_item.category_id = request.form['category']
        session.add(edited_item)
        session.commit()
        flash('Item {} Edited'.format(edited_item.name))
        session.close()
        return redirect(url_for('show_items', category_id=category_id))
    else:
        return render_template('edit_item.html',
                               item=edited_item,
                               categories=categories)


@app.route('/catalog/<int:category_id>/items/<int:item_id>/delete/',
           methods=['GET', 'POST'])
def delete_item(category_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    session = DBSession()
    deleted_item = session.query(Item).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(deleted_item)
        session.commit()
        flash('Item {} Deleted'.format(deleted_item.name))
        session.close()
        return redirect(url_for('show_items', category_id=category_id))
    else:
        return render_template('delete_item.html', item=deleted_item)


# json api
@app.route('/catalog.json')
def catalog_json():
    session = DBSession()
    categories = session.query(Category).all()
    session.close()
    return jsonify(categories=[category.serialize for category in categories])


@app.route('/catalog/<int:category_id>/items.json')
def items_json(category_id):
    session = DBSession()
    items = session.query(Item).filter_by(category_id=category_id).all()
    session.close()
    return jsonify(items=[item.serialize for item in items])


@app.route('/catalog/<int:category_id>/items/<int:item_id>.json')
def item_json(category_id, item_id):
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    session.close()
    return jsonify(item=item.serialize)


if __name__ == '__main__':
    host = '0.0.0.0'
    port = 8000
    app.secret_key = 'secret_key'
    app.debug = True
    app.run(host=host, port=port)
