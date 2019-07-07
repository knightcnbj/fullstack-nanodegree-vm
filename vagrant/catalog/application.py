#!/usr/bin/env python3
from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   jsonify,
                   url_for,
                   flash,
                   make_response,
                   session as login_session)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Item, Base

import random
import string
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import httplib2
import json
import requests
from functools import wraps


app = Flask(__name__)
app.secret_key = 'secret_key'

CLIENT_ID = json.loads(open('/var/www/fullstack-nanodegree-vm/vagrant/catalog/client_secrets.json', 'r')
                       .read())['web']['client_id']
APPLICATION_NAME = "Catalog App"

engine = create_engine('postgresql://catalog:catalog_ps@localhost/catalog_db')
#engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)


def login_required(f):
    """ redirect to login page if user is not logged in
    Returns:
        login page
    """
    @wraps(f)
    def decorated_function():
        if 'username' not in login_session:
            return redirect('/login')
    return decorated_function


@app.route('/login')
def show_login():
    """ login page
    Returns:
        page with link to google sign in.
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# login logic
@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ user login to their google account
    Returns:
        user info and profile picture
    """
    # check request's state is same as current session's state
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # validate client secrets
    code = request.data
    try:
        oauth_flow = flow_from_clientsecrets('/var/www/fullstack-nanodegree-vm/vagrant/catalog/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # get access token from client secret
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'
           .format(access_token))
    http = httplib2.Http()
    result = json.loads(http.request(url, 'GET')[1])

    # check access token has error
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # validate user id with token's id
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # make sure token is issued to client
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # check if same user tries to login again
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    user_info = requests.get(user_info_url, params=params)

    user_info_data = user_info.json()

    # store user info in login session
    login_session['username'] = user_info_data['name']
    login_session['picture'] = user_info_data['picture']
    login_session['email'] = user_info_data['email']

    # display user info
    output = '<h1>user name: {}</h1>'.format(login_session['username'])
    output += '<img src="'
    output += login_session['picture']
    output += ' "style="width:100px; height:100px; border-radius:100px;' \
              '-webkit-border-radius:100px; -moz-border-radius:100px;">'

    flash("you are now logged in as {}s".format(login_session['username']))
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """ user disconnect from their google account
    Returns:
        home page
    """
    # check if current session has access token
    access_token = login_session.get('access_token')
    if access_token is None:
        flash('Access Token is None')
        return redirect(url_for('show_catalog'))

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


# home page, display categories and latest items
@app.route('/')
@app.route('/catalog/')
def show_catalog():
    """ display all categories and latest items
    Returns:
        home page
    """
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


@login_required
@app.route('/catalog/new/', methods=['GET', 'POST'])
def new_category():
    """ create a new category
    Returns:
        on POST: redirect to home page after category is created
        on GET: page with a form to create new category
        login page if user is not logged in
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        session = DBSession()
        new_cate = Category(name=request.form['name'],
                            user_email=login_session['email'])
        session.add(new_cate)
        session.commit()
        flash('New Category {} Created'.format(new_cate.name))
        session.close()
        return redirect(url_for('show_catalog'))
    else:
        return render_template('new_category.html')


@login_required
@app.route('/catalog/<int:category_id>/edit/', methods=['GET', 'POST'])
def edit_category(category_id):
    """ edit an exiting category
    Args:
        category_id: id of current category
    Returns:
        on POST: redirect to home page after category is edited
        on GET: page to edit the category
        login page if user is not logged in
        unauthorized page if user is not owner of current category
    """
    if 'username' not in login_session:
        return redirect('/login')
    session = DBSession()
    edited_category = session.query(Category).filter_by(id=category_id).one()
    if edited_category.user_email != login_session['email']:
        return render_template('unauthorized.html')
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


@login_required
@app.route('/catalog/<int:category_id>/delete/', methods=['GET', 'POST'])
def delete_category(category_id):
    """ delete an existing category
    Args:
        category_id: id of current category
    Returns:
        on POST: redirect to home page after category is deleted
        on GET: page to delete the category
        login page if user is not logged in
        unauthorized page if user is not owner of current category
    """
    if 'username' not in login_session:
        return redirect('/login')
    session = DBSession()
    deleted_category = \
        session.query(Category).filter_by(id=category_id).one()
    if deleted_category.user_email != login_session['email']:
        return render_template('unauthorized.html')
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
    """ show all items in a category
    Args:
        category_id: id of current category
    Returns:
        page showing items under a category
    """
    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    session.close()
    return render_template('items.html', category=category, items=items)


@app.route('/catalog/<int:category_id>/items/<int:item_id>/')
def show_item_detail(category_id, item_id):
    """ show item's name and description
    Args:
        category_id: id of current category
        item_id: id of current item
    Returns:
        page with item name and description
    """
    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    session.close()
    return render_template('item_detail.html', category=category, item=item)


@login_required
@app.route('/catalog/<int:category_id>/items/new/', methods=['GET', 'POST'])
def new_item(category_id):
    """ create a new item by the logged in user
    Args:
        category_id: id of current item's category
    Return:
        on POST: redirect to category page after item is created
        on GET: page to create the item
        login page if user is not logged in
        unauthorized page if user is not owner of current user
    """
    if 'username' not in login_session:
        return redirect('/login')
    session = DBSession()
    category = session.query(Category).filter_by(id=category_id).one()
    if category.user_email != login_session['email']:
        return render_template('unauthorized.html')
    if request.method == 'POST':
        item = Item(
            name=request.form['name'],
            description=request.form['description'],
            category_id=category_id,
            user_email=login_session['email'],
        )
        session.add(item)
        session.commit()
        flash('New Item {} Created'.format(item.name))
        session.close()
        return redirect(url_for('show_items', category_id=category_id))
    else:
        return render_template('new_item.html', category=category)


@login_required
@app.route('/catalog/<int:category_id>/items/<int:item_id>/edit/',
           methods=['GET', 'POST'])
def edit_item(category_id, item_id):
    """ edit an item if logged in user is owner
    Args:
        category_id: id of current item's category
        item_id: id of current item
    Return:
        on POST: redirect to category page after item is edited
        on GET: page to edit the item
        login page if user is not logged in
        unauthorized page if user is not owner of current user
    """
    if 'username' not in login_session:
        return redirect('/login')
    session = DBSession()
    edited_item = session.query(Item).filter_by(id=item_id).one()
    if edited_item.user_email != login_session['email']:
        return render_template('unauthorized.html')
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


@login_required
@app.route('/catalog/<int:category_id>/items/<int:item_id>/delete/',
           methods=['GET', 'POST'])
def delete_item(category_id, item_id):
    """ delete an item if logged in user is owner
    Args:
        category_id: id of current item's category
        item_id: id of current item
    Return:
        on POST: redirect to category page after item is deleted
        on GET: page to delete the item
        login page if user is not logged in
        unauthorized page if user is not owner of current user
    """
    if 'username' not in login_session:
        return redirect('/login')
    session = DBSession()
    deleted_item = session.query(Item).filter_by(id=item_id).one()
    if deleted_item.user_email != login_session['email']:
        return render_template('unauthorized.html')
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
    """ json endpoint for catalog
    Returns:
        json object of catalog
    """
    session = DBSession()
    categories = session.query(Category).all()
    session.close()
    return jsonify(categories=[category.serialize for category in categories])


@app.route('/catalog/<int:category_id>/items.json')
def items_json(category_id):
    """ json endpoint for items in a category
    Args:
        category_id: id of current category
    Returns:
        json object of a category
    """
    session = DBSession()
    items = session.query(Item).filter_by(category_id=category_id).all()
    session.close()
    return jsonify(items=[item.serialize for item in items])


@app.route('/catalog/<int:category_id>/items/<int:item_id>.json')
def item_json(category_id, item_id):
    """ json endpoint for one item
    Args:
        category_id: id of item's category
        item_id: id of item
    Returns:
        json object of an item
    """
    session = DBSession()
    item = session.query(Item).filter_by(id=item_id).one()
    session.close()
    return jsonify(item=item.serialize)


if __name__ == '__main__':
    host = '0.0.0.0'
    port = 8000
    #app.secret_key = 'secret_key'
    app.debug = True
    app.run(host=host, port=port)