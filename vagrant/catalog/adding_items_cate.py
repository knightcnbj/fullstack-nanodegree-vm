#!/usr/bin/env python3
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Item, Base

# engine = create_engine('sqlite:///catalog.db')
engine = create_engine('postgresql://catalog:catalog@localhost/catalog')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

print('start adding category and item into db')
session = DBSession()

cate1 = Category(name="Soccer", user_email="system")
session.add(cate1)
session.commit()

item1 = Item(name="Shoes", description="i love soccer", category=cate1, user_email='system')
session.add(item1)
session.commit()

cate2 = Category(name="BasketBall", user_email="system")
session.add(cate2)
session.commit()

item2 = Item(name="Board", description="i wanna go NBA!", category=cate2, user_email='system')
session.add(item2)
session.commit()

session.close()
print('done adding category and item')
