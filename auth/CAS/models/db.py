#!/usr/bin/env python

"""
Workflow:

Creating permissions

    First we need some groups, so API user must crete some groups
        data = {role:'editors', creator:'my_secret'}
        POST /api/authorization/group data

    Then client can assign user:
        data = {group:'editors', user='rodmena', creator='my_secret'}
        POST /api/authorization/membership

    Now we can add some permissions to editors group:
        data = {name:'can_read_my_posts', creator:'my_secret', group:'editors'}
        POST /api/authorization/permission data


Using permissions:
    Request:
        GET /api/authorization/has_permission/rodmena?name=can_read_my_posts
    Response:
        {
            "result":true
        }
"""


__all__ = ['make_db_connection', 'AuthMembership', 'AuthGroup', 'AuthPermission']

import os
import datetime
from mongoengine import *
from mongoengine import signals



def make_db_connection():
    mongo_host = os.getenv('MONGO_HOST') or '127.0.0.1'
    _mongo_port = os.getenv('MONGO_PORT') or 27017
    mongo_port = int(_mongo_port)
    connect('Authorization_0x0199', host=mongo_host, port=mongo_port)


def handler(event):
    """Signal decorator to allow use of callback functions as class decorators."""
    def decorator(fn):
        def apply(cls):
            event.connect(fn, sender=cls)
            return cls

        fn.apply = apply
        return fn
    return decorator


@handler(signals.pre_save)
def update_modified(sender, document):
    document.modified = datetime.datetime.now()


@update_modified.apply
class AuthGroup(Document):
    creator = StringField(max_length=64, required=True)
    role = StringField(max_length=32, unique_with='creator', required=True)
    description = StringField(max_length=256)
    is_active = BooleanField(default=True)
    date_created = DateTimeField(default=datetime.datetime.now())
    modified = DateTimeField()

    def __repr__(self):
        return '{}: <{}>'.format(
            self.__class__.__name__,
            self.role
        )


@update_modified.apply
class AuthMembership(Document):
    user = StringField(max_length=64, unique_with='creator', required=True)
    creator = StringField(max_length=64, required=True)
    groups = ListField(ReferenceField(AuthGroup))
    is_active = BooleanField(default=True)
    date_created = DateTimeField(default=datetime.datetime.now())
    modified = DateTimeField()

    def __repr__(self):
        return '{}: <{}>'.format(
            self.__class__.__name__,
            self.user
        )

'''
AuthPermission:
    name: can_read_asset_09a8sd08asd09as8d0as
    group: reference to group
existance of a record means there is permission.
'''


@update_modified.apply
class AuthPermission(Document):
    name = StringField(max_length=64, unique_with='creator', required=True)
    creator = StringField(max_length=64, required=True)
    groups = ListField(ReferenceField(AuthGroup, required=True))
    is_active = BooleanField(default=True)
    date_created = DateTimeField(default=datetime.datetime.now())
    modified = DateTimeField()

    def __repr__(self):
        return '{}: <{}>'.format(
            self.__class__.__name__,
            self.name
        )

