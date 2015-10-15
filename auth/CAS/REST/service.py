import falcon
import json
from auth.CAS.authorization import Authorization


def stringify(req, resp):
    """
    dumps all valid jsons
    This is the latest after hook
    """
    if isinstance(resp.body, dict):
        try:
            resp.body = json.dumps(resp.body)
        except(nameError):
            resp.status = falcon.HTTP_500


class Ping:
    def on_get(self, req, resp):
        """Handles GET requests"""
        resp.body = {'message':'PONG'}


class Membership:
    def on_get(self, req, resp, client, user, group):
        cas = Authorization(client)
        resp.body={'result':False}
        if cas.has_membership(user, group):
            resp.body={'result':True}

    def on_post(self, req, resp, client, user, group):
        cas = Authorization(client)
        resp.body={'result':False}
        if cas.add_membership(user, group):
            resp.body={'result':True}


    def on_delete(self, req, resp, client, user, group):
        cas = Authorization(client)
        resp.body={'result':False}
        if cas.del_membership(user, group):
            resp.body={'result':True}


class Permission:
    def on_get(self, req, resp, client, group, name):
        cas = Authorization(client)
        resp.body={'result':False}
        if cas.has_permission(group, name):
            resp.body={'result':True}

    def on_post(self, req, resp, client, group, name):
        cas = Authorization(client)
        resp.body={'result':False}
        if cas.add_permission(group, name):
            resp.body={'result':True}

    def on_delete(self, req, resp, client, group, name):
        cas = Authorization(client)
        resp.body={'result':False}
        if cas.del_permission(group, name):
            resp.body={'result':True}


class UserPermission:
    def on_get(self, req, resp, client, user, name):
        cas = Authorization(client)
        resp.body={'result':False}
        if cas.user_has_permission(user,name):
            resp.body={'result':True}

class Group:
    def on_post(self, req, resp, client, group):
        cas = Authorization(client)
        resp.body={'result':False}
        if cas.add_group(group):
            resp.body={'result':True}


    def on_delete(self, req, resp, client, group):
        cas = Authorization(client)
        resp.body={'result':False}
        if cas.del_group(group):
            resp.body={'result':True}



api = falcon.API(after=[stringify])
api.add_route('/ping', Ping())
api.add_route('/api/membership/{client}/{user}/{group}', Membership())
api.add_route('/api/permission/{client}/{group}/{name}', Permission())
api.add_route('/api/has_permission/{client}/{user}/{name}', UserPermission())
api.add_route('/api/role/{client}/{group}', Group())
