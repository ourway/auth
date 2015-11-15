
#try:
#    import eventlet
#    eventlet.monkey_patch()
#except:
#    pass

import falcon
import json
try:
    import ujson as json
except ImportError:
    pass

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

class GetUserPermissions:
    def on_get(self, req, resp, client, user):
        cas = Authorization(client)
        resp.body = {'results': cas.get_user_permissions(user)}


class GetRolePermissions:
    def on_get(self, req, resp, client, role):
        cas = Authorization(client)
        resp.body = {'results': cas.get_permissions(role)}


class GetRoleMembers:
    def on_get(self, req, resp, client, role):
        cas = Authorization(client)
        resp.body = {'result': cas.get_role_members(role)}


class GetUserRoles:
    def on_get(self, req, resp, client, user):
        cas = Authorization(client)
        resp.body = {'result': cas.get_user_roles(user)}


class ListRoles:
    def on_get(self, req, resp, client):
        cas = Authorization(client)
        resp.body = {'result':cas.roles}

class WhichRolesCan:
    def on_get(self, req, resp, client, name):
        cas = Authorization(client)
        resp.body = {'result':cas.which_roles_can(name)}

class WhichUsersCan:
    def on_get(self, req, resp, client, name):
        cas = Authorization(client)
        resp.body = {'result':cas.which_users_can(name)}





class Role:
    def on_post(self, req, resp, client, role):
        cas = Authorization(client)
        resp.body={'result':False}
        if cas.add_role(role):
            resp.body={'result':True}


    def on_delete(self, req, resp, client, group):
        cas = Authorization(client)
        resp.body={'result':False}
        if cas.del_role(group):
            resp.body={'result':True}



api = falcon.API(after=[stringify])
api.add_route('/ping', Ping())
api.add_route('/api/membership/{client}/{user}/{group}', Membership())  ## POST DELETE GET
api.add_route('/api/permission/{client}/{group}/{name}', Permission())  ## POST DELETE GET
api.add_route('/api/has_permission/{client}/{user}/{name}', UserPermission())  ## GET
api.add_route('/api/user_permissions/{client}/{user}', GetUserPermissions())  ## GET
api.add_route('/api/role_permissions/{client}/{role}', GetRolePermissions())  ## GET
api.add_route('/api/user_roles/{client}/{user}', GetUserRoles())  ## GET
api.add_route('/api/members/{client}/{role}', GetRoleMembers())  ## GET
api.add_route('/api/role/{client}/{role}', Role())  ## POST DELETE
api.add_route('/api/roles/{client}', ListRoles())  ## GET
api.add_route('/api/which_roles_can/{client}/{name}', WhichRolesCan())  ## GET
api.add_route('/api/which_users_can/{client}/{name}', WhichUsersCan())  ## GET
