from flask import Flask, jsonify

from auth.dal.authorization_sqlite import Authorization

app = Flask(__name__)


@app.route("/ping", methods=["GET"])
def ping():
    """Handles GET requests"""
    return jsonify({"message": "PONG"})


@app.route("/api/membership/<client>/<user>/<group>", methods=["GET"])
def get_membership(client, user, group):
    cas = Authorization(client)
    result = False
    if cas.has_membership(user, group):
        result = True
    return jsonify({"result": result})


@app.route("/api/membership/<client>/<user>/<group>", methods=["POST"])
def add_membership(client, user, group):
    cas = Authorization(client)
    result = False
    if cas.add_membership(user, group):
        result = True
    return jsonify({"result": result})


@app.route("/api/membership/<client>/<user>/<group>", methods=["DELETE"])
def delete_membership(client, user, group):
    cas = Authorization(client)
    result = False
    if cas.del_membership(user, group):
        result = True
    return jsonify({"result": result})


@app.route("/api/permission/<client>/<group>/<name>", methods=["GET"])
def get_permission(client, group, name):
    cas = Authorization(client)
    result = False
    if cas.has_permission(group, name):
        result = True
    return jsonify({"result": result})


@app.route("/api/permission/<client>/<group>/<name>", methods=["POST"])
def add_permission(client, group, name):
    cas = Authorization(client)
    result = False
    if cas.add_permission(group, name):
        result = True
    return jsonify({"result": result})


@app.route("/api/permission/<client>/<group>/<name>", methods=["DELETE"])
def delete_permission(client, group, name):
    cas = Authorization(client)
    result = False
    if cas.del_permission(group, name):
        result = True
    return jsonify({"result": result})


@app.route("/api/has_permission/<client>/<user>/<name>", methods=["GET"])
def user_has_permission(client, user, name):
    cas = Authorization(client)
    result = False
    if cas.user_has_permission(user, name):
        result = True
    return jsonify({"result": result})


@app.route("/api/user_permissions/<client>/<user>", methods=["GET"])
def get_user_permissions(client, user):
    cas = Authorization(client)
    results = cas.get_user_permissions(user)
    return jsonify({"results": results})


@app.route("/api/role_permissions/<client>/<role>", methods=["GET"])
def get_role_permissions(client, role):
    cas = Authorization(client)
    results = cas.get_permissions(role)
    return jsonify({"results": results})


@app.route("/api/user_roles/<client>/<user>", methods=["GET"])
def get_user_roles(client, user):
    cas = Authorization(client)
    result = cas.get_user_roles(user)
    return jsonify({"result": result})


@app.route("/api/members/<client>/<role>", methods=["GET"])
def get_role_members(client, role):
    cas = Authorization(client)
    result = cas.get_role_members(role)
    return jsonify({"result": result})


@app.route("/api/roles/<client>", methods=["GET"])
def list_roles(client):
    cas = Authorization(client)
    result = cas.roles
    return jsonify({"result": result})


@app.route("/api/which_roles_can/<client>/<name>", methods=["GET"])
def which_roles_can(client, name):
    cas = Authorization(client)
    result = cas.which_roles_can(name)
    return jsonify({"result": result})


@app.route("/api/which_users_can/<client>/<name>", methods=["GET"])
def which_users_can(client, name):
    cas = Authorization(client)
    result = cas.which_users_can(name)
    return jsonify({"result": result})


@app.route("/api/role/<client>/<role>", methods=["POST"])
def add_role(client, role):
    cas = Authorization(client)
    result = False
    if cas.add_role(role):
        result = True
    return jsonify({"result": result})


@app.route("/api/role/<client>/<group>", methods=["DELETE"])
def delete_role(client, group):
    cas = Authorization(client)
    result = False
    if cas.del_role(group):
        result = True
    return jsonify({"result": result})
