#!/usr/bin/env python

## AuthGroup, AuthPermission, AuthMembership
import json
try:
    import ujson as json
except ImportError:
    pass


from auth.CAS.models.db import *
from mongoengine.errors import NotUniqueError


class Authorization(object):
    """ Main Authorization class """

    def __init__(self, client):
        """Initialize Authorization with a client
        @type client: String
        """
        self.client = client
        make_db_connection()

    @property
    def roles(self):
        """gets user groups"""
        result = AuthGroup.objects(creator=self.client).only('role')
        return json.loads(result.to_json())

    def get_permissions(self, role):
        """gets permissions of role"""
        target_role = AuthGroup.objects(role=role, creator=self.client).first()
        if not target_role:
            return '[]'
        targets = AuthPermission.objects(groups=target_role, creator=self.client).only('name')
        return json.loads(targets.to_json())


    def get_user_permissions(self, user):
        """get permissions of a user"""
        memberShipRecords = AuthMembership.objects(creator=self.client, user=user).only('groups')
        results = []
        for each in memberShipRecords:
            for group in each.groups:
                targetPermissionRecords = AuthPermission.objects(creator=self.client,
                                            groups=group).only('name')

                for each_permission in targetPermissionRecords:
                    results.append({'name':each_permission.name})
        return results

    def get_user_roles(self, user):
        """get permissions of a user"""
        memberShipRecords = AuthMembership.objects(creator=self.client, user=user).only('groups')
        results = []
        for each in memberShipRecords:
            for group in each.groups:
                results.append({'role':group.role})
        return results


    def get_role_members(self, role):
        """get permissions of a user"""
        targetRoleDb = AuthGroup.objects(creator=self.client, role=role)
        members = AuthMembership.objects(groups__in=targetRoleDb).only('user')
        return json.loads(members.to_json())

    def which_roles_can(self, name):
        """Which role can SendMail? """
        targetPermissionRecords = AuthPermission.objects(creator=self.client, name=name).first()
        return [{'role': group.role} for group in targetPermissionRecords.groups]

    def which_users_can(self, name):
        """Which role can SendMail? """
        _roles = self.which_roles_can(name)
        result =  [self.get_role_members(i.get('role')) for i in _roles]
        return result

    def get_role(self, role):
        """Returns a role object
        """
        role = AuthGroup.objects(role=role, creator=self.client).first()
        return role

    def add_role(self, role, description=None):
        """ Creates a new group """
        new_group = AuthGroup(role=role, creator=self.client)
        try:
            new_group.save()
            return True
        except NotUniqueError:
            return False

    def del_role(self, role):
        """ deletes a group """
        target = AuthGroup.objects(role=role, creator=self.client).first()
        if target:
            target.delete()
            return True
        else:
            return False

    def add_membership(self, user, role):
        """ make user a member of a group """
        targetGroup = AuthGroup.objects(role=role, creator=self.client).first()
        if not targetGroup:
            return False

        target = AuthMembership.objects(user=user, creator=self.client).first()
        if not target:
            target = AuthMembership(user=user, creator=self.client)

        if not role in [i.role for i in target.groups]:
            target.groups.append(targetGroup)
            target.save()
        return True


    def del_membership(self, user, role):
        """  dismember user from a group """
        if not self.has_membership(user, role):
            return True
        targetRecord = AuthMembership.objects(creator=self.client, user=user).first()
        if not targetRecord:
            return True
        for group in targetRecord.groups:
            if group.role==role:
                targetRecord.groups.remove(group)
        targetRecord.save()
        return True

    def has_membership(self, user, role):
        """ checks if user is member of a group"""
        targetRecord = AuthMembership.objects(creator=self.client, user=user).first()
        if targetRecord:
            return role in [i.role for i in targetRecord.groups]
        return False


    def add_permission(self, role, name):
        """ authorize a group for something """
        if self.has_permission(role, name):
            return True
        targetGroup = AuthGroup.objects(role=role, creator=self.client).first()
        if not targetGroup:
            return False
        # Create or update
        permission = AuthPermission.objects(name=name).update(
                add_to_set__groups=[targetGroup], creator=self.client, upsert=True
        )
        return True

    def del_permission(self, role, name):
        """ revoke authorization of a group """
        if not self.has_permission(role, name):
            return True
        targetGroup = AuthGroup.objects(role=role, creator=self.client).first()
        target = AuthPermission.objects(groups=targetGroup, name=name, creator=self.client).first()
        if not target:
            return True
        target.delete()
        return True

    def has_permission(self, role, name):
        """ verify groups authorization """
        targetGroup = AuthGroup.objects(role=role, creator=self.client).first()
        if not targetGroup:
            return False
        target = AuthPermission.objects(groups=targetGroup, name=name, creator=self.client).first()
        if target:
            return True
        return  False

    def user_has_permission(self, user, name):
        """ verify user has permission """
        targetRecord = AuthMembership.objects(creator=self.client, user=user).first()
        if not targetRecord:
            return False
        for group in targetRecord.groups:
            if self.has_permission(group.role, name):
                return True
        return False

