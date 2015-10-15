#!/usr/bin/env python

## AuthGroup, AuthPermission, AuthMembership
from auth.CAS.models.db import *
from mongoengine.errors import NotUniqueError


class Authorization(object):
    """ Main Authorization class """

    def __init__(self, client):
        """Initialize Authorization with a client
        @type client: String
        """
        self.client = client

    @property
    def groups(self):
        """gets user groups"""
        result = AuthGroup.objects(creator=self.client).only('role')
        return result.to_json()

    def add_group(self, role, description=None):
        """ Creates a new group """
        new_group = AuthGroup(role=role, creator=self.client)
        try:
            new_group.save()
            return True
        except NotUniqueError:
            return False

    def del_group(self, role):
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
        new_permission = AuthPermission(group=targetGroup, name=name, creator=self.client)
        new_permission.save()
        return True

    def del_permission(self, role, name):
        """ revoke authorization of a group """
        if not self.has_permission(role, name):
            return True
        targetGroup = AuthGroup.objects(role=role, creator=self.client).first()
        target = AuthPermission.objects(group=targetGroup, name=name, creator=self.client).first()
        if not target:
            return True
        target.delete()
        return True

    def has_permission(self, role, name):
        """ verify groups authorization """
        targetGroup = AuthGroup.objects(role=role, creator=self.client).first()
        if not targetGroup:
            return False
        target = AuthPermission.objects(group=targetGroup, name=name, creator=self.client).first()
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

