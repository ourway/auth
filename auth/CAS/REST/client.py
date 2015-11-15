
__author__ = 'Farsheed Ashouri'

import requests
from requests.exceptions import ConnectionError
import json
import re

try:
    import ujson as json
except ImportError:
    pass



services = {
    '/ping':['get'],
    '/api/membership/{client}/{user}/{group}':['post', 'delete', 'get'],
    '/api/permission/{client}/{group}/{name}':['post', 'delete', 'get'],
    '/api/has_permission/{client}/{user}/{name}':['get'],
    '/api/user_permissions/{client}/{user}' :['get'],
    '/api/role_permissions/{client}/{role}':['get'],
    '/api/user_roles/{client}/{user}':['get'],
    '/api/members/{client}/{role}':['get'],
    '/api/role/{client}/{role}':['post', 'delete'],
    '/api/roles/{client}':['get'],
    '/api/which_roles_can/{client}/{name}':['get'],
    '/api/which_users_can/{client}/{name}':['get'],
    }

translate = { 'get':'get', 'post':'add', 'delete':'remove' }


def connect(url, method='get'):
    func = requests.get
    if method=='post':
        func = requests.post
    elif method=='delete':
        func = requests.delete
    try:
        r = func(url)
        return r
    except ConnectionError:
        raise ConnectionError('Service Down')



def connection_factory(cls, url, method):
    def closure(*args, **kw):
        attrs = re.findall(re.compile(r'{([\w]+)'),url)
        kw['client'] = cls.api_key
        try:
            assert set(attrs) == set(kw.keys())
        except AssertionError:
            attrs.remove('client')
            raise AssertionError('I need %s.' % set(attrs))
        link = cls.service_url + url.format(**kw)
        r = connect(link, method)
        return json.loads(r.content.decode())
    closure.__doc__ = 'This function will call "%s" on server with method "%s"' % \
        (url, method.upper())
    return closure




class Client(object):
    """Client class to use in your applications"""
    def __new__(cls, api_key, service_url):
        cls.api_key = api_key
        cls.service_url = service_url
        pattern = re.compile(r'/api/([\w]+)/.*')
        for url in services:
            match = re.findall(pattern, url)
            if match and services[url]:
                for method in services[url]:
                    new_func_name = '%s_%s' % (translate[method], match[0])
                    setattr(cls, new_func_name, connection_factory(cls, url, method))
        return super(Client, cls).__new__(cls)

    def __repr__(self):
        output = ['Methods:']
        for i in dir(self):
            if i.startswith('get') or i.startswith('add') or i.startswith('remove'):
                output.append('  %s: %s'% (i, getattr(getattr(self, i), '__doc__')))
        return '\n'.join(output)


if __name__ == '__main__':
    c = Client('tt', 'http://192.168.99.100:4000')
    #c.services
    #print(c.get_user_roles())
    print(c.add_permission(group='myG', name='read_books'))
