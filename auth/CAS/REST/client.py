__author__ = "Farshid Ashouri"

import json
import re

import requests
from requests.exceptions import ConnectionError

services = {
    "/ping": ["get"],
    "/api/membership/{user}/{group}": ["post", "delete", "get"],
    "/api/permission/{group}/{name}": ["post", "delete", "get"],
    "/api/has_permission/{user}/{name}": ["get"],
    "/api/user_permissions/{user}": ["get"],
    "/api/role_permissions/{role}": ["get"],
    "/api/user_roles/{user}": ["get"],
    "/api/members/{role}": ["get"],
    "/api/role/{role}": ["post", "delete"],
    "/api/roles": ["get"],
    "/api/which_roles_can/{name}": ["get"],
    "/api/which_users_can/{name}": ["get"],
}

translate = {"get": "get", "post": "add", "delete": "remove"}


def connect(url, method="get", headers=None):
    func = requests.get
    if method == "post":
        func = requests.post
    elif method == "delete":
        func = requests.delete
    try:
        r = func(url, headers=headers)
        return r
    except ConnectionError:
        raise ConnectionError("Service Down") from None


def connection_factory(cls, url, method):
    def closure(*args, **kw):
        attrs = re.findall(re.compile(r"{([\w]+)"), url)
        # kw["client"] is NO LONGER added here
        try:
            assert set(attrs) == set(kw.keys())
        except AssertionError:
            # attrs.remove("client") is NO LONGER needed
            raise AssertionError("I need %s." % set(attrs)) from None

        link = cls.service_url + url.format(**kw)

        # Create auth header
        headers = {"Authorization": f"Bearer {cls.api_key}"}

        r = connect(link, method, headers=headers)
        return json.loads(r.content.decode())

    closure.__doc__ = 'This function will call "%s" on server with method "%s"' % (
        url,
        method.upper(),
    )
    return closure


class Client(object):
    """Client class to use in your applications"""

    def __new__(cls, api_key, service_url):
        cls.api_key = api_key
        cls.service_url = service_url
        pattern = re.compile(r"/api/([\w]+)")
        for url in services:
            match = re.findall(pattern, url)
            if match and services[url]:
                # Handle /api/... URLs
                for method in services[url]:
                    new_func_name = "%s_%s" % (translate[method], match[0])
                    setattr(cls, new_func_name, connection_factory(cls, url, method))
            elif services[url]:
                # Handle other URLs like /ping by using the endpoint name
                # Extract the endpoint name from URL (e.g., "/ping" -> "ping")
                endpoint_name = url.strip("/").replace(
                    "-", "_"
                )  # e.g., "/ping" -> "ping", "/some-endpoint" -> "some_endpoint"
                for method in services[url]:
                    new_func_name = "%s_%s" % (translate[method], endpoint_name)
                    setattr(cls, new_func_name, connection_factory(cls, url, method))
        return super(Client, cls).__new__(cls)

    def __repr__(self):
        output = ["Methods:"]
        for i in dir(self):
            if i.startswith("get") or i.startswith("add") or i.startswith("remove"):
                method = getattr(self, i)
                output.append("  %s: %s" % (i, method.__doc__))
        return "\n".join(output)


if __name__ == "__main__":
    c = Client("tt", "http://192.168.99.100:4000")
    # c.services
    # print(c.get_user_roles())
    # print(c.add_permission(group="myG", name="read_books"))  # This method doesn't exist until dynamically created
