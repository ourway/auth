import multiprocessing

from auth.server import main as serve

CPUs = multiprocessing.cpu_count()


_help = """
    Authenticate with header:  Authorization: Bearer <client-uuid4>
    -----------------------------------------------------------------
    | GET             | /ping                                       |
    | GET             | /health                                     |
    | GET POST DELETE | /api/membership/{user}/{role}               |
    | GET POST DELETE | /api/permission/{role}/{name}               |
    | GET             | /api/has_permission/{user}/{name}           |
    | GET             | /api/user_permissions/{user}                |
    | GET             | /api/user_roles/{user}                      |
    | GET             | /api/role_permissions/{role}                |
    | GET             | /api/members/{role}                         |
    | GET             | /api/roles                                  |
    | GET             | /api/which_roles_can/{name}                 |
    | GET             | /api/which_users_can/{name}                 |
    | POST DELETE     | /api/role/{role}                            |
    | GET             | /api/workflow/users/{workflow}              |
    | GET             | /api/workflow/user/{user}/can_run/{workflow}|
    -----------------------------------------------------------------
"""


def main(port=4000):
    print(
        "\n\n        Python Auth Server ------------\n\t"
        "by: Farshid Ashouri (@RODMENA LIMITED)\n"
    )
    print(_help)
    serve(port=port)


if __name__ == "__main__":
    main()
