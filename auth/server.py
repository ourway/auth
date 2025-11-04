"""
Flask server command
"""

import multiprocessing

from waitress import serve

from auth.main import app

CPUs = multiprocessing.cpu_count()

_help = """
    ---------------------------------------------------------------
    | GET             | /ping                                     |
    | GET POST DELETE | /api/permission/{key}/{role}/{action}     |
    | GET POST DELETE | /api/membership/{key}/{user}/{role}       |
    | GET             | /api/has_permission/{key}/{user}/{action} |
    | GET             | /api/user_permissions/{key}/{user}        |
    | GET             | /api/user_roles/{key}/{user}              |
    | GET             | /api/role_permissions/{key}/{role}        |
    | GET             | /api/members/{key}/{role}                 |
    | GET             | /api/roles/{key}/                         |
    | GET             | /api/which_roles_can/{key}/{action}       |
    | GET             | /api/which_users_can/{key}/{action}       |
    | POST DELETE     | /api/role/{key}/{role}                    |
    ---------------------------------------------------------------
"""


def main(port=4000, host="0.0.0.0"):
    print(
        "\n\n        Python Auth Server ------------\n\t"
        "by: Farshid Ashouri (@RODMENA LIMITED)\n"
    )
    print(_help)

    # Limit workers to maximum of 4
    worker_count = min(CPUs * 2, 4)
    serve(app, host=host, port=port, threads=worker_count)


if __name__ == "__main__":
    main()
