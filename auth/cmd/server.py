
from auth import api, serve
import sys
import multiprocessing
CPUs = multiprocessing.cpu_count()


_help = '''
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
'''



def main(port=4000):
    print('\n\n        Python Auth Server ------------\n\t'
          'by: Farsheed Ashouri (@rodmena)\n')
    print(_help)
    serve('0.0.0.0', port, api, processes=CPUs*2)


if __name__ == '__main__':
    main()
