import glob
import imp
import io
import os
from os import path
from setuptools import setup, find_packages, Extension
import sys

MYDIR = path.abspath(os.path.dirname(__file__))

# NOTE
REQUIRES = ['falcon', 'mongoengine', 'blinker', 'werkzeug', 'gunicorn',
    'eventlet', 'requests']

cmdclass = {}
ext_modules = []

setup(
    name='auth',
    version='0.4.9',
    description='Authorization for humans',
    long_description=io.open('README.rst', 'r', encoding='utf-8').read(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Natural Language :: English',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Programming Language :: Python :: Implementation :: Jython',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
    ],
    keywords='authorizarion role auth groups membership ensure ldap',
    author='Farsheed Ashouri',
    author_email='rodmena@me.com',
    url='http://github.com/ourway/auth/',
    license='Apache 2.0',
    packages=find_packages(exclude=['tests']),
    include_package_data=True,
    zip_safe=False,
    install_requires=REQUIRES,
    setup_requires=[],
    cmdclass=cmdclass,
    ext_modules=ext_modules,
    test_suite='nose.collector',
    entry_points={
        'console_scripts': [
                'auth-server = auth.cmd.server:main'
             ]
        }
)
