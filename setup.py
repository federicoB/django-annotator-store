import os
from setuptools import find_packages, setup
from annotator_store import __version__

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

test_requirements = ['mock', 'pytest', 'pytest-django', 'pytest-cov'],

setup(
    name='annoator_store',
    version=__version__,
    packages=find_packages(),
    include_package_data=True,
    license='Apache License, Version 2.0',
    description='Django application to act as an annotator.js 2.x annotator-store backend',
    long_description=README,
    url='https://github.com/Princeton-CDH/django-annotator-store',
    install_requires=[
        'django',
        'django-guardian',
        'jsonfield',
    ],
    setup_requires=['pytest-runner'],
    tests_require=test_requirements,
    extras_require={
        'test': test_requirements,
    },
    author='CDH @ Princeton',
    author_email='digitalhumanities@princeton.edu',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.10',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        # 'Programming Language :: Python :: 3.4', ?
        'Programming Language :: Python :: 3.5',
    ],
)
