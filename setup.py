from setuptools import setup

setup(
    name='django_microservice_auth',
    version='0.0.1',
    description='Django Microservice Authentication package',
    url='https://github.com/uwaiszaki/django_user_service_auth.git',
    author='Uwais Zaki',
    author_email='uwaiszaki104@gmail.com',
    license='unlicense',
    packages=['django_microservice_auth'],
    install_requires=[
        'Django==3.2.',
        'djangorestframework-jwt==1.11.0',
    ],
)
