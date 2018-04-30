from setuptools import setup


setup(
    name='scanner',
    version='1.0',
    description='Script scanning network periodically and writing information about users presence to database.',
    url='https://github.com/worstof3/scanner',
    author='Łukasz Karpiński',
    packages=['scanner'],
    install_requires=['scapy', 'asynctest'],
    test_suite='scanner.tests',
    entry_points={
        'console_scripts': [
            'scanner=scanner.script:main'
        ]
    }
)