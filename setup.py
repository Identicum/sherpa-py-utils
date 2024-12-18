# sherpa-py-utils is available under the MIT License. https://github.com/Identicum/sherpa-py-utils/
# Copyright (c) 2024, Identicum - https://identicum.com/
#
# Author: Ezequiel O Sandoval - esandoval@identicum.com
#

from setuptools import setup

setup(
    name='sherpa-py-utils',
    version='1.0.20241107',
    description='Python utilities on Identicum projects',
    url='git@github.com:Identicum/sherpa-py-utils.git',
    author='Identicum',
    author_email='esandoval@identicum.com',
    license='MIT License',
    install_requires=['requests', 'psutil', 'PyJWT', 'python-ldap'],
    packages=['sherpa', 'sherpa.utils'],
    zip_safe=False,
    python_requires='>=3.0'
)
