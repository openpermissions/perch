# -*- coding: utf-8 -*-
# Copyright 2016 Open Permissions Platform Coalition
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from setuptools import setup
import re

with open('perch/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

if not version:
    raise RuntimeError('Cannot find version information')

setup(
    name='opp-perch',
    version=version,
    description='Open Permissions Platform Couchdb Library',
    author='Open Permissions Platform Coalition',
    author_email='support@openpermissions.org',
    url='https://github.com/openpermissions/perch',
    packages=['perch'],
    install_requires=["tornado-couchdb==0.2.3",
                      "enum34==1.0.4",
                      "passlib==1.6.2",
                      "python-dateutil==2.5.2",
                      "voluptuous==0.8.9"]
)
