#!/usr/bin/env python
#
# Copyright 2008-2018 Concur Technologies, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import getpass
import os
import tripit

def get_credential():
    username = raw_input('Username: ')
    password = getpass.getpass('Password: ')
    return tripit.WebAuthCredential(username, password)

api_url='https://api.tripit.com'

api_url = os.getenv('API_URL') or 'https://api.tripit.com'
print "api_url: %s" % api_url
cred = get_credential()
t = tripit.TripIt(cred, api_url=api_url)
