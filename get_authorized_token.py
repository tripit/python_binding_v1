#!/usr/bin/env python
#
# Copyright 2008-2012 Concur Technologies, Inc.
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

import sys

import tripit

def main(argv):
    if len(argv) < 5:
        print "Usage: get_authorized_token.py api_url consumer_key consumer_secret request_token request_token_secret"
        return 1
    
    api_url = argv[0]
    consumer_key = argv[1]
    consumer_secret = argv[2]
    request_token = argv[3]
    request_token_secret = argv[4]

    oauth_credential = tripit.OAuthConsumerCredential(consumer_key, consumer_secret, request_token, request_token_secret)
    t = tripit.TripIt(oauth_credential, api_url = api_url)
    print t.get_access_token()

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
