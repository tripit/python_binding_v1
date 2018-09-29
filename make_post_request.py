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


import sys

import tripit

def main(argv):
    trip_xml = "<Request><Trip>" \
               "<start_date>2009-12-09</start_date>" \
               "<end_date>2009-12-27</end_date>" \
               "<primary_location>New York, NY</primary_location>" \
               "</Trip></Request>"
               
    trip_xml2 = "<Request><Trip>" \
                "<start_date>2010-12-09</start_date>" \
                "<end_date>2010-12-27</end_date>" \
                "<primary_location>Boston, MA</primary_location>" \
                "</Trip></Request>"

    if len(argv) < 5:
        print "Usage: make_post_request.py request_url consumer_key consumer_secret access_token access_token_secret"
        return 1
    
    request_url = argv[0]
    consumer_key = argv[1]
    consumer_secret = argv[2]
    access_token = argv[3]
    access_token_secret = argv[4]

    oauth_credential = tripit.OAuthConsumerCredential(consumer_key, consumer_secret, access_token, access_token_secret)
    t = tripit.TripIt(oauth_credential, api_url=request_url)
    r = t.create(trip_xml)
    print 'RESPONSE: %s' % r
    id = r.get_children()[0].get_attribute_value('id')
    r = t.replace_trip(id, trip_xml2)
    print '\nRESPONSE: %s' % r

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
