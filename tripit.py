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

"""
  Methods to interact with the TripIt v1 API
"""

import base64
import datetime
import hmac
from hashlib import md5
import random
import re
import time
import urllib
import urllib2
import traceback
import xml.sax
import json

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

class WebAuthCredential:
    def __init__(self, username, password):
        self._username = username
        self._password = password

    def getUsername(self):
        return self._username

    def getPassword(self):
        return self._password
    
    def authorize(self, request, args):
        pair = "%s:%s" % (self._username, self._password)
        token = base64.b64encode(pair)
        request.add_header('Authorization', 'Basic %s' % token)

# } class:WebAuthCredential

class OAuthConsumerCredential:
    OAUTH_SIGNATURE_METHOD = 'HMAC-SHA1'
    OAUTH_VERSION = '1.0'
    
    # You can construct 3 kinds of OAuth credentials:
    # 1. A credential with no token (to get a request token):
    #    OAuthConsumerCredential('consumer_key', 'consumer_secret')
    #    OAuthConsumerCredential(oauth_consumer_key='consumer_key', oauth_consumer_secret='consumer_secret')
    # 2. A 3 legged OAuth credential (request or authorized token):
    #    OAuthConsumerCredential('consumer_key', 'consumer_secret', 'token', 'token_secret')
    #    OAuthConsumerCredential(oauth_consumer_key='consumer_key', oauth_consumer_secret='consumer_secret', oauth_token='token', oauth_token_secret='token_secret')
    # 3. A 2 legged OAuth credential:
    #    OAuthConsumerCredential('consumer_key', 'consumer_secret', 'requestor_id')
    #    OAuthConsumerCredential(oauth_consumer_key='consumer_key', oauth_consumer_secret='consumer_secret', oauth_requestor_id='requestor_id')
    def __init__(self, oauth_consumer_key, oauth_consumer_secret,
                 oauth_token='', oauth_token_secret='', oauth_requestor_id=''):
        self._oauth_consumer_key     = oauth_consumer_key
        self._oauth_consumer_secret  = oauth_consumer_secret
        
        self._oauth_oauth_token = self._oauth_token_secret = self._oauth_requestor_id = '' 
        if oauth_token != '' and oauth_token_secret != '':
            self._oauth_oauth_token      = oauth_token
            self._oauth_token_secret     = oauth_token_secret
        elif oauth_token != '':
            self._oauth_requestor_id = oauth_token
        elif oauth_requestor_id != '':
            self._oauth_requestor_id = oauth_requestor_id
        
    def authorize(self, request, args):
        request.add_header('Authorization',
            self._generate_authorization_header(
                request, args))
    
    def validateSignature(self, url):
        base_url, query = url.split("?", 1)
        params = {}
        def parse_param(param_string):
            name, value = param_string.split("=", 1)
            params[urllib.unquote(name)] = urllib.unquote(value)
        map(parse_param, query.split("&"))
        
        signature = params.get('oauth_signature')
        
        return signature == self._generate_signature('GET', base_url, params)

    def getOAuthConsumerKey(self):
        return self._oauth_consumer_key
    
    def getOAuthConsumerSecret(self):
        return self._oauth_consumer_secret

    def getOAuthToken(self):
        return self._oauth_oauth_token

    def getOAuthTokenSecret(self):
        return self._oauth_token_secret
    
    def getOAuthRequestorId(self):
        return self._oauth_requestor_id
    
    def getSessionParameters(self, redirect_url, action):
        params = self._generate_oauth_parameters('GET', action, {'redirect_url':redirect_url})
        params['redirect_url'] = redirect_url
        params['action'] = action
        return json.dumps(params)
    
    def _generate_authorization_header(self, request, args):
        realm = request.get_type() + '://' + request.get_host()
        http_method = request.get_method().upper()
        http_url = request.get_type() + '://' + request.get_host() + request.get_selector().split('?', 1)[0]
        return ('OAuth realm="%s",' % (realm)) + \
            ','.join(
                ['%s="%s"' % (_escape(k), _escape(v))
                 for k, v in self._generate_oauth_parameters(
                     http_method, http_url, args).items()])

    def _generate_oauth_parameters(self, http_method, http_url, args):
        oauth_parameters = {
            'oauth_consumer_key'     :
                self._oauth_consumer_key,
            'oauth_nonce'            : _generate_nonce(),
            'oauth_timestamp'        : str(int(time.time())),
            'oauth_signature_method' :
                OAuthConsumerCredential.OAUTH_SIGNATURE_METHOD,
            'oauth_version'          : OAuthConsumerCredential.OAUTH_VERSION
            }
        if self._oauth_oauth_token != '':
            oauth_parameters['oauth_token'] = \
                self._oauth_oauth_token
        
        if self._oauth_requestor_id != '':
            oauth_parameters['xoauth_requestor_id'] = \
                self._oauth_requestor_id

        oauth_parameters_for_base_string = oauth_parameters.copy()
        if args is not None:
            oauth_parameters_for_base_string.update(args)

        oauth_parameters['oauth_signature'] = self._generate_signature(http_method, http_url, oauth_parameters_for_base_string)
        
        return oauth_parameters
    
    def _generate_signature(self, method, base_url, params):
        base_url = _escape(base_url)
        
        params.pop('oauth_signature', None)
        
        parameters = _escape(
            '&'.join(
                ['%s=%s' % \
                 (_escape(str(k)), _escape(str(params[k]))) \
                 for k in sorted(params)]))

        signature_base_string = '&'.join([method, base_url, parameters])
        
        key = self._oauth_consumer_secret + '&' + self._oauth_token_secret
        
        try:
            import hashlib
            hashed = hmac.new(key, signature_base_string, hashlib.sha1)
        except ImportError:
            import sha
            hashed = hmac.new(key, signature_base_string, sha)
    
        return base64.b64encode(hashed.digest())

# } class:OAuthConsumerCredential

def _escape(s):
    return urllib.quote(str(s), safe='~')

def _generate_nonce():
    random_number = ''.join(str(random.randint(0, 9)) for _ in range(40))
    m = md5(str(time.time()) + str(random_number))
    return m.hexdigest()

class ResponseHandler(xml.sax.handler.ContentHandler):
    def __init__(self):
        xml.sax.handler.ContentHandler.__init__(self)
        self._element_stack = []
        self._current_content = None
        self._root_obj = None

    def get_response_obj(self):
        return self._root_obj

    def startElement(self, name, attrs):
        if re.match('[A-Z]', name):
            type_name = str(name)
            data_node = TravelObj(type_name, (),
                                  { '_attributes' : { }, '_children' : [] })
            if len(self._element_stack) > 0:
                self._element_stack[-1].add_child(data_node)
            self._element_stack.append(data_node)
            if self._root_obj is None:
                self._root_obj = self._element_stack[0]

    def endElement(self, name):
        if self._current_content is not None:
            if name.endswith('date'):
                self._current_content = datetime.date(
                    *(time.strptime(
                        self._current_content, '%Y-%m-%d')[0:3]))
            elif name.endswith('time'):
                self._current_content = datetime.time(
                    *(time.strptime(
                        self._current_content, '%H:%M:%S')[3:6]))

            self._element_stack[-1].set_attribute(name, self._current_content)
            
            self._current_content = None

        if re.match('[A-Z]', name):
            self._element_stack.pop()

    def characters(self, content):
        if self._current_content is not None:
            self._current_content = '%s%s' % (self._current_content, content)
        else:
            self._current_content = content

# } class:ResponseHandler

class TravelObj(type):
    def __new__(cls, name, bases, dict):
        return type.__new__(cls, name, bases, dict)

    def __init__(cls, name, bases, dict):
        super(TravelObj, cls).__init__(name, bases, dict)

    def __getattr__(self, name):
        return self.get_attribute_value(name)

    def __cmp__(self, other):
        # start_date
        try:
            if self.start_date and other.start_date:
                return cmp(self.start_date, other.start_date)
        except AttributeError:
            pass

        # StartDateTime or DateTime
        try:
            cls_start_datetime_obj = None
            other_start_datetime_obj = None
            for child in self.get_children():
                if child.__name__ == 'StartDateTime' or \
                child.__name__ == 'DateTime':
                    cls_start_datetime_obj = datetime.datetime.combine(
                        child.date, child.time)
                    break

            for child in other.get_children():
                if child.__name__ == 'StartDateTime' or \
                child.__name__ == 'DateTime':
                    other_start_datetime_obj = datetime.datetime.combine(
                        child.date, child.time)
                    break
            return cmp(cls_start_datetime_obj, other_start_datetime_obj)
        except Exception:
            pass
    
    def set_attribute(self, name, value):
        self._attributes[name] = value

    def add_child(self, child):
        self._children.append(child)

    def get_attribute_names(self):
        return self._attributes.keys()

    def get_attribute_value(self, name):
        if name in self._attributes:
            return self._attributes[name]
        else:
            raise AttributeError("'TravelObj' has no attribute '%s'" % name)

    def get_children(self):
        return self._children

    def has_error(self):
        for o in self._children:
            if o.__name__ == 'Error':
                return True
        return False

    def has_warning(self):
        for o in self._children:
            if o.__name__ == 'Warning':
                return True
        return False

# } class:TravelObj

class TripIt(object):
    # webauth_credentials and oauth_credentials are for backward compatibility
    # of keyword arguments. Consider them deprecated and instead use either
    # the first positional argument, or the "credential" keyword argument
    # for either type of credential.
    #
    # NOTE that if you were using positional arguments before for anything but
    # webauth credentials, the signature of this constructor has changed, and
    # you will need to update your code to match.
    #
    # Also, note that despite having a default value, the "credential" parameter
    # is NOT optional. In a future release, the default value, and the
    # webauth_credentials and oauth_credentials keyword parameters will be removed.
    def __init__(self, credential = None, api_url='https://api.tripit.com',
                 webauth_credentials = None, oauth_credentials = None):
        self._api_url     = api_url
        self._api_version = 'v1'
        self._credential  = credential or oauth_credentials or webauth_credentials

        self.resource  = None
        self.response  = None
        self.http_code = None

    def _do_request(self, verb, entity=None, url_args=None, post_args=None):
        """
        Makes a request POST/GET to the API and returns the response
          from the server.
        """
        if verb in ['/oauth/request_token', '/oauth/access_token']:
            base_url = self._api_url + verb
        else:
            if entity is not None:
                base_url = '/'.join(
                    [self._api_url, self._api_version, verb, entity])
            else:
                base_url = '/'.join([self._api_url, self._api_version, verb])

        args = None
        if url_args is not None:
            args = url_args
            url = base_url + '?' + urllib.urlencode(url_args)
        else:
            url = base_url

        self.resource = url

        if post_args is not None:
            args = post_args
            request = urllib2.Request(url, urllib.urlencode(post_args))
        else:
            request = urllib2.Request(url)
            
        self._credential.authorize(request, args)

        stream = None
        try:
            stream = urllib2.urlopen(request)
            self.http_code = 200
        except urllib2.HTTPError, http_error:
            self.http_code = http_error.code
            stream = http_error

        data = stream.read()
        stream.close()
        self.response = data
        return data

    def _parse_command(self, params=None, post_args=None, override_verb=None):
        verb = override_verb
        entity = None
        if verb is None:
            command = traceback.extract_stack()[-2][2]
            try:
                (verb, entity) = command.split('_', 1)
            except ValueError:
                verb = command
                entity = None

        response_data = self._do_request(verb, entity, params, post_args)
        return _xml_to_py(response_data)

    def get_trip(self, id, filter=None):
        if filter is None:
            filter = {}
        filter['id'] = id
        return self._parse_command(filter)

    def get_air(self, id):
        return self._parse_command({ 'id' : id })

    def get_lodging(self, id):
        return self._parse_command({ 'id' : id })

    def get_car(self, id):
        return self._parse_command({ 'id' : id })

    def get_points_program(self, id):
        return self._parse_command({ 'id' : id })

    def get_profile(self):
        return self._parse_command()

    def get_rail(self, id):
        return self._parse_command({ 'id' : id })

    def get_transport(self, id):
        return self._parse_command({ 'id' : id })

    def get_cruise(self, id):
        return self._parse_command({ 'id' : id })

    def get_restaurant(self, id):
        return self._parse_command({ 'id' : id })

    def get_activity(self, id):
        return self._parse_command({ 'id' : id })

    def get_note(self, id):
        return self._parse_command({ 'id' : id })

    def get_map(self, id):
        return self._parse_command({ 'id' : id })

    def get_directions(self, id):
        return self._parse_command({ 'id' : id })

    def delete_trip(self, id):
        return self._parse_command({ 'id' : id })

    def delete_air(self, id):
        return self._parse_command({ 'id' : id })

    def delete_lodging(self, id):
        return self._parse_command({ 'id' : id })

    def delete_car(self, id):
        return self._parse_command({ 'id' : id })

    def delete_rail(self, id):
        return self._parse_command({ 'id' : id })

    def delete_transport(self, id):
        return self._parse_command({ 'id' : id })

    def delete_cruise(self, id):
        return self._parse_command({ 'id' : id })

    def delete_restaurant(self, id):
        return self._parse_command({ 'id' : id })

    def delete_activity(self, id):
        return self._parse_command({ 'id' : id })

    def delete_note(self, id):
        return self._parse_command({ 'id' : id })

    def delete_map(self, id):
        return self._parse_command({ 'id' : id })

    def delete_directions(self, id):
        return self._parse_command({ 'id' : id })
    
    def replace_trip(self, id, xml):
        return self._parse_command({ 'id' : id, 'xml' : xml })

    def replace_air(self, id, xml):
        return self._parse_command({ 'id' : id, 'xml' : xml })

    def replace_lodging(self, id, xml):
        return self._parse_command({ 'id' : id , 'xml' : xml})

    def replace_car(self, id, xml):
        return self._parse_command({ 'id' : id, 'xml' : xml })

    def replace_rail(self, id, xml):
        return self._parse_command({ 'id' : id, 'xml' : xml })

    def replace_transport(self, id, xml):
        return self._parse_command({ 'id' : id, 'xml' : xml })

    def replace_cruise(self, id, xml):
        return self._parse_command({ 'id' : id, 'xml' : xml })

    def replace_restaurant(self, id, xml):
        return self._parse_command({ 'id' : id, 'xml' : xml })

    def replace_activity(self, id, xml):
        return self._parse_command({ 'id' : id, 'xml' : xml })

    def replace_note(self, id, xml):
        return self._parse_command({ 'id' : id, 'xml' : xml })

    def replace_map(self, id, xml):
        return self._parse_command({ 'id' : id, 'xml' : xml })

    def replace_directions(self, id, xml):
        return self._parse_command({ 'id' : id, 'xml' : xml })

    def list_trip(self, filter=None):
        return self._parse_command(filter)

    def list_object(self, filter=None):
        return self._parse_command(filter)

    def list_points_program(self):
        return self._parse_command()

    def create(self, xml):
        return self._parse_command(None, { 'xml' : xml })
    
    def crs_load_reservations(self, xml, company_key=None):
        args = {'xml' : xml}
        if company_key is not None:
            args['company_key'] = company_key
        return self._parse_command(None, args, 'crsLoadReservations')
    
    def crs_delete_reservations(self, record_locator):
        return self._parse_command({'record_locator' : record_locator}, None, 'crsDeleteReservations')

    def get_request_token(self):
        response = self._do_request('/oauth/request_token')

        if self.http_code == 200:
            return _parse_qs(response)
        else:
            return response

    def get_access_token(self):
        response = self._do_request('/oauth/access_token')

        if self.http_code == 200:
            return _parse_qs(response)
        else:
            return response

# } class:TripIt

def _parse_qs(qs):
    request_params = {}
    for param in qs.split('&'):
        (request_param, request_param_value) = param.split('=')
        request_params[request_param] = request_param_value

    return request_params

def _xml_to_py(data):
    parser = xml.sax.make_parser()
    handler = ResponseHandler()
    parser.setContentHandler(handler)
    parser.parse(StringIO(data))
    return handler.get_response_obj()
