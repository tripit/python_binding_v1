TripIt API Bindings - Python
============================

[API Documentation http://tripit.github.com/api/] (http://tripit.github.com/api/)

Example
=======

    import tripit

    consumer_key = '5dbf348aa966c5f7f07e8ce2ba5e7a3badc234bc'
    consumer_secret = 'fceb3aedb960374e74f559caeabab3562efe97b4'
    authorized_token_key = 'df919acd38722bc0bd553651c80674fab2b46508'
    authorized_token_secret = '1370adbe858f9d726a43211afea2b2d9928ed878'

    oauth_credential = tripit.OAuthConsumerCredential(consumer_key, consumer_secret, authorized_token_key, authorized_token_secret)

    t = tripit.TripIt(oauth_credential)

    # Lists the authenticated user's upcoming trips
    t.list_trip()
    print t.response
