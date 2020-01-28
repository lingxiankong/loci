#!/usr/bin/env python

import json
import os
import re
import ssl
from distutils.util import strtobool

try:
    import urllib2
except ImportError:
    # python3
    from urllib import request as urllib2

DOCKER_REGISTRY='registry.hub.docker.com'

def get_authenticate_details(protocol, registry, repo):
    # Make a request to the registry to read 'Www-Authenticate' header.
    # Parse it for use as auth location and details.

    # Check for known image registry.
    if registry == DOCKER_REGISTRY:
        auth_details = {
            'realm': 'https://auth.docker.io/token',
            'service': 'registry.docker.io',
            'scope': 'repository:{repo}:pull'.format(repo=repo)
        }
        return auth_details

    # Make a request for the latest image tag (Todo: just use real tag)
    url = "{protocol}://{registry}/v2/{repo}/manifests/latest".format(
                    protocol=protocol,
                    registry=registry,
                    repo=repo)

    try:
        req = urllib2.Request(url=url)
        if strtobool(os.environ.get('REGISTRY_INSECURE', "False")):
            resp = urllib2.urlopen(req, context=ssl._create_unverified_context())
        else:
            resp = urllib2.urlopen(req)
    except urllib2.HTTPError as err:
        # A 401 response is expected.
        if err.code != 401:
            return None

        bearerauth = err.hdrs.get('Www-Authenticate', None)
        preamble, tokens = bearerauth.split(' ')
        auth_details = {}
        for auth in tokens.split(','):
            key, value = auth.split('=')[0:2]
            auth_details[key] = value.strip('"')

        return auth_details

    return None


def get_token(protocol, registry, repo):
    auth_details = get_authenticate_details(protocol, registry, repo)

    url = "{realm}?scope={scope}&service={service}".format(
        realm=auth_details['realm'],
        scope=auth_details['scope'],
        service=auth_details['service'])
    print(url)
    try:
        r = urllib2.Request(url=url)
        if strtobool(os.environ.get('REGISTRY_INSECURE', "False")):
            resp = urllib2.urlopen(r, context=ssl._create_unverified_context())
        else:
            resp = urllib2.urlopen(r)
        resp_text = resp.read().decode('utf-8').strip()
        return json.loads(resp_text)['token']
    except urllib2.HTTPError as err:
        if err.reason == 'Not Found':
            return None

def get_sha(repo, tag, registry, protocol, token):
    url = "{}://{}/v2/{}/manifests/{}".format(protocol, registry, repo, tag)
    print(url)
    r = urllib2.Request(url=url)
    if token:
        r.add_header('Authorization', 'Bearer {}'.format(token))
    if strtobool(os.environ.get('REGISTRY_INSECURE', "False")):
        resp = urllib2.urlopen(r, context=ssl._create_unverified_context())
    else:
        resp = urllib2.urlopen(r)
    resp_text = resp.read().decode('utf-8').strip()
    return json.loads(resp_text)['fsLayers'][0]['blobSum']


def get_blob(repo, tag, protocol, registry=DOCKER_REGISTRY, token=None):
    sha = get_sha(repo, tag, registry, protocol, token)
    url = "{}://{}/v2/{}/blobs/{} ".format(protocol, registry, repo, sha)
    print(url)
    r = urllib2.Request(url=url)
    if token:
        r.add_header('Authorization', 'Bearer {}'.format(token))
    if strtobool(os.environ.get('REGISTRY_INSECURE', "False")):
        resp = urllib2.urlopen(r, context=ssl._create_unverified_context())
    else:
        resp = urllib2.urlopen(r)
    return resp.read()

def protocol_detection(registry, protocol='http'):
    PROTOCOLS = ('http','https')
    index = PROTOCOLS.index(protocol)
    try:
        url = "{}://{}".format(protocol, registry)
        r = urllib2.Request(url)
        resp = urllib2.urlopen(r)
    except (urllib2.URLError,urllib2.HTTPError) as err:
        if err.reason == 'Forbidden':
            return protocol
        elif index < len(PROTOCOLS) - 1:
            return protocol_detection(registry, PROTOCOLS[index + 1])
        else:
            raise Exception("Cannot detect protocol for registry: {} due to error: {}".format(registry,err))
    except:
        raise
    else:
        return protocol

def get_wheels(url):
    r = urllib2.Request(url=url)
    if strtobool(os.environ.get('REGISTRY_INSECURE', "False")):
        resp = urllib2.urlopen(r, context=ssl._create_unverified_context())
    else:
        resp = urllib2.urlopen(r)
    return resp.read()

def parse_image(full_image):
    slash_occurrences = len(re.findall('/',full_image))
    repo = None
    registry = DOCKER_REGISTRY
    if slash_occurrences > 1:
        full_image_list = full_image.split('/')
        registry = full_image_list[0]
        repo = '/'.join(full_image_list[1:-1])
        image = full_image_list[-1]
    elif slash_occurrences == 1:
        repo, image = full_image.split('/')
    else:
        image = full_image
    if image.find(':') != -1:
        image, tag = image.split(':')
    else:
        tag = 'latest'
    return registry, repo+'/'+image if repo else image, tag

def main():
    if 'WHEELS' in os.environ:
        wheels = os.environ['WHEELS']
    else:
        with open('/opt/loci/wheels', 'r') as f:
            wheels = f.read()

    if wheels.startswith('/'):
        with open(wheels, 'rb') as f:
            data = f.read()
    elif wheels.startswith('http'):
        data = get_wheels(wheels)
    else:
        registry, image, tag = parse_image(wheels)
        if os.environ.get('REGISTRY_PROTOCOL') in ['http', 'https']:
            protocol = os.environ.get('REGISTRY_PROTOCOL')
        elif os.environ.get('REGISTRY_PROTOCOL') == 'detect':
            protocol = protocol_detection(registry)
        else:
            raise ValueError("Unknown protocol given in argument")
        kwargs = dict()
        if registry:
            kwargs.update({'registry': registry})
        kwargs.update({'token': get_token(protocol, registry, image)})
        data = get_blob(image, tag, protocol, **kwargs)

    if 'WHEELS_DEST' in os.environ:
        dest = os.environ['WHEELS_DEST']
    else:
        with open('/opt/loci/wheels', 'w') as f:
            f.write(wheels)
        dest = '/tmp/wheels.tar.gz'
    with open(dest, 'wb') as f:
        f.write(data)


if __name__ == '__main__':
    main()
