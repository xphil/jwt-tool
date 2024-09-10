#!/usr/bin/env python3

"""
Author: Phil Levchenko
GitHub: https://github.com/xphil
Date: 2024-09-11
Description: Super simple tool to decode, validate and print
             out JWT tokens. Optionally with help of JWKS.
License: MIT
"""

import argparse
import sys
import textwrap
import base64

import jwt
import json
from jwt import PyJWKClient, ExpiredSignatureError, InvalidTokenError
import urllib


VERSION = '0.1'


def validate_and_decode_jwt_with_jwks(token, jwk_set_uri):
    assert len(jwk_set_uri) > 7
    assert token != ""

    try:
        header_data = jwt.get_unverified_header(token)
        # Fetch the public key from the JWKS endpoint

        signing_key = None
        jwks_client = PyJWKClient(jwk_set_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        key = signing_key.key

        algorithms = [header_data['alg']]
        options = {}
        if g_args.args.no_validate_exp:
            options["verify_exp"] = False
        if g_args.args.no_validation:
            options["verify_signature"] = False
        # Decode the token with the secret key
        decoded_token = jwt.decode(token, key, algorithms=algorithms, options=options)

        # If decoding was successful, return the decoded token
        return decoded_token, header_data

    except ExpiredSignatureError:
        # Token has expired
        g_cp.red("Error: token has expired")
        return (None, None)
    except InvalidTokenError:
        # Token is invalid
        g_cp.red("Error: invalid token")
        return (None, None)
    except urllib.error.URLError:
        g_cp.red("Error: incorrect JWK Set URI")
        return (None, None)


def base64_url_decode(input_str):
    padding = '=' * (4 - len(input_str) % 4)  # Add padding if necessary
    return base64.urlsafe_b64decode(input_str + padding)


def decode_jwt(token):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT token format.")

    header = parts[0]
    payload = parts[1]

    # Decode the payload (second part of the JWT)
    decoded_header = json.loads(base64_url_decode(header).decode('utf-8'))
    # Decode the payload (second part of the JWT)
    decoded_payload = json.loads(base64_url_decode(payload).decode('utf-8'))

    return decoded_payload, decoded_header


def main(argv):
    global g_cp
    global g_args

    g_args = Config(argv)
    g_cp = ColorPrinter(color=not g_args.args.no_color, indent=0)

    if len(g_args.args.jwk_set_uri) > 7:
        if g_args.args.no_validation:
            g_cp.red("\nNOTE: No JWT validation has been perfomed!\n")
        elif g_args.args.no_validate_exp:
            g_cp.red("\nNOTE: No JWT expiration date validation has been perfomed!\n")
        decoded_token, header_data = validate_and_decode_jwt_with_jwks(g_args.args.token, g_args.args.jwk_set_uri)
    else:
        g_cp.red("\nNOTE: No JWT validation has been perfomed! Missing --jwk-set-uri argument\n")
        decoded_token, header_data = decode_jwt(g_args.args.token)

    if decoded_token:
        pretty_header = json.dumps(header_data, indent=4)
        pretty_body = json.dumps(decoded_token, indent=4)
        g_cp.green("Header:")
        print(pretty_header)
        g_cp.green("Body:")
        print(pretty_body)


class Config:
    def __init__(self, arg_list):
        description = '''
Tool that helps to decode, validate and visualize JWT tokens
    '''
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument('token', help='Base64-encoded JWT token string')
        parser.add_argument('-N', '--no-validation', action='store_true', help='Skip all token validations')
        parser.add_argument('-E', '--no-validate-exp', action='store_true', help='Do not validate expiration time')
        parser.add_argument('-C', '--no-color', action='store_true', help='Print without color')
        parser.add_argument('-s', '--jwk-set-uri', default="", help='JWK Set URI')
        parser.add_argument('--version', action='version',
                            version='%(prog)s v{}'.format(VERSION), help='Print version')

        self.args = parser.parse_args(arg_list[1:])


class ColorPrinter:
    def __init__(self, color=True, indent=4):
        '''indent - number of spaces for a single indentation level, e.g. if you set indent=4 then
         when printed some color with double indent (indent_level=2) the string will have
         8 spaces at the beginning (4 * 2).'''

        self.color = color
        self.indent = []
        for i in range(8):
            self.indent.append(' ' * i * indent)

    def red(self, msg, indent_level=0):
        msg = textwrap.indent("{}".format(msg), self.indent[indent_level])
        if self.color:
            print("\033[91m{}\033[00m".format(msg))
        else:
            print(msg)

    def green(self, msg, indent_level=0):
        msg = textwrap.indent("{}".format(msg), self.indent[indent_level])
        if self.color:
            print("\033[92m{}\033[00m".format(msg))
        else:
            print(msg)

    def yellow(self, msg, indent_level=0):
        msg = textwrap.indent("{}".format(msg), self.indent[indent_level])
        if self.color:
            print("\033[93m{}\033[00m".format(msg))
        else:
            print(msg)

    def lightPurple(self, msg, indent_level=0):
        msg = textwrap.indent("{}".format(msg), self.indent[indent_level])
        if self.color:
            print("\033[94m{}\033[00m".format(msg))
        else:
            print(msg)

    def purple(self, msg, indent_level=0):
        msg = textwrap.indent("{}".format(msg), self.indent[indent_level])
        if self.color:
            print("\033[95m{}\033[00m".format(msg))
        else:
            print(msg)

    def cyan(self, msg, indent_level=0):
        msg = textwrap.indent("{}".format(msg), self.indent[indent_level])
        if self.color:
            print("\033[96m{}\033[00m".format(msg))
        else:
            print(msg)

    def lightGray(self, msg, indent_level=0):
        msg = textwrap.indent("{}".format(msg), self.indent[indent_level])
        if self.color:
            print("\033[97m{}\033[00m".format(msg))
        else:
            print(msg)

    def black(self, msg, indent_level=0):
        msg = textwrap.indent("{}".format(msg), self.indent[indent_level])
        if self.color:
            print("\033[98m{}\033[00m".format(msg))
        else:
            print(msg)


if __name__ == '__main__':
    main(sys.argv)
