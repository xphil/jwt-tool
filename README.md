# jwt-tool
Super simple tool that can decode, validate and visualize JWT tokens. Verification through JWKS.

# Usage
### Print help

```
$ ./jwt-tool.py -h
```

### Decode JWT token without validation

```bash
$ ./jwt-tool.py <base64-encoded JWT token string>
```

### Decode JWT token with validation through JWKS

```bash
$ ./jwt-tool.py --jwk-set-uri <JWKs URI> <base64-encoded JWT token string>
```

### Verify signature, but disable expiration date validation

```bash
$ ./jwt-tool.py --jwk-set-uri <JWKs URI> --no-validate-exp <base64-encoded JWT token string>
```

### Temporarily disable verification
Usually used when you don't want to remove --jwk-set-uri from command line, but want to temporarily
disable verification

Just use --no-verification or -N option.

```bash
$ ./jwt-tool.py -N --jwk-set-uri <JWKs URI> <base64-encoded JWT token string>

OR

$ ./jwt-tool.py --no-verification --jwk-set-uri <JWKs URI> <base64-encoded JWT token string>
```

# License
See LICENSE file.
