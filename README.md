# murmur-auth-pam

PAM authenticator for grpc-enabled [Mumble](http://mumble.info/) servers.

## Configuration

Configuration for the authenticator is stored in `/etc/pam.d/murmur-auth-pam`. The following example configuration authenticates against local accounts:

    auth      required   pam_unix.so nodelay
    account   required   pam_unix.so

## Known limitations

Information about the user must be accessible via `getpwnam` and `getpwuid`.

## License

BSD-3
