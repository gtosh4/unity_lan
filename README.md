# Unit LAN
A peer-to-peer LAN driven by Discord roles / voice channels using Wireguard.

## Discord Bot
Application ID: 905550991955460126


## Credential Store
### Linux
```sh
gpg --full-generate-key
# Fill out info

gpg --list-keys
# ID is the line after 'pub'

pass init <gpg key id>

# optional:
pass git init
```
