Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
All rights reserved.


# Zoiper quick setup

Use one SIP account per endpoint.

## Account fields

- Username / User: `101` (or any provisioned user)
- Password: `pass_101`
- Domain / Host: `pbx.local` (or PBX IP)
- Port: `5060`
- Transport: `UDP` (or TCP when enabled)

## Optional advanced fields

- Outbound proxy: `pbx.local:5060`
- Auth username: same as username
- Keep-alive: enabled

## Codec testing profile

For mixed-codec test, set endpoint priorities differently:

Endpoint 1 preferred codecs:
1. PCMU
2. PCMA

Endpoint 2 preferred codecs:
1. PCMA
2. PCMU

Then call from one extension to another and check PBX logs for codec bridge information.

## Dialing

- `100`
- `sip:100@pbx.local`
