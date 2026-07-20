Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
All rights reserved.


# Linphone quick setup (desktop/mobile)

Use one SIP account per endpoint.

## Transport and identity

- Username: `100` (or any provisioned user)
- Password: `pass_100`
- Domain/Server: `pbx.local` (or your PBX IP/domain)
- SIP Proxy/Outbound proxy: `sip:pbx.local:5060;transport=udp`
- Display name: optional

## Network

- Transport: UDP (TCP also works if enabled in sample_pbx)
- Register: enabled
- Expiration: 300 to 600 seconds

## Audio codecs

To validate transcoding, set different codec priorities across two endpoints.

Example endpoint A order:
1. PCMU (G.711u)
2. PCMA (G.711a)

Example endpoint B order:
1. PCMA (G.711a)
2. PCMU (G.711u)

If you loaded extra plugins with `-g`, you can prefer those codecs on one side.

## Dialing

Dial by username:
- `101`
- `sip:101@pbx.local`
