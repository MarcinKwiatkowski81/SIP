Copyright (c) 2026, Marcin Kwiatkowski <marcin@kwiatkowski.info.pl>
All rights reserved.


# SIP/RTP Stack API

This documentation is generated from source using Doxygen.

## Modules

- SIP protocol parsing and messaging
- SIP transactions and dialogs
- RTP media sessions and codec interfaces
- Stateful SIP server/proxy/B2BUA
- Sample PBX application

## Key Public API Entry Points

- include/SipStack.h: SIP user-agent stack API
- include/SipServer.h: SIP server/registrar/proxy/B2BUA API
- include/Rtp.h: RTP session API
- include/Codec.h: codec interfaces and registry
- include/SipMessage.h: SIP message model and parser

## Build Docs

Enable and build docs target:

```bash
cmake -S . -B build -DSIP_BUILD_DOCS=ON
cmake --build build --target docs
```

Generated HTML output:

- build/docs/html/index.html
