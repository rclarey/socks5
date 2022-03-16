# A SOCKS5 proxy library for Deno

<a href="https://github.com/rclarey/socks5/actions">
  <img src="https://img.shields.io/github/workflow/status/rclarey/socks5/CI" alt="GitHub Workflow Status" />
</a>
<a href="https://github.com/rclarey/socks5/releases">
  <img src="https://img.shields.io/github/v/release/rclarey/socks5" alt="GitHub release (latest by date)" />
</a>
<a href="https://doc.deno.land/https/raw.githubusercontent.com/rclarey/socks5/main/client.ts">
  <img src="https://doc.deno.land/badge.svg" alt="Documentation" />
</a>
<a href="https://deno-visualizer.danopia.net/dependencies-of/https/raw.githubusercontent.com/rclarey/socks5/main/client.ts">
  <img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fdeno-visualizer.danopia.net%2Fshields%2Fdep-count%2Fhttps%2Fraw.githubusercontent.com%2Frclarey%2Fsocks5%2Fmain%2Fclient.ts" alt="Dependencies" />
</a>
<a href="https://github.com/rclarey/socks5/blob/main/LICENSE">
  <img src="https://img.shields.io/github/license/rclarey/socks5" alt="MIT License" />
</a>

## Features
- Supported commands
  - ✅ CONNECT
  - ❌ BIND
  - ✅ UDP ASSOCIATE
  
- Supported authentication methods
  - No authentication
  - Username & password

## Usage
```typescript
import { Client } from "https://deno.land/x/socks5/client.ts"

const config = {
  // hostname of the proxy server
  hostname: "my-proxy-server.example",
  // optional, port of the proxy server. defaults to 1080
  port: 1234,
  // optional, username and password to authenticate. not required if
  // the server supports using no authentication
  username: "my_name",
  password: "my_password",
};
const client = new Client(config);

// now you can replace
Deno.connect(connectOpts);
// with
client.connect(connectOpts);

// and you can replace
Deno.listenDatagram(listenOpts);
// with
client.listenDatagram(listenOpts);
