import { writeAll } from "https://deno.land/std@0.128.0/streams/conversion.ts#^";
import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "https://deno.land/std@0.128.0/testing/asserts.ts#^";
import {
  AddrType,
  AuthMethod,
  Client,
  ReplyStatus,
  SOCKS_VERSION,
  USERNAME_PASSWORD_AUTH_VERSION,
} from "./client.ts";
import { readN } from "./utils.ts";

const serializedUdpServerAddr = Uint8Array.from([
  AddrType.IPv4,
  127,
  0,
  0,
  1,
  8,
  32,
]);

const ip4Address = {
  hostname: "1.2.3.4",
  port: 1234,
  serialized: Uint8Array.from([AddrType.IPv4, 1, 2, 3, 4, 4, 210]),
};
// hostname=102:304:506:708:90a:b0c:d0e:f10, port=1234
const ip6Address = {
  hostname: "102:304:506:708:90a:b0c:d0e:f10",
  port: 5678,
  // deno-fmt-ignore
  serialized: Uint8Array.from([
    AddrType.IPv6,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    22, 46,
  ]),
};
const domainnameAddress = {
  hostname: "example.com",
  port: 3106,
  serialized: Uint8Array.from([
    AddrType.DomainName,
    "example.com".length,
    ...new TextEncoder().encode("example.com"),
    12,
    34,
  ]),
};

interface MockServerOptions {
  udp?: boolean;
  socksVersion?: number;
  authMethod?: AuthMethod;
  authVersion?: number;
  authFails?: boolean;
  socksVersionReply?: number;
  replyStatus?: ReplyStatus;
  address?: Uint8Array;
  udpAddress?: Uint8Array;
}

interface ReceivedValues {
  socksVersion?: number;
  authMethods?: number[];
  authVersion?: number;
  username?: string;
  password?: string;
  socksVersionRequest?: number;
  command?: number;
  address?: Uint8Array;
  read?: Uint8Array;
}

function addrLength(msg: Uint8Array) {
  if (msg[3] === AddrType.IPv4) {
    return 4;
  }
  if (msg[3] === AddrType.IPv6) {
    return 16;
  }
  return msg[4] + 1;
}

function echoUdp(address: Uint8Array | undefined, values: ReceivedValues) {
  const l = Deno.listenDatagram({ port: 2080, transport: "udp" });

  (async () => {
    try {
      while (true) {
        const [msg, addr] = await l.receive();
        values.read = msg;
        if (address) {
          await l.send(
            Uint8Array.from([
              0,
              0,
              0,
              ...address,
              ...msg.subarray(4 + addrLength(msg)),
            ]),
            addr,
          );
        } else {
          await l.send(msg, addr);
        }
      }
    } catch {
      // ignore
    }
  })();

  return l;
}

function mockServer(opts: MockServerOptions = {}) {
  const server = Deno.listen({ hostname: "127.0.0.1", port: 1080 });
  let conn: Deno.Conn | undefined;
  let udpConn: Deno.DatagramConn | undefined;
  const buff = new Uint8Array(1024);
  const values: ReceivedValues = {};

  if (opts.udp) {
    udpConn = echoUdp(opts.udpAddress, values);
  }

  (async () => {
    let n: number;
    let addrType: number;
    for await (const c of server) {
      conn = c;
      // negotiate auth
      [values.socksVersion, n] = await readN(c, 2);
      values.authMethods = [...(await readN(c, n))];
      await writeAll(
        c,
        Uint8Array.from([
          opts.socksVersion ?? SOCKS_VERSION,
          opts.authMethod ?? AuthMethod.NoAuth,
        ]),
      );
      // auth subnegotiation
      if (opts.authMethod === AuthMethod.UsernamePassword) {
        const td = new TextDecoder();
        [values.authVersion, n] = await readN(c, 2);
        values.username = td.decode(await readN(c, n));
        [n] = await readN(c, 1);
        values.password = td.decode(await readN(c, n));
        await writeAll(
          c,
          Uint8Array.from([
            opts.authVersion ?? USERNAME_PASSWORD_AUTH_VERSION,
            opts.authFails ? ReplyStatus.GeneralError : ReplyStatus.Success,
          ]),
        );
      }

      // handle request
      [values.socksVersionRequest, values.command, , addrType] = await readN(
        c,
        4,
      );
      let addrBytes: Uint8Array;
      if (addrType === AddrType.IPv4) {
        addrBytes = await readN(c, 6);
      } else if (addrType === AddrType.IPv6) {
        addrBytes = await readN(c, 18);
      } else {
        [n] = await readN(c, 1);
        addrBytes = Uint8Array.from([n, ...(await readN(c, n + 2))]);
      }
      values.address = Uint8Array.from([addrType, ...addrBytes]);
      await writeAll(
        c,
        Uint8Array.from([
          opts.socksVersionReply ?? SOCKS_VERSION,
          opts.replyStatus ?? ReplyStatus.Success,
          0,
          ...(opts.address ?? ip4Address.serialized),
        ]),
      );

      while (true) {
        const n = await c.read(buff);
        if (n === null) {
          continue;
        }
        values.read = buff.subarray(0, n);
        await conn.write(values.read);
      }
    }
  })().catch(() => {});

  return {
    values,
    close() {
      conn?.close();
      udpConn?.close();
      server.close();
    },
  };
}

const configNoAuth = {
  hostname: "127.0.0.1",
};
const config = {
  ...configNoAuth,
  username: "name",
  password: "password1234",
};
const connectOptions = {
  port: 1234,
  hostname: "1.2.3.4",
};
const listenOptions = {
  port: 2345,
  hostname: "0.0.0.0",
  transport: "udp",
} as const;

Deno.test("connectAndRequest() - unsupported SOCKS version", async () => {
  const { close } = mockServer({ socksVersion: 4 });
  const client = new Client(config);
  await assertRejects(
    () => client.connect(connectOptions),
    Error,
    "unsupported SOCKS version number: 4",
  );

  close();
});

Deno.test("connectAndRequest() - no authentication", async () => {
  const { values, close } = mockServer();
  const client = new Client(configNoAuth);
  const conn = await client.connect(connectOptions);
  assertEquals(values.authMethods, [AuthMethod.NoAuth]);

  conn.close();
  close();
});

Deno.test(
  "connectAndRequest() - username/password authentication",
  async () => {
    const { values, close } = mockServer({
      authMethod: AuthMethod.UsernamePassword,
    });
    const client = new Client(config);
    const conn = await client.connect(connectOptions);
    assertEquals(values.authMethods, [
      AuthMethod.NoAuth,
      AuthMethod.UsernamePassword,
    ]);
    assertEquals(values.authVersion, 1);
    assertEquals(values.username, "name");
    assertEquals(values.password, "password1234");

    conn.close();
    close();
  },
);

Deno.test("connectAndRequest() - no acceptable authentication", async () => {
  const { close } = mockServer({
    authMethod: AuthMethod.NoneAcceptable,
  });
  const client = new Client(config);
  await assertRejects(
    () => client.connect(connectOptions),
    Error,
    "no acceptable authentication methods",
  );

  close();
});

Deno.test(
  "connectAndRequest() - unsupported authentication version",
  async () => {
    const { close } = mockServer({
      authMethod: AuthMethod.UsernamePassword,
      authVersion: 2,
    });
    const client = new Client(config);
    await assertRejects(
      () => client.connect(connectOptions),
      Error,
      "unsupported authentication version number: 2",
    );

    close();
  },
);

Deno.test("connectAndRequest() - authentication failed", async () => {
  const { close } = mockServer({
    authMethod: AuthMethod.UsernamePassword,
    authFails: true,
  });
  const client = new Client(config);
  await assertRejects(
    () => client.connect(connectOptions),
    Error,
    "authentication failed",
  );

  close();
});

Deno.test("connectAndRequest() - IPv4 target address", async () => {
  const { values, close } = mockServer();
  const client = new Client(config);
  const conn = await client.connect({
    port: ip4Address.port,
    hostname: ip4Address.hostname,
  });

  assertEquals(values.address, ip4Address.serialized);
  conn.close();
  close();
});

Deno.test("connectAndRequest() - IPv6 target address", async () => {
  const { values, close } = mockServer();
  const client = new Client(config);
  const conn = await client.connect({
    port: ip6Address.port,
    hostname: ip6Address.hostname,
  });

  assertEquals(values.address, ip6Address.serialized);
  conn.close();
  close();
});

Deno.test("connectAndRequest() - domain name target address", async () => {
  const { values, close } = mockServer();
  const client = new Client(config);
  const conn = await client.connect({
    port: domainnameAddress.port,
    hostname: domainnameAddress.hostname,
  });

  assertEquals(values.address, domainnameAddress.serialized);
  conn.close();
  close();
});

Deno.test(
  "connectAndRequest() - unsupported SOCKS version (request)",
  async () => {
    const { close } = mockServer({
      socksVersionReply: 4,
    });
    const client = new Client(config);
    await assertRejects(
      () => client.connect(connectOptions),
      Error,
      "unsupported SOCKS version number: 4",
    );

    close();
  },
);

Deno.test("connectAndRequest() - request failed", async (t) => {
  const cases = [
    [ReplyStatus.GeneralError, "general SOCKS server failure"],
    [ReplyStatus.RulesetError, "connection not allowed by ruleset"],
    [ReplyStatus.NetworkUnreachable, "Network unreachable"],
    [ReplyStatus.HostUnreachable, "Host unreachable"],
    [ReplyStatus.ConnectionRefused, "Connection refused"],
    [ReplyStatus.TTLExpired, "TTL expired"],
    [ReplyStatus.UnsupportedCommand, "Command not supported"],
    [ReplyStatus.UnsupportedAddress, "Address type not supported"],
    [255 as ReplyStatus, "unknown SOCKS error"],
  ] as const;

  for (const [replyStatus, errText] of cases) {
    await t.step(`handles ${errText}`, async () => {
      const { close } = mockServer({
        replyStatus,
      });
      const client = new Client(config);
      await assertRejects(() => client.connect(connectOptions), Error, errText);

      close();
    });
  }
});

Deno.test("connect() - localAddr and remoteAddr are correct", async () => {
  const { values, close } = mockServer({
    // 127.0.0.1:1080
    address: Uint8Array.from([AddrType.IPv4, 127, 0, 0, 1, 4, 56]),
  });
  const proxy = {
    hostname: "127.0.0.1",
    port: 1080,
  };
  const remote = {
    hostname: "1.2.3.4",
    port: 5678,
  };
  const client = new Client(proxy);
  const conn = await client.connect(remote);

  assertEquals(conn.localAddr, {
    ...proxy,
    transport: "tcp",
  });
  assertEquals(conn.remoteAddr, {
    ...remote,
    transport: "tcp",
  });

  conn.close();
  close();
});

Deno.test("connect() - can read", async () => {
  const { values, close } = mockServer();
  const client = new Client(config);
  const conn = await client.connect(connectOptions);

  const msg = crypto.getRandomValues(new Uint8Array(100));
  await conn.write(msg);
  const reply = new Uint8Array(4);
  await conn.read(reply);
  assertEquals(reply, msg.subarray(0, 4));
  const reply2 = await conn.readable.getReader().read();
  assertEquals(reply2.value, msg.subarray(4));

  conn.close();
  close();
});

Deno.test("connect() - can write", async () => {
  const { values, close } = mockServer();
  const client = new Client(config);
  const conn = await client.connect(connectOptions);

  const msg = crypto.getRandomValues(new Uint8Array(10));
  await conn.write(msg);
  // yield to mock server
  await Promise.resolve();
  assertEquals(values.read, msg);

  await conn.read(new Uint8Array(10));
  crypto.getRandomValues(msg);
  await conn.writable.getWriter().write(msg);
  // yield to mock server
  await Promise.resolve();
  assertEquals(values.read, msg);

  conn.close();
  close();
});

Deno.test("connect() - can close", async () => {
  const { values, close } = mockServer();
  const client = new Client(config);
  const conn = await client.connect(connectOptions);

  await conn.write(new Uint8Array(10));
  conn.closeWrite();
  await assertRejects(() => conn.write(new Uint8Array(2)));
  await conn.read(new Uint8Array(2));
  conn.close();
  await assertRejects(() => conn.read(new Uint8Array(2)));

  close();
});

Deno.test("listenDatagram() - addr is correct", async () => {
  const { values, close } = mockServer({
    // 127.0.0.1:9876
    address: Uint8Array.from([AddrType.IPv4, 127, 0, 0, 1, 38, 148]),
  });
  const client = new Client(config);
  const conn = client.listenDatagram(listenOptions);
  assertEquals(conn.addr, listenOptions);
  await conn.isReady;
  assertEquals(conn.addr, {
    hostname: "127.0.0.1",
    port: 9876,
    transport: "udp",
  });

  conn.close();
  close();
});

Deno.test("listenDatagram() - UDP closed if negotiation fails", async () => {
  const { values, close } = mockServer({
    socksVersion: 4,
  });
  const client = new Client(config);
  const conn = client.listenDatagram(listenOptions);
  await assertRejects(() => conn.isReady);
  assertThrows(() => conn.close(), Error, "Bad resource ID");

  close();
});

Deno.test(
  "listenDatagram() - UDP closed when TCP connection closes",
  async () => {
    const { close } = mockServer();
    const client = new Client(config);
    const conn = client.listenDatagram(listenOptions);
    await conn.isReady;
    close();
    // give some time for TCP connection closing to be detected
    await new Promise((r) => setTimeout(r, 200));
    assertThrows(() => conn.close(), Error, "Bad resource ID");
  },
);

Deno.test("listenDatagram() - send() encodes header correctly", async () => {
  const { values, close } = mockServer({
    udp: true,
    address: serializedUdpServerAddr,
  });
  const client = new Client(config);
  const conn = client.listenDatagram(listenOptions);

  const remote = {
    hostname: ip6Address.hostname,
    port: ip6Address.port,
    transport: "udp",
  } as const;
  const msg = crypto.getRandomValues(new Uint8Array(10));
  await conn.send(msg, remote);
  await conn.receive();
  assertEquals(
    values.read,
    Uint8Array.from([0, 0, 0, ...ip6Address.serialized, ...msg]),
  );

  conn.close();
  close();
});

// FIXME: unskip these when bug in Deno is fixed https://github.com/denoland/deno/issues/13729
// Deno.test("listenDatagram() - receive() ignores datagrams with non-zero reserved bytes", async () => {
//   const server = mockServer();
//   let udpServer: Deno.DatagramConn;
//   let buff: Uint8Array;
//   (async () => {
//     const addr = {
//       ...listenOptions,
//       hostname: "127.0.0.1",
//     };
//     udpServer = Deno.listenDatagram({ port: 2080, transport: "udp" });
//     // reserve bytes are 01
//     const nonZeroReserve = new Uint8Array(12);
//     nonZeroReserve[1] = 1;
//     await udpServer.send(nonZeroReserve, addr);
//     buff = crypto.getRandomValues(new Uint8Array(8));
//     // reserve bytes are 00
//     udpServer.send(
//       Uint8Array.from([0, 0, 0, ...ip4Address.serialized, ...buff]),
//       addr,
//     );
//   })();

//   const client = new Client(config);
//   const conn = client.listenDatagram(listenOptions);
//   const recv = await conn.receive();
//   assertEquals(recv[0], buff!);
//   assertEquals(recv[1], {
//     hostname: ip4Address.hostname,
//     port: ip4Address.port,
//     transport: "udp",
//   });

//   udpServer!.close();
//   server.close();
// });

// Deno.test("listenDatagram() - receive() ignores datagrams with non-zero fragment", async () => {
//   const server = mockServer();
//   let udpServer: Deno.DatagramConn;
//   let buff: Uint8Array;
//   (async () => {
//     const addr = {
//       ...listenOptions,
//       hostname: "127.0.0.1",
//     };
//     udpServer = Deno.listenDatagram({ port: 2080, transport: "udp" });
//     // fragment byte is 1
//     const nonZeroReserve = new Uint8Array(12);
//     nonZeroReserve[2] = 1;
//     await udpServer.send(nonZeroReserve, addr);
//     buff = crypto.getRandomValues(new Uint8Array(8));
//     // fragment byte is 0
//     udpServer.send(
//       Uint8Array.from([0, 0, 0, ...ip4Address.serialized, ...buff]),
//       addr,
//     );
//   })();

//   const client = new Client(config);
//   const conn = client.listenDatagram(listenOptions);
//   const recv = await conn.receive();
//   assertEquals(recv[0], buff!);
//   assertEquals(recv[1], {
//     hostname: ip4Address.hostname,
//     port: ip4Address.port,
//     transport: "udp",
//   });

//   conn.close();
//   udpServer!.close();
//   server.close();
// });

Deno.test("listenDatagram() - receive() decodes header correctly", async () => {
  const server = mockServer({
    udp: true,
    address: serializedUdpServerAddr,
    udpAddress: domainnameAddress.serialized,
  });

  const client = new Client(config);
  const conn = client.listenDatagram(listenOptions);
  await conn.send(new Uint8Array(4), {
    hostname: ip6Address.hostname,
    port: ip6Address.port,
    transport: "udp",
  });
  const [, receivedAddress] = await conn.receive();
  assertEquals(receivedAddress, {
    hostname: domainnameAddress.hostname,
    port: domainnameAddress.port,
    transport: "udp",
  });

  conn.close();
  server.close();
});
