import { writeAll } from "https://deno.land/std@0.128.0/streams/conversion.ts#^";
import { readN, uint8ArrayToReader } from "./utils.ts";

export const SOCKS_VERSION = 5;
export const USERNAME_PASSWORD_AUTH_VERSION = 1;
export enum AddrType {
  IPv4 = 1,
  DomainName = 3,
  IPv6 = 4,
}
export enum AuthMethod {
  NoAuth = 0,
  UsernamePassword = 2,
  NoneAcceptable = 0xff,
}
export enum ReplyStatus {
  Success = 0,
  GeneralError,
  RulesetError,
  NetworkUnreachable,
  HostUnreachable,
  ConnectionRefused,
  TTLExpired,
  UnsupportedCommand,
  UnsupportedAddress,
}
export enum Command {
  Connect = 1,
  Bind,
  UdpAssociate,
}

function decodeError(status: number) {
  switch (status) {
    case ReplyStatus.GeneralError:
      return "general SOCKS server failure";
    case ReplyStatus.RulesetError:
      return "connection not allowed by ruleset";
    case ReplyStatus.NetworkUnreachable:
      return "Network unreachable";
    case ReplyStatus.HostUnreachable:
      return "Host unreachable";
    case ReplyStatus.ConnectionRefused:
      return "Connection refused";
    case ReplyStatus.TTLExpired:
      return "TTL expired";
    case ReplyStatus.UnsupportedCommand:
      return "Command not supported";
    case ReplyStatus.UnsupportedAddress:
      return "Address type not supported";
    default:
      return "unknown SOCKS error";
  }
}

const v4Pattern = /^(?:\d{1,3}\.){3}\d{1,3}/;
const v6Pattern = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;
function serializeAddress(hostname: string, port: number) {
  const portBytes = [port >> 8, port % 256];
  if (v4Pattern.test(hostname)) {
    return Uint8Array.from([
      AddrType.IPv4,
      ...hostname.split(".").map(Number),
      ...portBytes,
    ]);
  }
  if (v6Pattern.test(hostname)) {
    return Uint8Array.from([
      AddrType.IPv6,
      ...hostname.split(":").flatMap((x) => {
        const num = parseInt(x, 16);
        return [num >> 8, num % 256];
      }),
      ...portBytes,
    ]);
  }

  const bytes = new TextEncoder().encode(hostname);
  return Uint8Array.from([
    AddrType.DomainName,
    bytes.length,
    ...bytes,
    ...portBytes,
  ]);
}

async function deserializeAddress(r: Deno.Reader) {
  const [type] = await readN(r, 1);
  const hostname = await (async () => {
    if (type === AddrType.IPv4) {
      const parts = [...(await readN(r, 4))];
      return { value: parts.map(String).join("."), length: 4 };
    }
    if (type === AddrType.IPv6) {
      const parts = [];
      const buff = await readN(r, 16);
      for (let i = 0; i < buff.length; i += 2) {
        parts.push((buff[i] << 8) + buff[i + 1]);
      }
      return { value: parts.map(String).join(":"), length: 16 };
    }
    if (type === AddrType.DomainName) {
      const [length] = await readN(r, 1);
      return {
        value: new TextDecoder().decode(await readN(r, length)),
        length: length + 1,
      };
    }

    throw new Error(`unexpected address type: ${type}`);
  })();

  const [portUpper, portLower] = await readN(r, 2);
  const port = (portUpper << 8) + portLower;
  return { hostname: hostname.value, port, bytesRead: hostname.length + 3 };
}

interface AddrConfig {
  hostname: string;
  port?: number;
}

interface AuthConfig {
  username: string;
  password: string;
}

interface UdpProxyInfo {
  tcpConn: Deno.Conn;
  addr: { hostname: string; port: number; transport: "udp" };
}

export type ClientConfig = AddrConfig | (AddrConfig & AuthConfig);

export class Client {
  #config: Required<ClientConfig>;

  constructor(config: ClientConfig) {
    this.#config = {
      ...config,
      port: config.port ?? 1080,
    };
  }

  #connectAndRequest = async (cmd: Command, hostname: string, port: number) => {
    const conn = await Deno.connect({
      hostname: this.#config.hostname,
      port: this.#config.port,
    });

    // handle auth negotiation
    const methods = [AuthMethod.NoAuth];
    if ("username" in this.#config) {
      methods.push(AuthMethod.UsernamePassword);
    }
    await writeAll(
      conn,
      Uint8Array.from([SOCKS_VERSION, methods.length, ...methods]),
    );
    const [negotiationVersion, method] = await readN(conn, 2);
    if (
      negotiationVersion !== SOCKS_VERSION ||
      method === AuthMethod.NoneAcceptable
    ) {
      try {
        conn.close();
      } catch {
        // ignore
      }
      throw new Error(
        negotiationVersion !== SOCKS_VERSION
          ? `unsupported SOCKS version number: ${negotiationVersion}`
          : "no acceptable authentication methods",
      );
    }

    if (method === AuthMethod.UsernamePassword) {
      const cfg = this.#config as AddrConfig & AuthConfig;
      const te = new TextEncoder();
      const username = te.encode(cfg.username);
      const password = te.encode(cfg.password);
      await writeAll(
        conn,
        Uint8Array.from([
          USERNAME_PASSWORD_AUTH_VERSION,
          username.length,
          ...username,
          password.length,
          ...password,
        ]),
      );
      const [authVersion, status] = await readN(conn, 2);
      if (
        authVersion !== USERNAME_PASSWORD_AUTH_VERSION ||
        status !== ReplyStatus.Success
      ) {
        try {
          conn.close();
        } catch {
          // ignore
        }
        throw new Error(
          authVersion !== USERNAME_PASSWORD_AUTH_VERSION
            ? `unsupported authentication version number: ${authVersion}`
            : "authentication failed",
        );
      }
    }

    // handle actual message
    await writeAll(
      conn,
      Uint8Array.from([
        SOCKS_VERSION,
        cmd,
        0,
        ...serializeAddress(hostname, port),
      ]),
    );
    const [replyVersion, status, _] = await readN(conn, 3);
    if (replyVersion !== SOCKS_VERSION || status !== ReplyStatus.Success) {
      try {
        conn.close();
      } catch {
        // ignore
      }
      throw new Error(
        replyVersion !== SOCKS_VERSION
          ? `unsupported SOCKS version number: ${replyVersion}`
          : decodeError(status),
      );
    }

    return {
      conn,
      ...(await deserializeAddress(conn)),
    };
  };

  async connect(opts: Deno.ConnectOptions): Promise<Deno.TcpConn> {
    const remoteAddr = {
      hostname: opts.hostname ?? "127.0.0.1",
      port: opts.port,
      transport: "tcp",
    } as const;
    const { conn, hostname, port } = await this.#connectAndRequest(
      Command.Connect,
      remoteAddr.hostname,
      remoteAddr.port,
    );
    const localAddr = {
      hostname,
      port,
      transport: "tcp",
    } as const;

    return {
      setKeepAlive(keepalive?: boolean) {
        conn.setKeepAlive(keepalive);
      },
      setNoDelay(nodelay?: boolean) {
        conn.setNoDelay(nodelay);
      },
      get localAddr() {
        return localAddr;
      },
      get remoteAddr() {
        return remoteAddr;
      },
      get rid() {
        return conn.rid;
      },
      get readable() {
        return conn.readable;
      },
      get writable() {
        return conn.writable;
      },
      read: conn.read.bind(conn),
      write: conn.write.bind(conn),
      close: conn.close.bind(conn),
      closeWrite: conn.closeWrite.bind(conn),
    };
  }

  listenDatagram(
    opts: Deno.ListenOptions & { transport: "udp" },
  ): Deno.DatagramConn & { readonly isReady: Promise<void> } {
    const udpConn = Deno.listenDatagram(opts);
    let proxyInfo: null | UdpProxyInfo = null;

    const close = (throwErr = false) => {
      let err: unknown;
      try {
        proxyInfo?.tcpConn.close();
      } catch (e) {
        err = e;
      }
      try {
        udpConn.close();
      } catch (e) {
        err = e;
      }
      if (err && throwErr) {
        throw err;
      }
    };

    const isReady = (async () => {
      try {
        const localAddr = udpConn.addr as Deno.NetAddr;
        const { conn, hostname, port } = await this.#connectAndRequest(
          Command.UdpAssociate,
          localAddr.hostname,
          localAddr.port,
        );
        proxyInfo = {
          tcpConn: conn,
          addr: {
            hostname,
            port,
            transport: "udp",
          },
        };
        // close UDP connection when TCP connection closes
        (async () => {
          const buff = new Uint8Array(1024);
          while (true) {
            const val = await conn.read(buff).catch(() => null);
            if (val === null) {
              break;
            }
          }
          close();
        })();
      } catch (e) {
        close();
        throw e;
      }
    })();

    return {
      get isReady() {
        return isReady;
      },
      get addr() {
        return proxyInfo ? proxyInfo.addr : udpConn.addr;
      },
      async send(p: Uint8Array, addr: Deno.Addr) {
        if (!proxyInfo) {
          await isReady;
        }

        const netAddr = addr as Deno.NetAddr;
        const serializedAddress = serializeAddress(
          netAddr.hostname,
          netAddr.port,
        );
        const msg = new Uint8Array(3 + serializedAddress.length + p.length);
        msg.set(serializedAddress, 3);
        msg.set(p, 3 + serializedAddress.length);
        return udpConn.send(msg, proxyInfo!.addr);
      },
      async receive(p?: Uint8Array): Promise<[Uint8Array, Deno.Addr]> {
        if (!proxyInfo) {
          await isReady;
        }

        const buff = new Uint8Array(p ? p.length + 1024 : 2048);
        const [res] = await udpConn.receive(buff);
        // if first two reserved bytes are not zero, or the fragment value is
        // not zero, then ignore the datagram
        if (res[0] || res[1] || res[2]) {
          return this.receive(p);
        }

        const { hostname, port, bytesRead } = await deserializeAddress(
          uint8ArrayToReader(res.subarray(3)),
        );
        return [
          res.subarray(3 + bytesRead),
          { hostname, port, transport: "udp" },
        ];
      },
      close() {
        close(true);
      },
      [Symbol.asyncIterator]: udpConn[Symbol.asyncIterator],
    };
  }
}
