import { writeAll } from "https://deno.land/std@0.128.0/streams/conversion.ts#^";

async function readN(
  reader: Deno.Reader,
  n: number,
  arr?: Uint8Array
): Promise<Uint8Array> {
  const out = arr ?? new Uint8Array(n);
  let nRead = 0;
  while (nRead < n) {
    const m = await reader.read(out.subarray(nRead));
    if (m === null) {
      throw new Deno.errors.UnexpectedEof(
        `reached EOF but we expected to read ${n - nRead} more bytes`
      );
    }
    nRead += m;
  }
  return out;
}

const SOCKS_VERSION = 5;
const USERNAME_PASSWORD_AUTH_VERSION = 1;
enum AddrType {
  IPv4 = 1,
  DomainName = 3,
  IPv6 = 4,
}
enum AuthMethod {
  NoAuth = 0,
  UsernamePassword = 2,
  NoneAcceptable = 0xff,
}
enum ReplyStatus {
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
enum Command {
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

const v4Pattern = /^(?:\d{1,3}.){3}\d{1,3}/;
const v6Pattern = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;
function serializeHostname(hostname: string) {
  if (v4Pattern.test(hostname)) {
    return Uint8Array.from([AddrType.IPv4, ...hostname.split(".").map(Number)]);
  }
  if (v6Pattern.test(hostname)) {
    return Uint8Array.from([
      AddrType.IPv6,
      ...hostname.split(":").flatMap((x) => {
        const num = parseInt(x, 16);
        return [num >> 8, num % 256];
      }),
    ]);
  }

  const bytes = new TextEncoder().encode(hostname);
  return Uint8Array.from([AddrType.DomainName, bytes.length, ...bytes]);
}

async function deserializeHostname(conn: Deno.Conn) {
  const [type] = await readN(conn, 1);
  if (type === AddrType.IPv4) {
    const parts = [...(await readN(conn, 4))];
    return parts.map(String).join(".");
  }
  if (type === AddrType.IPv6) {
    const parts = [...(await readN(conn, 16))];
    return parts.map(String).join(":");
  }
  if (type === AddrType.DomainName) {
    const [length] = await readN(conn, 1);
    return new TextDecoder().decode(await readN(conn, length));
  }

  throw new Error(`unexpected address type: ${type}`);
}

interface AddrConfig {
  hostname: string;
  port?: number;
}

interface AuthConfig {
  username: string;
  password: string;
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

  #connectAndNegotiateAuth = async () => {
    const conn = await Deno.connect({
      hostname: this.#config.hostname,
      port: this.#config.port,
    });

    const methods = [AuthMethod.NoAuth];
    if ("username" in this.#config) {
      methods.push(AuthMethod.UsernamePassword);
    }
    await writeAll(
      conn,
      Uint8Array.from([SOCKS_VERSION, methods.length, ...methods])
    );
    const [version, method] = await readN(conn, 2);
    if (version !== SOCKS_VERSION || method === AuthMethod.NoneAcceptable) {
      try {
        conn.close();
      } catch {}
      throw new Error(
        version !== SOCKS_VERSION
          ? `unsupported SOCKS version number: ${version}`
          : "no acceptable authentication methods"
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
        ])
      );
      const [authVersion, status] = await readN(conn, 2);
      if (
        authVersion !== USERNAME_PASSWORD_AUTH_VERSION ||
        status !== ReplyStatus.Success
      ) {
        try {
          conn.close();
        } catch {}
        throw new Error(
          authVersion !== USERNAME_PASSWORD_AUTH_VERSION
            ? `unsupported authentication version number: ${authVersion}`
            : "authentication failed"
        );
      }
    }

    return conn;
  };

  async connect(opts: Deno.ConnectOptions): Promise<Deno.Conn> {
    const remoteAddr = {
      hostname: opts.hostname ?? "127.0.0.1",
      port: opts.port,
      transport: "tcp",
    } as const;
    const conn = await this.#connectAndNegotiateAuth();
    const hostnameBuff = serializeHostname(remoteAddr.hostname);
    await writeAll(
      conn,
      Uint8Array.from([
        SOCKS_VERSION,
        Command.Connect,
        0,
        ...hostnameBuff,
        opts.port >> 8,
        opts.port % 256,
      ])
    );
    const [version, status, _] = await readN(conn, 3);
    if (version !== SOCKS_VERSION || status !== ReplyStatus.Success) {
      try {
        conn.close();
      } catch {}
      throw new Error(
        version !== SOCKS_VERSION
          ? `unsupported SOCKS version number: ${version}`
          : decodeError(status)
      );
    }

    const hostname = await deserializeHostname(conn);
    const [portUpper, portLower] = await readN(conn, 2);
    const port = (portUpper << 8) + portLower;
    const localAddr = {
      hostname,
      port,
      transport: "tcp",
    } as const;

    return {
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
}
