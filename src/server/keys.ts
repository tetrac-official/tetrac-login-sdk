// Single source of truth for the app-scoped Redis keyspace (multi-app isolation,
// v0.4.0). Every per-user key carries the resolved appId as a namespace segment so
// that two apps sharing one Redis/Upstash database can never read or overwrite each
// other's records. The appId is validated to exclude ':' (the separator) BEFORE it
// reaches here, so a crafted appId can't escape its namespace.
//
//   appScoped("pubKey:", "myapp", "<publicKey>")  ->  "pubKey:myapp:<publicKey>"
//
// The email index is the deliberate exception: its key is the bare `email:{address}`
// and the appId lives as a HASH FIELD whose value is that app's public key — the
// `{ appId: publicKey }` map that lets one email span multiple apps.
export function appScoped(prefix: string, appId: string, id: string): string {
  return `${prefix}${appId}:${id}`;
}
