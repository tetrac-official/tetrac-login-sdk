// Next.js App Router binding. Wire up a single catch-all route:
//
//   // app/api/auth/[...action]/route.ts
//   import { createNextAuthRoutes } from "@tetrac/login-sdk/next";
//   import { resolveStorageAdapter } from "@tetrac/login-sdk/storage";
//   const storage = await resolveStorageAdapter();
//   export const { GET, POST } = createNextAuthRoutes({ storage, config: { origin: "https://app.example" } });
//
import { createAuthHandlers, type AuthHandlerOptions, type AuthHandlers } from "../server/routes.js";
import { error } from "../server/http.js";

/** A bound route handler over the Web Request/Response API. */
export type AuthRouteHandler = (req: Request) => Promise<Response>;

/** POST actions the catch-all serves. */
export const AUTH_POST_ACTIONS = [
  "challenge",
  "register",
  "login",
  "login-wallet",
  "connect-wallet",
  "import-wallet",
  "logout",
] as const;
export type AuthPostAction = (typeof AUTH_POST_ACTIONS)[number];

/** GET actions the catch-all serves. */
export const AUTH_GET_ACTIONS = ["user-data", "search-wallet"] as const;
export type AuthGetAction = (typeof AUTH_GET_ACTIONS)[number];

/**
 * Status returned when the catch-all resolves no action.
 *
 * Defaults to **400**, not 404. The route handler exists and was reached; it is the
 * `action` segment that names nothing — a malformed request parameter, i.e. a client
 * error, which is how every other validation failure here already answers. A 404 asserts
 * the endpoint is absent, which is untrue, and in a web context reads as "page not found",
 * so monitoring and users both draw the wrong conclusion.
 *
 * 405 is about the METHOD versus a resource, not an unknown sub-resource. 501 is a 5xx and
 * would page someone for a mistake the caller made.
 */
export type UnknownActionStatus = 400 | 404 | 422 | 501;

export interface NextAuthRoutesOptions extends AuthHandlerOptions {
  /** Status for an unrecognised action segment. Default 400. */
  unknownActionStatus?: UnknownActionStatus;
}

export interface NextAuthRoutes {
  GET: (req: Request, ctx: RouteContext) => Promise<Response>;
  POST: (req: Request, ctx: RouteContext) => Promise<Response>;
  /** The underlying framework-agnostic handlers, for wrapping or direct use. */
  handlers: AuthHandlers;
}

// Next passes params as a Promise (15+) or plain object (≤14); support both.
export type RouteContext = {
  params: { action?: string[] } | Promise<{ action?: string[] }>;
};

// Next passes the catch-all segments in ctx.params.action; join them back into the
// action string ("login", "login-wallet", …).
async function actionOf(ctx: RouteContext): Promise<string> {
  const params = await ctx.params;
  return (params.action ?? []).join("/");
}

export function createNextAuthRoutes(opts: NextAuthRoutesOptions): NextAuthRoutes {
  const handlers = createAuthHandlers(opts);
  const unknownStatus: UnknownActionStatus = opts.unknownActionStatus ?? 400;

  // A Map, NOT an object literal.
  //
  // Indexing an object literal walks Object.prototype, so `postRoutes["constructor"]` used
  // to resolve to the Object constructor — truthy — and got CALLED as a handler. The route
  // then returned a non-Response (or threw a raw TypeError for `valueOf`/`hasOwnProperty`),
  // turning an unauthenticated request into a framework 500 with a stack instead of a clean
  // rejection. No real handler was ever reachable that way, but the noise looked like one.
  //
  // `Map.get` resolves own entries only, so the whole class is gone rather than guarded.
  // The `satisfies` below makes the table EXHAUSTIVE: adding an action to the union without
  // binding a handler (or vice versa) is a compile error, not a 400 discovered in staging.
  const postRoutes = new Map<string, AuthRouteHandler>(
    Object.entries({
      challenge: handlers.challenge,
      register: handlers.register,
      login: handlers.login,
      "login-wallet": handlers.loginWallet,
      "connect-wallet": handlers.connectWallet,
      "import-wallet": handlers.importWallet,
      logout: handlers.logout,
    } satisfies Record<AuthPostAction, AuthRouteHandler>),
  );

  const getRoutes = new Map<string, AuthRouteHandler>(
    Object.entries({
      "user-data": handlers.userData,
      "search-wallet": handlers.searchWallet,
    } satisfies Record<AuthGetAction, AuthRouteHandler>),
  );

  function dispatch(
    table: Map<string, AuthRouteHandler>,
    known: readonly string[],
  ): (req: Request, ctx: RouteContext) => Promise<Response> {
    return async (req, ctx) => {
      const action = await actionOf(ctx);
      const handler = table.get(action);
      if (!handler) {
        return error(`Unknown auth action "${action}". Expected one of: ${known.join(", ")}.`, unknownStatus);
      }
      return handler(req);
    };
  }

  return {
    POST: dispatch(postRoutes, AUTH_POST_ACTIONS),
    GET: dispatch(getRoutes, AUTH_GET_ACTIONS),
    handlers,
  };
}
