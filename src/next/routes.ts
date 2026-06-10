// Next.js App Router binding. Wire up a single catch-all route:
//
//   // app/api/auth/[...action]/route.ts
//   import { createNextAuthRoutes } from "@tetrac/login-sdk/next";
//   import { resolveStorageAdapter } from "@tetrac/login-sdk/storage";
//   const storage = await resolveStorageAdapter();
//   export const { GET, POST } = createNextAuthRoutes({ storage });
//
import { createAuthHandlers, type AuthHandlerOptions } from "../server/routes.js";
import { error } from "../server/http.js";

// Next passes params as a Promise (15+) or plain object (≤14); support both.
type RouteContext = {
  params: { action?: string[] } | Promise<{ action?: string[] }>;
};

async function actionOf(ctx: RouteContext): Promise<string> {
  const params = await ctx.params;
  return (params.action ?? []).join("/");
}

export function createNextAuthRoutes(opts: AuthHandlerOptions) {
  const handlers = createAuthHandlers(opts);

  const postRoutes: Record<string, (req: Request) => Promise<Response>> = {
    challenge: handlers.challenge,
    register: handlers.register,
    login: handlers.login,
    "login-wallet": handlers.loginWallet,
    "connect-wallet": handlers.connectWallet,
    "import-wallet": handlers.importWallet,
    logout: handlers.logout,
  };

  const getRoutes: Record<string, (req: Request) => Promise<Response>> = {
    "user-data": handlers.userData,
    "search-wallet": handlers.searchWallet,
  };

  async function POST(req: Request, ctx: RouteContext): Promise<Response> {
    const handler = postRoutes[await actionOf(ctx)];
    return handler ? handler(req) : error("Not found", 404);
  }

  async function GET(req: Request, ctx: RouteContext): Promise<Response> {
    const handler = getRoutes[await actionOf(ctx)];
    return handler ? handler(req) : error("Not found", 404);
  }

  return { GET, POST, handlers };
}
