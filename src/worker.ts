import { handleRequest } from './handler';

export { RateLimiterV2DO } from './rate-limiter';

export interface Env {
  CACHE: KVNamespace;
  ADMIN_KEY: string;
  PROBE_URL: string;
  RATE_LIMITER: DurableObjectNamespace;
  /** Salt for hashing client IPs before rate-limiter storage. */
  IP_HASH_SALT?: string;
  /** Yoke domain intelligence service binding (.lol family) */
  YOKE?: Fetcher;
  /** Shared key for .lol family service bindings */
  SERVICE_KEY?: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleRequest(request, env, ctx);
  },
};
