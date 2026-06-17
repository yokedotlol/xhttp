import { handleRequest } from './handler';

export { RateLimiterDO } from './rate-limiter';

export interface Env {
  CACHE: KVNamespace;
  ADMIN_KEY: string;
  PROBE_URL: string;
  RATE_LIMITER: DurableObjectNamespace;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleRequest(request, env, ctx);
  },
};
