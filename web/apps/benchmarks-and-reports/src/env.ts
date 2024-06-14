import { createNextjsEnv } from "@risc0/ui/libs/env-valibot/nextjs";
import { vercel as presetVercel } from "@risc0/ui/libs/env-valibot/presets";
import { optional as vOptional, picklist as vPicklist } from "valibot";

const env = createNextjsEnv({
  extends: [presetVercel()],

  /**
   * Specify server-side environment variables schema here.
   */
  server: {
    NODE_ENV: vOptional(vPicklist(["development", "test", "production"]), "development"),
  },

  /**
   * Specify client-side environment variables schema here.
   * To expose them to the client, prefix them with `NEXT_PUBLIC_`.
   */
  client: {},

  /**
   * You can't destruct `process.env` as a regular object in the Next.js edge runtimes
   * (e.g. middlewares) or client-side so we need to destruct manually.
   */
  runtimeEnv: {
    NODE_ENV: process.env.NODE_ENV,
  },
  /**
   * Makes it so that empty strings are treated as undefined.
   * `SOME_VAR: z.string()` and `SOME_VAR=''` will throw an error.
   */
  emptyStringAsUndefined: true,
});

export default env;
