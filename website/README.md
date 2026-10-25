# Website deployment

Run website commands from this directory.

Use `pnpm deploy` to build and deploy to the production domains. Use
`pnpm preview` to serve a local Astro build.

## Worker Previews

Run `pnpm deploy` once after changing `preview_urls` to apply preview routing.
Run `pnpm deploy:preview` to build and deploy a remote Worker Preview for
your current Git branch. Wrangler prints its URL. To choose a preview name,
run `pnpm deploy:preview --name <name>`.

Worker Previews require Wrangler 4.135.0 or later; this project pins a
compatible version. Keep `assets` at the top level of `wrangler.jsonc`.
The empty `previews` block is sufficient for this static website. Preview
deployments do not change the production domains or enable their
`workers.dev` route. Keep `preview_urls` enabled to make previews reachable.

## Cloudflare Workers Builds

Configure `licence-audit-website` in the Cloudflare dashboard:

| Setting | Value |
| --- | --- |
| Root directory | `website` |
| Build command | `pnpm build` |
| Production branch | `main` |
| Deploy command | `pnpm exec wrangler deploy` |
| Preview command | `pnpm exec wrangler preview` |

Under **Settings > Build > Branch control**, enable **Preview Builds** to
create previews for non-production branches and post their URLs on pull
requests.

For an existing Workers Builds connection, select **Set up Worker Previews**
in the **Settings > Builds** banner first. Review the preview settings before
you select **Switch to Worker Previews**: Cloudflare does not let you reverse
this switch.

See the Cloudflare guides for
[Worker Preview configuration](https://developers.cloudflare.com/workers/previews/configuration/) and
[branch builds](https://developers.cloudflare.com/workers/ci-cd/builds/build-branches/).
