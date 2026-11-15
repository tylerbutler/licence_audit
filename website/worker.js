const canonicalHost = "licence-audit.tylerbutler.com";
const aliasHost = "license-audit.tylerbutler.com";

export default {
  fetch(request, env) {
    const url = new URL(request.url);

    if (url.hostname === aliasHost) {
      url.protocol = "https:";
      url.hostname = canonicalHost;
      return Response.redirect(url.toString(), 301);
    }

    return env.ASSETS.fetch(request);
  },
};
