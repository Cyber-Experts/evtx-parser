# Self-hosted, offline EVTX parser.
#
#   docker build -t evtx-parser .                  # needs network once (npm + web fonts)
#   docker run --rm -p 3000:3000 evtx-parser       # http://localhost:3000
#
# Air-gapped: build on a connected machine, then
#   docker save evtx-parser | gzip > evtx-parser.tar.gz
# copy the archive across and `docker load < evtx-parser.tar.gz`.
#
# Built with NEXT_PUBLIC_OFFLINE=1: no analytics or third-party scripts, and
# the running app makes no outbound requests. .evtx files are parsed in the
# browser, never sent to this server either.

FROM node:24-alpine AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_PUBLIC_OFFLINE=1 \
    NEXT_OUTPUT_STANDALONE=1
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
# Standalone server + the static assets and content it serves at runtime.
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
COPY --from=build --chown=node:node /app/public ./public
COPY --from=build --chown=node:node /app/content ./content
USER node
EXPOSE 3000
CMD ["node", "server.js"]
