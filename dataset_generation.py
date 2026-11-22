import requests
import time
import tarfile
import io
import json
from datetime import date
from semantic_version import Version, NpmSpec
import os
import pandas as pd
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import re

load_dotenv()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
   }
    
MAX_RETRIES = 6
MIN_DELAY = 0.5          # seconds between requests
MAX_BACKOFF = 60         # cap for exponential backoff
TIMEOUT = 30

_session = requests.Session()
_cache = {}
_last_request_time = 0.0


def get_request(url, use_cache=True):
    global _last_request_time

    if use_cache and url in _cache:
        return _cache[url]

    all_data = []
    current_url = url
    visited_urls = set()

    while current_url:
        if current_url in visited_urls:
            break
        visited_urls.add(current_url)

        headers = HEADERS if "github" in current_url else {}
        page_data = None

        for attempt in range(MAX_RETRIES):
            # Proactive throttling: keep a minimum gap between requests
            elapsed = time.time() - _last_request_time
            if elapsed < MIN_DELAY:
                time.sleep(MIN_DELAY - elapsed)

            try:
                response = _session.get(current_url, headers=headers, timeout=TIMEOUT)
            except (requests.ConnectionError, requests.Timeout) as e:
                wait = min(2 ** (attempt + 1), MAX_BACKOFF)
                print(
                    f"Network error ({e}). Retrying in {wait}s "
                    f"(attempt {attempt + 1}/{MAX_RETRIES})..."
                )
                time.sleep(wait)
                continue
            finally:
                _last_request_time = time.time()

            status = response.status_code
            

            # 1) GitHub primary rate limit exhausted
            if status == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
                reset = int(response.headers.get("X-RateLimit-Reset", 0))
                wait = max(reset - int(time.time()), 0) + 1
                print(f"GitHub rate limit reached. Waiting {wait}s...")
                time.sleep(wait)
                continue

            # 2) Server tells us exactly how long to wait
            if status in (403, 429, 503) and "Retry-After" in response.headers:
                try:
                    wait = int(response.headers["Retry-After"])
                except ValueError:
                    wait = 5
                print(f"Throttled. Server asks to wait {wait}s...")
                time.sleep(wait + 1)
                continue

            # 3) 429 / 5xx without Retry-After: exponential backoff + jitter
            if status == 429 or status >= 500:
                wait = min(2 ** (attempt + 1), MAX_BACKOFF) + random.uniform(0, 1)
                print(
                    f"HTTP {status}. Waiting {wait:.1f}s "
                    f"(attempt {attempt + 1}/{MAX_RETRIES})..."
                )
                time.sleep(wait)
                continue

            # 4) Everything else: raise on error, otherwise parse JSON
            response.raise_for_status()
            page_data = response.json()
            break
        else:
            raise RuntimeError(f"Giving up after {MAX_RETRIES} retries: {current_url}")

        if isinstance(page_data, list):
            all_data.extend(page_data)
        else:
            # Non-list response (e.g., a single dict object)
            all_data = page_data
            break

        next_link = response.links.get("next")
        current_url = next_link["url"] if next_link and "url" in next_link else None

    if use_cache:
        _cache[url] = all_data

    return all_data
def check_vulnerability(package_version, vulnerability_range):
    x = vulnerability_range.split(",")[0].strip() 
    y = vulnerability_range.split(",")[1].strip() if len(vulnerability_range.split(",")) > 1 else None
    version = Version(package_version)
    spe_x = NpmSpec(x)
    spe_y = NpmSpec(y) if y else None
    if spe_x.match(version) and (spe_y.match(version) if spe_y else True):
        return True
    else:
        return False
def get_all_issues(repo, since="2025-07-01T00:00:00Z"):
    all_items = []
    page = 1

    while True:
        url = (
            f"https://api.github.com/repos/{repo}/issues"
            f"?state=all&since={since}&per_page=100&page={page}"
        )
    #url = f"https://api.github.com/repos/{repo}/issues?state=all&since=2025-07-01T00:00:00Z&per_page=100"
        data = get_request(url)
    
    #return data
        if not data:          # empty page -> no more data
            break

        all_items.extend(data)

        page += 1

    return all_items   
def get_all_ghsa(repo):
    all_items = []
    page = 1

    while True:
        url = (
            f"https://api.github.com/advisories"
            f"?ecosystem=npm&affects={repo}&per_page=100&page={page}"
        )
        data = get_request(url)

        if not data:          # empty page -> no more data
            break

        all_items.extend(data)

        page += 1

    return all_items        
def remove_duplicates(data):
    result = [
        item for item in data
        if not item.get("summary", "").lower().startswith("duplicate")
    ]

    return result     
repositories = [
    # ===== A - active (release in last 6 months) =====
    
    "axios/axios",
    "vitejs/vite",
    "nodejs/undici",
    "react/react",
    "remix-run/react-router",
    "eslint/eslint",
    "webpack/webpack",
    "colinhacks/zod",
    "evanw/esbuild",
    "honojs/hono",
    "expressjs/express",
    "rollup/rollup",
    "microsoft/playwright",
    "markedjs/marked",
    "lodash/lodash",
    "isaacs/minimatch",
    "electron/electron",
    "angular/angular",
    "NaturalIntelligence/fast-xml-parser",
    "babel/babel",
    "npm/node-semver",
    "withastro/astro",
    "storybookjs/storybook",
    "juliangruber/brace-expansion",
    "sveltejs/svelte",
    "prettier/prettier",
    "ljharb/qs",
    "vercel/turbo",
    "nuxt/nuxt",
    "postcss/postcss",
    "websockets/ws",
    "tailwindlabs/tailwindcss",
    "pillarjs/path-to-regexp",
    "Automattic/mongoose",
    "ai/nanoid",
    "ajv-validator/ajv",
    "nodeca/js-yaml",
    "uuidjs/uuid",
    "nestjs/nest",
    "sidorares/node-mysql2",
    "eemeli/yaml",
    "fastify/fastify",
    "isaacs/node-tar",
    "vuejs/core",
    "immerjs/immer",
    "puppeteer/puppeteer",
    "chimurai/http-proxy-middleware",
    "remotion-dev/remotion",
    "jsdom/jsdom",
    "salesforce/tough-cookie",
    "motdotla/dotenv",
    "lovell/sharp",
    "jestjs/jest",
    "nodemailer/nodemailer",
    "typeorm/typeorm",
    "react-hook-form/react-hook-form",
    "form-data/form-data",
    "expressjs/body-parser",
    "preactjs/preact",
    "apostrophecms/sanitize-html",
    "jquery/jquery",
    "isaacs/node-glob",
    "prisma/prisma",
    "panva/jose",
    "jshttp/cookie",
    "iamkun/dayjs",
    "yahoo/serialize-javascript",
    "yargs/yargs",
    "brianc/node-postgres",
    "redis/node-redis",
    "digitalbazaar/forge",
    "sequelize/sequelize",
    "browserslist/browserslist",
    "follow-redirects/follow-redirects",
    "cheeriojs/cheerio",
    "webpack/webpack-dev-middleware",
    "knex/knex",
    "mochajs/mocha",
    "sindresorhus/got",
    "pmndrs/zustand",
    "koajs/koa",
    "date-fns/date-fns",
    "markdown-it/markdown-it",
    "nodejs/node-gyp",
    "mde/ejs",
    "zloirock/core-js",
    "sindresorhus/p-limit",
    "redis/ioredis",
    "sindresorhus/strip-ansi",
    "tj/commander",
    "hapijs/joi",
    "validatorjs/validator.js",
    "unjs/unplugin",
    "expressjs/cors",
    "vercel/swr",
    "remix-run/remix",
    "lit/lit",
    "apache/echarts",
    "jashkenas/underscore",
    "patriksimek/vm2",
    "sindresorhus/ky",
    "socketio/engine.io",
    "pmndrs/jotai",
    "gatsbyjs/gatsby",
    "sindresorhus/p-queue",
    "sindresorhus/globby",
    "sindresorhus/p-retry",
    "sinonjs/sinon",
    "ladjs/superagent",
    "helmetjs/helmet",
    "parcel-bundler/parcel",
    "pmndrs/valtio",
    "pugjs/pug",
    "gruntjs/grunt",
    "sindresorhus/slugify",

    # ===== B - slowing (last release 6-12 months ago) =====
    "debug-js/debug",
    "twbs/bootstrap",
    "chaijs/chai",
    "auth0/node-jsonwebtoken",
    "chalk/chalk",
    "jshttp/mime-types",
    "sindresorhus/execa",
    "chalk/ansi-regex",
    "paulmillr/chokidar",
    "winstonjs/winston",
    "chalk/ansi-styles",
    "moment/luxon",
    "socketio/socket.io",
    "jquense/yup",
    "unjs/ofetch",
    "sindresorhus/quick-lru",
    "sindresorhus/pretty-ms",
    "jaredpalmer/formik",
    "colinhacks/superjson",
    "sindresorhus/del",
    "sindresorhus/is",
    "sindresorhus/p-throttle",

    # ===== D - not in your datasets (cannot rank) =====
    "moment/moment",
    "node-fetch/node-fetch",
    "request/request",
    "indutny/node-ip",
    "mysqljs/mysql",
    "kelektiv/node.bcrypt.js",
    "janl/mustache.js",
    "xmldom/xmldom",
    "json5/json5",
    "minimistjs/minimist",
    "micromatch/micromatch",
    "micromatch/braces",
    "shelljs/shelljs",
    "yargs/yargs-parser",
    "yargs/y18n",
    "gulpjs/gulp",
    "less/less.js",
    "caolan/async",
    "immutable-js/immutable-js",
    "petkaantonov/bluebird",
    "trpc/trpc",
    "unjs/ohash",
    "npm/cli",
    "solidjs/solid",
    "reduxjs/redux",
    "ReactiveX/rxjs",
    "npm/promise-spawn",
    "sindresorhus/escape-string-regexp",
    "chartjs/chart",
    "d3/d3",
    "mrdoob/three.js",
    "mui/material-ui",
    "ant-design/ant-design",
    "chakra-ui/chakra-ui",
    "radix-ui/primitives",
]

repositories = [
    "react",
    #"JSONPath-Plus/JSONPath",
    #"hughsk/flat",
    #"BinaryMuse/toml-node",
    #"isaacs/ini",
   
    ##"adaltas/node-csv",
    #"SheetJS/sheetjs",
   # "exceljs/exceljs",
    #"protobufjs/protobuf.js",
    #"fb55/nth-check",
    #"fb55/css-what",
    #"postcss/postcss-selector-parser",

  #  "sindresorhus/semver-regex",
   # "sindresorhus/trim-newlines",
   # "sindresorhus/normalize-url",
   # "jonschlinkert/word-wrap",
   # "yargs/y18n",
   # "npm/hosted-git-info",
   # "chaijs/get-func-name",

    #"jonschlinkert/kind-of",
    #"jonschlinkert/set-value",
    #"jonschlinkert/mixin-deep",
    #"jonschlinkert/union-value",
    #"jonschlinkert/unset-value",
    #"mariocasciaro/object-path",
    #"sindresorhus/dot-prop",
   
    
    #"jonschlinkert/merge-deep",
    #"jonschlinkert/defaults-deep",
    #"SBoudrias/getobject",
   # "sindresorhus/object-assign",
    
   # "request/request",
    #"request/request-promise",
    #"tomas/needle",
    #"lquixada/cross-fetch",
    #"matthew-andrews/isomorphic-fetch",
    #"kornelski/http-cache-semantics",
   
   # "socketio/socket.io",
    #"socketio/engine.io-client",
    #"indutny/node-ip",
    #"rs/node-netmask",
    #"mycoboco/pac-resolver",
   # "TooTallNate/node-degenerator",
   
    
#    "tulios/kafkajs",
   
    #"cisco/node-jose",
   # "kjur/jsrsasign",
  # "auth0/node-jwa",
    
    #"mikenicholson/passport-jwt",
    #"ciaranj/node-oauth",
    #"lelylan/simple-oauth2",
   # "panva/openid-client",
    
   # "Dexus/pem",
    
    #"mscdex/ssh2",
    
   # "crypto-browserify/pbkdf2",
  #  "pvorb/node-md5",
    
    
    #"indutny/bn.js",
    #"indutny/asn1.js",
   
    #"browserify/crypto-browserify",
    #"typestack/class-validator",
    #"typestack/class-transformer",
    #"hacksparrow/safe-eval",
    #"sebhildebrandt/systeminformation",
    #"luin/serialize",
    #"RIAEvangelist/node-ipc",
    #"apocas/dockerode",
   # "apocas/docker-modem",
    
    #"tediousjs/node-mssql",
    #"tediousjs/tedious",
    #"oracle/node-oracledb",
    #"datastax/nodejs-driver",
   
   
    #"louischatriot/nedb",
    #"typicode/lowdb",
    #"bookshelf/bookshelf",
    #"Vincit/objection.js",
    #"drizzle-team/drizzle-orm",
    #"kysely-org/kysely",
   # "archiverjs/node-archiver",
   # "kevva/decompress",
   # "sindresorhus/extract-zip",
   # "thejoshwolfe/yauzl",
   # "mafintosh/tar-stream",
   # "foliojs/pdfkit",
   # "Hopding/pdf-lib",
   # "jimp-dev/jimp",
   # "Automattic/node-canvas",
   # "aheckmann/gm",
   # "fluent-ffmpeg/node-fluent-ffmpeg",
   
   # "aws/aws-sdk-js-v3",
    
   
   
  #  "googleapis/nodejs-storage",
   # "stripe/stripe-node",
   # "twilio/twilio-node",
   # "sendgrid/sendgrid-nodejs",
   
    #"discordjs/discord.js",
    #"telegraf/telegraf",
    #"serverless/serverless",
    #"aws/aws-cdk",
    #"OptimalBits/bull",
    #"taskforcesh/bullmq",
    #"agenda/agenda",
    #"kelektiv/node-cron",
    #"node-schedule/node-schedule",
    #"log4js-node/log4js-node",
    #"trentm/node-bunyan",
    #"karma-runner/karma",
    #"jasmine/jasmine",
    #"nock/nock",
    #"puppeteer/puppeteer",
    #"SeleniumHQ/selenium",
    #"webdriverio/webdriverio",
    
    #"npm/cli",
    #"npm/pacote",
   # "npm/npm-registry-fetch",
    "npm/cacache",
    "npm/ssri",
    "isaacs/minipass",
    "Qix-/color-convert",
    "Qix-/color-string",
    "Marak/colors.js",
    "lukeed/kleur",
    "alexeyraspopov/picocolors",
    "faker-js/faker",
    "dominictarr/event-stream",
    "rbuckton/reflect-metadata",
]
repositories = [
   # Best vulnerable packages in dataset.csv (0 missing issue/PR cells)#
   #"@nestjs/common",
    #"astro",
    #"electron",
    #"hono",
    #"mongoose",
    #"nuxt",
    #"react-router",
    #"axios",
    #"fastify",
   # "typeorm",
    # Vulnerable packages in dataset.csv with some missing issue/PR cells
  #  "vm2",
   # "sequelize",
    #"undici",
    #"systeminformation",
    #"fast-xml-parser",
    #"qs",
    #"nodemailer",
    #"nanoid",
   # "browserslist",
    #"brace-expansion",
    #"joi",
    #"postcss",
    #"js-yaml",
    #"sharp",
    #"body-parser",
    #"sanitize-html",
    
    # Clean non-vulnerable contrast packages in dataset.csv (0 missing issue/PR cells)
   # "remotion",
   # "svelte",
   # "storybook",
   # "vite",
   # "puppeteer",
   # "turbo",
   # "prisma",
  #  "react-hook-form",
   # "webpack",
   # "webdriverio",
   # "eslint",
   # "react",
   # "tailwindcss",
   # "prettier",
   # "playwright",
   # "jest",
    #"drizzle-orm",
    #"remix",
    #"express",
    #"mocha",
    #"lit",
   #"bootstrap",
     
   # "mysql2",  
   # "vitest",
    #"tar",
   # "dompurify",  
   #"pdfjs-dist",  
   # "multer", 
   # "socket.io-parser",  
    #"node-forge",  
  # "webpack-dev-server",  
    #"adm-zip", 
   
  #  "inquirer",  
     
    #"react-dom",  
    #"sass", 
    #"cypress",
   # "vue",  
     
    #"lru-cache", 
   # "redis",  
    #"better-sqlite3",  
  # "glob", 
   # "engine.io",
  #"next",
   # "graphql",  
    #"@tanstack/react-query",
    #"minimatch",
    #"marked",
    #"pg",  
    #"semver",  
    #"mongodb", 
   # "autoprefixer",  
   
    #"jspdf",  
    #"fs-extra",  
     
    #"nodemon", 
    #"picomatch",
    #"rimraf",  
    #"supports-color",  
    
    #"agent-base",  
  #  "http-proxy-agent", 
  #  "https-proxy-agent",  
   # "iconv-lite",  
    #"argon2",  
    #"express-session",  
    #"jws",  
   # "parse5",  
   # "supertest",  
   # "tar-fs",  
   # "string-width",  
   #"validator",  
   # "ora",#########################
    #"unzipper",  
   #"bcryptjs",  
  #  "handlebars", 
    #"jsonwebtoken",  
    #"node-rsa",  
   # "proxy-from-env", 
    #"send",  ##----------------#v´´
    #"serve-static",  
    #"source-map",
   # "sqlite3",  
    #"@sveltejs/kit",
    #"@angular/core",
   # "rollup",
   # "zod",
    #"got",
   # "esbuild",
  #  "@prisma/client",
   # "ioredis",
   
   # "@nestjs/core",
   # "immer",
    #"dotenv",
   # "chai",
   # "knex",
    #"koa",
   # "jose",
    #"jotai",
 #   "uuid",
  #  "form-data",
   # "dayjs",
   # "serialize-javascript",
   # "zustand",
   # "p-queue",
   # "swr",
  #  "ws",
   # "yaml",
   # "preact",
   # "pacote",
   # "ky",
   # "jsdom",
    #"http-proxy-middleware",
   # "node-gyp",
    # "typescript",
]
repositories = [
    # Vulnerable, active (advisory count)
   # "directus",                    # 61
   # "pnpm",                        # 50
   # "@angular/platform-server",    # 47
   ####### "@solana/web3.js",             # 34
    #"@angular/ssr",                # 20
    #"liquidjs",                    # 19
    #"highcharts",                  # 19
    #"@hono/node-server",           # 11
    #"@astrojs/node",               # 10
    #"simple-git",                  # 10
    #"@apollo/gateway",             # 9
   # "immutable",                   # 9
   # "@modelcontextprotocol/sdk",   # 9
   # "npm",                         # 9
   # "xml-crypto",                  # 8
   # "happy-dom",                   # 8
   # "basic-ftp",                   # 8
   # "aws-cdk-lib",                 # 8
   # "wrangler",                    # 6
    #"@nestjs/microservices",       # 5
    #"elysia",                      # 5
    #"snowflake-sdk",               # 4
    #"isomorphic-git",              # 4
    #"@payloadcms/next",            # 4
    #"quasar",                      # 4
  #  "@sveltejs/adapter-vercel",    # 3
   # "@fastify/busboy",             # 3
   # "bitcoinjs-lib",               # 3
   # "@hapi/hapi",                  # 2
   # "@fastify/websocket",          # 2
   # "@astrojs/vercel",             # 2
   # "@astrojs/cloudflare",         # 2
    #"@node-red/runtime",           # 2
    #"chromedriver",                # 2
  #  "react-native",                # 2
   # "expo",                        # 2
   # "@azure/msal-node",            # 2
    #"isolated-vm",                 # 2------------------------------
#  "@anthropic-ai/sdk",           # 2
  #  "@modelcontextprotocol/inspector",  # 2
   # "@tiptap/core",                # 2
    #"@vue/server-renderer",        # 1
    #"express-handlebars",          # 1
   # "@fastify/session",            # 1
  #  "@fastify/oauth2",             # 1
 #   "@react-router/node",          # 1
  #  "electron-updater",            # 1
   # "objection",                   # 1
   # "papaparse",                   # 1
 #   "pdfmake",                     # 1
  #  "superagent",                  # 1
  #  "pac-resolver",                # 1
  #  "@rspack/core",                # 1
  #  "open",                        # 1
 #   "keycloak-js",                 # 1
 #   "@azure/identity",             # 1
  #  "mailparser",                  # 1
  #  "serverless",                  # 1
  #  "maplibre-gl",                 # 1
   ### "apexcharts",                  # 1
   # "@nuxt/ui",                    # 1
   # "react-router-dom",            # 1
   # "@tauri-apps/cli",             # 1

    # Vulnerable, published within 90 days but 1-3 releases a year
   # "image-size",
   # "multiparty",
   # "netmask",
  #  "mime",
   # "restify",
   # "chrome-launcher",

    # Clean contrast packages (no advisories found), active
 #   "viem",
    #"@angular/build",
   # "@angular/forms",
   # "@angular/animations",
  #  "@angular/material",#yizi----
   
    
    #"@nestjs/cli",
   # "@nestjs/schematics",
  #  "@nestjs/config",
 #   "@nestjs/event-emitter",
    #"@nestjs/throttler",
   # "@nestjs/cache-manager",
    #"@langchain/openai",
   # "wagmi",
    #"tsdown",
    #"puppeteer-core",
   # "@ionic/angular",
    #"@ionic/react",
   # "@capacitor/core",
    #"@medusajs/medusa",
  #  "@auth0/auth0-spa-js",
    #"mssql",
   # "tedious",
   # "electron-builder",
    #"msw",
   # "algoliasearch",
   # "@astrojs/mdx",
 #   "@astrojs/react",
# "slate",
  #  "lexical",
   
 #   "@hookform/resolvers",
  #  "@react-router/dev",
   # "oidc-provider",
    #"openid-client",
   # "@nuxt/kit",
    #"mapbox-gl",
    #"@node-red/editor-api",
  #  "@graphql-tools/schema",
   # "@graphql-codegen/cli",
    #"graphql-ws",
    #"@vue/compiler-sfc",
    #"@vitejs/plugin-vue",
 #   "@vue/test-utils",
  #  "konva",
   # "pixi.js",
    #"shiki",
    #"recharts",
   # "@clickhouse/client",
   # "@elastic/elasticsearch",
   # "meilisearch",
   # "firebase-admin",
   #"@xmldom/xmldom",
   # "@google-cloud/storage",
    #"@azure/storage-blob",
   # "type-fest",
    "node-html-parser",
    "selenium-webdriver",
    "testcafe",
    "lighthouse",
    "react-window",
    "nock",
    "otplib",
    "agenda",
    "concurrently",
    "execa",
    "wait-on",
    "@testing-library/user-event",
    "@testing-library/jest-dom",
    "@tauri-apps/api",
    "@radix-ui/react-dialog",
    "@fastify/swagger",
    "@fastify/cookie",
    "@fastify/rate-limit",
    "@fastify/compress",
    "@fastify/sensible",
    "@electron/rebuild",
    "@electron/asar",
    "pdfkit",
    "tar-stream",
    "proxy-agent",
    "@sveltejs/vite-plugin-svelte",
    "@sveltejs/adapter-auto",
    "drizzle-kit",
    "p-retry",
    "p-limit",
    "p-map",
    "vite-plugin-dts",
    "nanostores",
    "mongodb-memory-server",
    # Clean, published within 90 days but 1-3 releases a year
    "@nestjs/mongoose",
    "@nestjs/passport",
    "@fastify/formbody",
    "linkedom",
    "turndown",
    "keyv",
    "chokidar",
    "monaco-editor",
    "ts-pattern",
    "react-toastify",
    "ejs",
    "@angular/compiler"
]
repositories = [
 #   "@angular/common",
  #  "@angular/platform-browser",
   # "@apollo/server",
    #"@babel/core",
    #"@babel/traverse",
    #"@octokit/request",
   # "@remix-run/node",
    #"ajv",
    #"babel-loader",
    #"bowser",
    #"chalk",
    ######"chart.js",
   # "cheerio",
   # "codemirror",
   # "commander",
   # "compression",
   # "content-type",
   # "cookie",
   # "cors",
   # "css-loader",
   # "debug",
   # "ember-source",
   # "express-fileupload",
    #"express-validator",
    #"finalhandler",
    #"follow-redirects",
    #"grunt",
    #####"h3",
    #"helmet",
    #"jquery",
    #"js-beautify",
    #"jsonpath",
    #"jsonpath-plus",
    #"katex",
    #"lerna",
    #"lodash",
    #"lodash-es",
    #"lodash.template",
   # "markdown-it",
    #"mathjs",
    #"mime-types",
    #"morgan",
    #"nx",
    #"parcel",
    #"path-to-regexp",
    #"pinia",
    #"pino",
    #"pug",
    #"raw-body",
    #"sails",
  
    #"solid-js",
    #"strip-ansi",
    #"terser",
    #"terser-webpack-plugin",
    
    "tinymce",
    "tough-cookie",
    "ts-jest",
    "tsup",
    "type-is",
    "ua-parser-js",
    "underscore",
    "vue-router",
    "webpack-cli",
    "webpack-dev-middleware",
    "winston",
    "yargs",
    "yup",
]
def extract_github_owner_repo(metadata):
    """Extracts GitHub owner/repo string from npm metadata."""
    info = metadata.get('repository', {})
    url = info.get('url', '')
    if not url: return None
    match = re.search(r'github\.com/([^/]+)/([^/\.]+)', url)
    if match: return f"{match.group(1)}/{match.group(2)}"
    return None

for repos in repositories:
    
    package_name=repos#.split("/")[1]
    url ="https://registry.npmjs.org/" + repos
    package = get_request(url)
    package_name=extract_github_owner_repo(package)
    if repos == "socket.io-parser":
        package_name = "socketio/socket.io"
    if repos== "webpack-dev-server":
        package_name = "webpack/webpack-dev-server"  
    if repos== "inquirer":
        package_name = "SBoudrias/Inquirer.js" 
    if repos== "validator":
        package_name = "validatorjs/validator.js"
    if repos== "handlebars":
        package_name = "handlebars-lang/handlebars.js"             
############ versions###########
    versions = package.get("versions", {})
    ti = package.get("time", {}) # list containing the version and the creation time of the version
    all_data = []

############ created at###########
    created_at = package.get("time", {}).get("created")
    for version, t in ti.items():
        
        row = {}
        if version == "created" or version == "modified" or "-" in version or "alpha" in version or "beta" in version or "rc" in version:
            continue
        if date.fromisoformat(t[:10]) > date.fromisoformat("2026-06-30") or date.fromisoformat(t[:10]) < date.fromisoformat("2025-07-01"):
            continue
    ############## PURL ############
        purl = f"pkg:npm/{package.get('name')}@{version}"
    ######### published at ############
        published_at = t
    ######### unpacked size ############
        unpacked_size = versions.get(version, {}).get("dist", {}).get("unpackedSize")
    ######### file count ############   
        file_count = versions.get(version, {}).get("dist", {}).get("fileCount")
    ######### dependency count ############
        dependency_count = len(versions.get(version, {}).get("dependencies") or {})
        optional_dependency_count = len(versions.get(version, {}).get("optionalDependencies") or {})
        peer_dependency_count = len(versions.get(version, {}).get("peerDependencies") or {})
        dev_dependency_count = len(versions.get(version, {}).get("devDependencies") or {})
        bundled = versions.get(version, {}).get("bundleDependencies") or versions.get(version, {}).get("bundledDependencies") or []
        bundled_dependency_count = len(set(bundled))
        print("--------------------------------")
        print("Version:", version)
        row["purl"] = purl
        row["package_created_at"] = created_at
        row["published_at"] = published_at
        row["unpacked_size"] = unpacked_size
        row["file_count"] = file_count
        row["dependency_count"] = dependency_count
        row["optional_dependency_count"] = optional_dependency_count
        row["peer_dependency_count"] = peer_dependency_count
        row["dev_dependency_count"] = dev_dependency_count
        row["bundled_dependency_count"] = bundled_dependency_count
        print("PURL:", purl)
       # print("Commit date:", published_at)
       # print("Unpacked size:", unpacked_size)
       # print("File count:", file_count)
       # print("Dependency count:", dependency_count)
       # print("Optional dependency count:", optional_dependency_count) 
       # print("Peer dependency count:", peer_dependency_count)
       # print("Dev dependency count:", dev_dependency_count)
       # print("Bundled dependency count:", bundled_dependency_count)
    ############package_downloads_M############
        year = 2026
        month = 6
        i=0
        while(year,month)>=(2025,7):
            last_day = 30 if month in [4, 6, 9, 11] else 28 if month == 2 else 31 
            start=date(year,month,1)
            end=date(year,month,last_day)
            package_downloads_URL=f"https://api.npmjs.org/downloads/range/{start}:{end}/{repos}"
            downloads_data = get_request(package_downloads_URL)
            package_downloads_days_M = len(downloads_data.get("downloads", []))    
            package_downloads_M = sum(download.get("downloads", 0) for download in downloads_data.get("downloads", []))
            # print(f"package_downloads_M{i}:", package_downloads_M)
            row["package_downloads_M"+str(i)] = package_downloads_M
            row["package_download_days_observed_M"+str(i)] = package_downloads_days_M
            # print(f"package_downloads_days_M{i}:", package_downloads_days_M)
            times= package.get("time", {})
            package_stable_release_count_M=0
            for v, value in times.items():
                if v == "created" or v == "modified":
                    continue
                publish=date.fromisoformat(value[:10])    
                if start <= publish <= end:
                    if "beta" not in v and "alpha" not in v and "rc" not in v and "pre" not in v and "a" not in v and "b" not in v:
                        package_stable_release_count_M += 1
            # print(f"package_stable_release_count_M{i}:", package_stable_release_count_M)
            row["package_stable_release_count_M"+str(i)] = package_stable_release_count_M
        ###### issues: opened, reopened, closed ########
            issues_opened_count_M=0
            issues_closed_count_M=0
            issues_reopened_count_M=None
            issues_open_at_month_end_M=0
            pull_requests_opened_M=0
            pull_requests_closed_unmerged_M=0
            pull_requests_merged_M=0
            pull_requests_reopened_M=None
            pull_requests_open_at_month_end_M=0

            url = f"https://api.github.com/repos/{package_name}/issues?state=all&since=2025-07-01T00:00:00Z&per_page=100"
            
            issues = get_request(url)
            
            for issue in issues:
                is_pr = "pull_request" in issue
                
                if start <= date.fromisoformat(issue.get("created_at")[:10]) <= end:
                    if not is_pr:
                            issues_opened_count_M = issues_opened_count_M + 1 if issues_opened_count_M is not None else 1
                    else:
                        pull_requests_opened_M = pull_requests_opened_M + 1 if pull_requests_opened_M is not None else 1
                if  issue.get("closed_at") is not None:      
                    if start <= date.fromisoformat(issue.get("closed_at")[:10]) <= end:
                        if not is_pr:
                            issues_closed_count_M = issues_closed_count_M + 1 if issues_closed_count_M is not None else 1
                        else:
                            if issue.get('pull_request', {}).get('merged_at'):
                                pull_requests_merged_M = pull_requests_merged_M + 1 if pull_requests_merged_M is not None else 1
                            else:
                                pull_requests_closed_unmerged_M = pull_requests_closed_unmerged_M + 1 if pull_requests_closed_unmerged_M is not None else 1
                #######this later 
                if date.fromisoformat(issue.get("created_at")[:10])<=end and (issue.get("closed_at") is None or date.fromisoformat(issue.get("closed_at")[:10])>end):
                    if not is_pr:
                        issues_open_at_month_end_M = issues_open_at_month_end_M + 1 if issues_open_at_month_end_M is not None else 1
                    else:
                        pull_requests_open_at_month_end_M = pull_requests_open_at_month_end_M + 1 if pull_requests_open_at_month_end_M is not None else 1
                              
            #issue_open_URL = f"https://api.github.com/search/issues?q=repo:{repo}+is:issue+created:{start}..{end}"
            #issue_closed_URL = f"https://api.github.com/search/issues?q=repo:{repo}+is:issue+closed:{start}..{end}"
            #issue_reopened_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:issue+is:open+updated:{start}..{end}"
            #issue_at_month_end_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:issue"
            #issues_open=get_request(issue_open_URL)
            #issues_closed=get_request(issue_closed_URL)
            #issues_reopened=get_request(issue_reopened_URL)
            #issues_at_month_end=get_request(issue_at_month_end_URL)
            
            #issues_open_at_month_end_M = sum(1 for iss in issues_at_month_end.get("items", []) if datetime(year, month, last_day, 23, 59, 59, tzinfo=timezone.utc) <= datetime.fromisoformat(iss.get("created_at").replace("Z", "+00:00")) < datetime(year, month, last_day, 23, 59, 59, tzinfo=timezone.utc) + timedelta(seconds=1))      
            #issues_opened_count_M=issues_open["total_count"] #len(issues_open.get("items", []))
            #issues_closed_count_M=issues_closed["total_count"] #len(issues_closed.get("items", []))
            #issues_reopened_count_M=issues_reopened["total_count"] #len(issues_reopened.get("items", []))

        ###### pull requests: opened, merged, closed unmerged, reopened ########    
            #pull_open_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:pr+created:{start}..{end}"
           # pull_closed_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:pr+is:unmerged+closed:{start}..{end}"
           # pull_merged_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:pr+merged:{start}..{end}"
           # pull_reopened_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:pr+is:open+updated:{start}..{end}"
           # pull_opened_at_month_end_M_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:pr"
           # pull_opened=get_request(pull_open_URL)
           # pull_opened_at_month_end=get_request(pull_opened_at_month_end_M_URL)
           # pull_closed=get_request(pull_closed_URL)
           # pull_merged=get_request(pull_merged_URL)
            #pull_reopened=get_request(pull_reopened_URL)
            #pull_requests_opened_M=None
            #pull_requests_closed_unmerged_M=None
            #pull_requests_merged_M=None
            #pull_requests_reopened_M=None
            #pull_requests_opened_M=pull_opened["total_count"] #len(pull_opened.get("items", []))
            #pull_requests_closed_unmerged_M=pull_closed["total_count"] #len(pull_closed)
            #pull_requests_merged_M=pull_merged["total_count"] #len(pull_merged.get("items", []))
           # pull_requests_reopened_M=pull_reopened["total_count"] #len(pull_reopened.get("items", []))
            #pull_requests_open_at_month_end_M = sum(1 for pull in pull_opened_at_month_end.get("items", []) if datetime.fromisoformat(pull.get("created_at")[:10]) <= datetime(year, month, last_day)) 
            row["issues_opened_M"+str(i)] = issues_opened_count_M
            row["issues_reopened_M"+str(i)] = issues_reopened_count_M
            row["issues_closed_M"+str(i)] = issues_closed_count_M
            row["issues_open_at_month_end_M"+str(i)] = issues_open_at_month_end_M
           # print(f"issues_open_at_month_end_M{i}:", issues_open_at_month_end_M)
            row["pull_requests_opened_M"+str(i)] = pull_requests_opened_M
            row["pull_requests_merged_M"+str(i)] = pull_requests_merged_M
            row["pull_requests_closed_unmerged_M"+str(i)] = pull_requests_closed_unmerged_M 
            row["pull_requests_reopened_M"+str(i)] = pull_requests_reopened_M
            row["pull_requests_open_at_month_end_M"+str(i)] = pull_requests_open_at_month_end_M 
           # print(f"pull_requests_open_at_month_end_M{i}:", pull_requests_open_at_month_end_M)  
           # print(f"issues_opened_count_M{i}:", issues_opened_count_M)
           # print(f"issues_reopened_count_M{i}:", issues_reopened_count_M)
           # print(f"issues_closed_count_M{i}:", issues_closed_count_M)
           # print(f"pull_requests_opened_M{i}:", pull_requests_opened_M)
           # print(f"pull_requests_merged_M{i}:", pull_requests_merged_M)
           # print(f"pull_requests_closed_unmerged_M{i}:", pull_requests_closed_unmerged_M)
            if month == 1:
                month = 12
                year -= 1
            else:
                month -= 1
            i += 1
              
        
    ##### ghsa low, moderate, high, critical, unknown  count before 07.2026 (prediction time)############
        ghsa_url = f"https://api.github.com/advisories?ecosystem=npm&affects={repos}&per_page=100"
        ghsa_low_count=0
        ghsa_moderate_count=0  
        ghsa_high_count=0
        ghsa_critical_count=0
        ghsa_unknown_count=0
        ghsa_data = remove_duplicates(get_request(ghsa_url))
        print(len(ghsa_data))
        #ghsa_data=get_all_ghsa(package_name)
        for advisory in ghsa_data:
            ##if only a specific version is affected keep the two lines below 
            #vulnerable_ranges = [
       #    v["vulnerable_version_range"]
        #   for v in advisory["vulnerabilities"]]
       #    is_vulnerable = any(check_vulnerability(version, r.replace(" ", "")) for r in vulnerable_ranges)   
            if date.fromisoformat(advisory.get("published_at")[:10]) < date.fromisoformat("2026-07-01") :#and is_vulnerable:
                if advisory.get("severity") == "low" :
                    ghsa_low_count += 1
                elif advisory.get("severity") == "medium" :
                    ghsa_moderate_count += 1
                elif advisory.get("severity") == "high" :
                    ghsa_high_count += 1
                elif advisory.get("severity") == "critical":
                    ghsa_critical_count += 1
                else:
                    ghsa_unknown_count += 1
        row["ghsa_low_count"] = ghsa_low_count
        row["ghsa_moderate_count"] = ghsa_moderate_count
        row["ghsa_high_count"] = ghsa_high_count
        row["ghsa_critical_count"] = ghsa_critical_count
        row["ghsa_unknown_count"] = ghsa_unknown_count            
       # print("ghsa_low_count:", ghsa_low_count)
        # print("ghsa_moderate_count:", ghsa_moderate_count)  
        # print("ghsa_high_count:", ghsa_high_count)
        # print("ghsa_critical_count:", ghsa_critical_count)
        # print("ghsa_unknown_count:", ghsa_unknown_count)
    
        year = 2026
        month = 6
        i=0    
    #####if advisory.get("severity") == "low" and check_vulnerability(version, advisory.get("vulnerable_version_range")):
        while(year,month)>=(2025,7):
            last_day = 30 if month in [4, 6, 9, 11] else 28 if month == 2 else 31 
            start=date(year,month,1)
            end=date(year,month,last_day)
            ghsa_low_count_M=0
            ghsa_moderate_count_M=0
            ghsa_high_count_M=0
            ghsa_critical_count_M=0
            ghsa_unknown_count_M=0
            for advisory in ghsa_data: 
            ##if only a specific version is affected keep the two lines below 
            #vulnerable_ranges = [ v["vulnerable_version_range"] for v in advisory["vulnerabilities"]]
            #is_vulnerable = any(check_vulnerability(version, r.replace(" ", "")) for r in vulnerable_ranges)
                if start <= date.fromisoformat(advisory.get("published_at")[:10]) <= end :#and is_vulnerable:
                    if advisory.get("severity") == "low"  :
                        ghsa_low_count_M += 1
                    elif advisory.get("severity") == "medium" :
                        ghsa_moderate_count_M += 1
                    elif advisory.get("severity") == "high" :
                        ghsa_high_count_M += 1
                    elif advisory.get("severity") == "critical":
                        ghsa_critical_count_M += 1
                    else:
                        ghsa_unknown_count_M += 1
            row["ghsa_low_count_M"+str(i)] = ghsa_low_count_M
            row["ghsa_moderate_count_M"+str(i)] = ghsa_moderate_count_M
            row["ghsa_high_count_M"+str(i)] = ghsa_high_count_M
            row["ghsa_critical_count_M"+str(i)] = ghsa_critical_count_M
            row["ghsa_unknown_count_M"+str(i)] = ghsa_unknown_count_M            
           # print(f"ghsa_low_count_M{i}:", ghsa_low_count_M)
           # print(f"ghsa_moderate_count_M{i}:", ghsa_moderate_count_M)  
           # print(f"ghsa_high_count_M{i}:", ghsa_high_count_M)
           # print(f"ghsa_critical_count_M{i}:", ghsa_critical_count_M)
           # print(f"ghsa_unknown_count_M{i}:", ghsa_unknown_count_M)
            i+= 1
            if month == 1:
                month = 12
                year -= 1
            else:
                month -= 1
    ######predicition Goal#############
        target_ghsa_low_count_90d=0
        target_ghsa_moderate_count_90d=0
        target_ghsa_high_count_90d=0
        target_ghsa_critical_count_90d=0
        target_ghsa_unknown_count_90d=0
        for advisory in ghsa_data:
            ##if only a specific version is affected keep the two lines below 
      #  vulnerable_ranges = [ v["vulnerable_version_range"] for v in advisory["vulnerabilities"]]
       # is_vulnerable = any(check_vulnerability(version, r.replace(" ", "")) for r in vulnerable_ranges)
            if date.fromisoformat("2026-07-01") <= date.fromisoformat(advisory.get("published_at")[:10]) < date.fromisoformat("2026-09-28"):# and is_vulnerable:
                if advisory.get("severity") == "low":
                    target_ghsa_low_count_90d += 1
                elif advisory.get("severity") == "medium":
                    target_ghsa_moderate_count_90d += 1
                elif advisory.get("severity") == "high":
                    target_ghsa_high_count_90d += 1
                elif advisory.get("severity") == "critical":
                    target_ghsa_critical_count_90d += 1
                else:
                    target_ghsa_unknown_count_90d += 1
        row["target_ghsa_low_count_90d"] = target_ghsa_low_count_90d
        row["target_ghsa_moderate_count_90d"] = target_ghsa_moderate_count_90d
        row["target_ghsa_high_count_90d"] = target_ghsa_high_count_90d
        row["target_ghsa_critical_count_90d"] = target_ghsa_critical_count_90d
        row["target_ghsa_unknown_count_90d"] = target_ghsa_unknown_count_90d
        all_data.append(row)            
        # print("target_ghsa_low_count_90d:", target_ghsa_low_count_90d)
        # print("target_ghsa_moderate_count_90d:", target_ghsa_moderate_count_90d)
        # print("target_ghsa_high_count_90d:", target_ghsa_high_count_90d)
        # print("target_ghsa_critical_count_90d:", target_ghsa_critical_count_90d)
        # print("target_ghsa_unknown_count_90d:", target_ghsa_unknown_count_90d)            
    df = pd.DataFrame(all_data)
    df.to_csv(
    "dataset.csv",
    mode="a",
    index=False,
    header=True if not os.path.exists("dataset.csv") else False,
    na_rep="null",
    encoding="utf-8"
     )

    print("Full Package saved!")    
