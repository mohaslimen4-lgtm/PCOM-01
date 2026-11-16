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

    headers = HEADERS if "github" in url else {}

    for attempt in range(MAX_RETRIES):
        # Proactive throttling: keep a minimum gap between requests
        elapsed = time.time() - _last_request_time
        if elapsed < MIN_DELAY:
            time.sleep(MIN_DELAY - elapsed)

        try:
            response = _session.get(url, headers=headers, timeout=TIMEOUT)
        except (requests.ConnectionError, requests.Timeout) as e:
            wait = min(2 ** (attempt + 1), MAX_BACKOFF)
            print(f"Network error ({e}). Retrying in {wait}s "
                  f"(attempt {attempt + 1}/{MAX_RETRIES})...")
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
            print(f"HTTP {status}. Waiting {wait:.1f}s "
                  f"(attempt {attempt + 1}/{MAX_RETRIES})...")
            time.sleep(wait)
            continue

        # 4) Everything else: raise on error, otherwise return
        response.raise_for_status()
        data = response.json()
        if use_cache:
            _cache[url] = data
        return data

    raise RuntimeError(f"Giving up after {MAX_RETRIES} retries: {url}")
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
        data = get_request(url)

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
    "react/react",
    "axios/axios",
    "lodash/lodash",
    "expressjs/express",
    "eemeli/yaml",
    "mochajs/mocha",
    "preactjs/preact",
    "eslint/eslint",
    "Automattic/mongoose",
    "vuejs/core",
    "angular/angular",
    "sveltejs/svelte",
    "webpack/webpack",
    "vitejs/vite",
    "rollup/rollup",
    "prettier/prettier",
    "jestjs/jest",
    "chalk/chalk",
    "yargs/yargs",
    "moment/moment",
    "uuidjs/uuid",
    "expressjs/body-parser",
    "koajs/koa",
    "nestjs/nest",
    "socketio/socket.io",
    "node-fetch/node-fetch",
    "cheeriojs/cheerio",
    "puppeteer/puppeteer",
    "winstonjs/winston",
    "debug-js/debug",
    "postcss/postcss",
    "sequelize/sequelize",
    "typeorm/typeorm",
    "ljharb/qs",
    "follow-redirects/follow-redirects",
    "nodeca/js-yaml",
    "markedjs/marked",
    "ajv-validator/ajv",
    "fastify/fastify", "nuxt/nuxt",
    "pillarjs/path-to-regexp",
    "jshttp/cookie",
     "chimurai/http-proxy-middleware",
    "webpack/webpack-dev-middleware",
    "sindresorhus/got", "ladjs/superagent", "nodejs/undici", "request/request",
    "websockets/ws", "socketio/engine.io", "salesforce/tough-cookie",
    "form-data/form-data", "indutny/node-ip",
   "brianc/node-postgres", "sidorares/node-mysql2", "mysqljs/mysql",
   "redis/node-redis", "redis/ioredis",
    "knex/knex", "prisma/prisma",
     "auth0/node-jsonwebtoken", "panva/jose", "kelektiv/node.bcrypt.js",
    "digitalbazaar/forge", "nodemailer/nodemailer",
     "mde/ejs", "pugjs/pug", "janl/mustache.js",
    "markdown-it/markdown-it",
    "apostrophecms/sanitize-html",
    "xmldom/xmldom", "NaturalIntelligence/fast-xml-parser",
    "json5/json5", "minimistjs/minimist",
    "yahoo/serialize-javascript",  "jsdom/jsdom",
   "npm/node-semver", "isaacs/node-tar", "isaacs/minimatch", "isaacs/node-glob",
   "juliangruber/brace-expansion", "micromatch/micromatch", "micromatch/braces",
   "paulmillr/chokidar", "shelljs/shelljs", 
    "sindresorhus/execa", 
    "yargs/yargs-parser", "yargs/y18n", "chalk/ansi-regex", "nodejs/node-gyp",
    "gulpjs/gulp", "gruntjs/grunt", "patriksimek/vm2",
    "jquery/jquery", "twbs/bootstrap", "babel/babel",
    "evanw/esbuild", "parcel-bundler/parcel", "gatsbyjs/gatsby",
    "electron/electron", "tailwindlabs/tailwindcss",
     "less/less.js", "browserslist/browserslist",
    "microsoft/playwright","jashkenas/underscore", "iamkun/dayjs",
    "colinhacks/zod", "caolan/async", "zloirock/core-js",
    "immutable-js/immutable-js", "petkaantonov/bluebird", "ai/nanoid",
    "sinonjs/sinon", "chaijs/chai",
]
for repos in repositories:
    repo=repos 
    package_name=repo.split("/")[1]
    url ="https://registry.npmjs.org/" + package_name
    package = get_request(url)
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
            package_downloads_URL=f"https://api.npmjs.org/downloads/range/{start}:{end}/{package.get('name')}"
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
            issues_opened_count_M=None
            issues_closed_count_M=None
            issues_reopened_count_M=None
            issues_open_at_month_end_M=None
            pull_requests_opened_M=None
            pull_requests_closed_unmerged_M=None
            pull_requests_merged_M=None
            pull_requests_reopened_M=None
            pull_requests_open_at_month_end_M=None

            
            issues = get_all_issues(repos)
            
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
        ghsa_url = f"https://api.github.com/advisories?ecosystem=npm&affects={package_name}&per_page=100"
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
    header=False,
    na_rep="null",
    encoding="utf-8"
     )

    print("Full Package saved!")    
