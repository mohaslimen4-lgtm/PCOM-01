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
    
def get_request(url):
    headers = HEADERS if "github" in url else {}
    response = requests.get(url, headers=headers)
    if response.status_code == 403:
        remaining = response.headers.get("X-RateLimit-Remaining")

        if remaining == "0":
            reset = int(response.headers.get("X-RateLimit-Reset", 0))
            wait = max(reset - int(time.time()), 0) 

            print(f"Rate limit reached. Waiting {wait} seconds...")
            time.sleep(wait)

            return get_request(url)
    if response.status_code == 429:
        wait = 5
        print(f"Too many requests. Waiting {wait} seconds...")
        time.sleep(wait)
        return get_request(url)

    response.raise_for_status()
    return response.json()
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
repositories = [
    "react/react",
    "axios/axios",
    "lodash/lodash",
    "expressjs/express",
    "eemeli/yaml",
    "mochajs/mocha",
    "preactjs/preact",
    "eslint/eslint",
    "prettier/prettier",
    "jestjs/jest",
    "vitest-dev/vitest",
    "microsoft/playwright",
    "puppeteer/puppeteer",
    "tailwindlabs/tailwindcss",
    "colinhacks/zod",
    "date-fns/date-fns",
    "moment/moment",
    "iamkun/dayjs",
    "uuidjs/uuid",
    "ai/nanoid",
    "chalk/chalk",
    "debug-js/debug",
    "motdotla/dotenv",
    "tj/commander.js",
    "yargs/yargs",
    "npm/node-semver",
    "Automattic/mongoose",
    "prisma/prisma",
    "socketio/socket.io",
    "ReactiveX/rxjs",
    "reduxjs/redux",
    "remix-run/react-router",
    "vercel/swr",
    "lovell/sharp",
    "expressjs/cors",
    "expressjs/body-parser",
    "nodejs/node",
]        
for repos in repositories:
    repo=repos 
    package_name=repo.split("/")[1]
    url ="https://registry.npmjs.org/" + package_name
    package = get_request(url)
############ versions###########
    versions = package.get("versions", {})
    ti = package.get("time", {}) # list containing the version and the creation time of the version
    

############ created at###########
    created_at = package.get("time", {}).get("created")
    for version, t in ti.items():
        all_data = []
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
        row["created_at"] = created_at
        row["published_at"] = published_at
        row["unpacked_size"] = unpacked_size
        row["file_count"] = file_count
        row["dependency_count"] = dependency_count
        row["optional_dependency_count"] = optional_dependency_count
        row["peer_dependency_count"] = peer_dependency_count
        row["dev_dependency_count"] = dev_dependency_count
        row["bundled_dependency_count"] = bundled_dependency_count
        print("PURL:", purl)
        print("Commit date:", published_at)
        print("Unpacked size:", unpacked_size)
        print("File count:", file_count)
        print("Dependency count:", dependency_count)
        print("Optional dependency count:", optional_dependency_count) 
        print("Peer dependency count:", peer_dependency_count)
        print("Dev dependency count:", dev_dependency_count)
        print("Bundled dependency count:", bundled_dependency_count)
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
            print(f"package_downloads_M{i}:", package_downloads_M)
            row["package_downloads_M"+str(i)] = package_downloads_M
            row["package_downloads_days_observed_M"+str(i)] = package_downloads_days_M
            print(f"package_downloads_days_M{i}:", package_downloads_days_M)
            times= package.get("time", {})
            package_stable_release_count_M=0
            for v, value in times.items():
                if v == "created" or v == "modified":
                    continue
                publish=date.fromisoformat(value[:10])    
                if start <= publish <= end:
                    if "beta" not in v and "alpha" not in v and "rc" not in v and "pre" not in v and "a" not in v and "b" not in v:
                        package_stable_release_count_M += 1
            print(f"package_stable_release_count_M{i}:", package_stable_release_count_M)
            row["package_stable_release_count_M"+str(i)] = package_stable_release_count_M
        ###### issues: opened, reopened, closed ########
            issue_open_URL = f"https://api.github.com/search/issues?q=repo:{repo}+is:issue+created:{start}..{end}"
            issue_closed_URL = f"https://api.github.com/search/issues?q=repo:{repo}+is:issue+closed:{start}..{end}"
            issue_reopened_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:issue+is:open+updated:{start}..{end}"
            issue_at_month_end_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:issue"
            issues_open=get_request(issue_open_URL)
            issues_closed=get_request(issue_closed_URL)
            issues_reopened=get_request(issue_reopened_URL)
            issues_at_month_end=get_request(issue_at_month_end_URL)
            issues_opened_count_M=None
            issues_closed_count_M=None
            issues_reopened_count_M=None
            issues_open_at_month_end_M=None
            issues_open_at_month_end_M = sum(1 for iss in issues_at_month_end.get("items", []) if datetime(year, month, last_day, 23, 59, 59, tzinfo=timezone.utc) <= datetime.fromisoformat(iss.get("created_at").replace("Z", "+00:00")) < datetime(year, month, last_day, 23, 59, 59, tzinfo=timezone.utc) + timedelta(seconds=1))      
            issues_opened_count_M=issues_open["total_count"] #len(issues_open.get("items", []))
            issues_closed_count_M=issues_closed["total_count"] #len(issues_closed.get("items", []))
            issues_reopened_count_M=issues_reopened["total_count"] #len(issues_reopened.get("items", []))

        ###### pull requests: opened, merged, closed unmerged, reopened ########    
            pull_open_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:pr+created:{start}..{end}"
            pull_closed_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:pr+is:unmerged+closed:{start}..{end}"
            pull_merged_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:pr+merged:{start}..{end}"
            pull_reopened_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:pr+is:open+updated:{start}..{end}"
            pull_opened_at_month_end_M_URL=f"https://api.github.com/search/issues?q=repo:{repo}+is:pr"
            pull_opened=get_request(pull_open_URL)
            pull_opened_at_month_end=get_request(pull_opened_at_month_end_M_URL)
            pull_closed=get_request(pull_closed_URL)
            pull_merged=get_request(pull_merged_URL)
            pull_reopened=get_request(pull_reopened_URL)
            pull_requests_opened_M=None
            pull_requests_closed_unmerged_M=None
            pull_requests_merged_M=None
            pull_requests_reopened_M=None
            pull_requests_opened_M=pull_opened["total_count"] #len(pull_opened.get("items", []))
            pull_requests_closed_unmerged_M=pull_closed["total_count"] #len(pull_closed)
            pull_requests_merged_M=pull_merged["total_count"] #len(pull_merged.get("items", []))
            pull_requests_reopened_M=pull_reopened["total_count"] #len(pull_reopened.get("items", []))
            pull_requests_open_at_month_end_M = sum(1 for pull in pull_opened_at_month_end.get("items", []) if datetime.fromisoformat(pull.get("created_at")[:10]) <= datetime(year, month, last_day)) 
            row["issues_opened_count_M"+str(i)] = issues_opened_count_M
            row["issues_reopened_count_M"+str(i)] = issues_reopened_count_M
            row["issues_closed_count_M"+str(i)] = issues_closed_count_M
            row["issues_open_at_month_end_M"+str(i)] = issues_open_at_month_end_M
            print(f"issues_open_at_month_end_M{i}:", issues_open_at_month_end_M)
            row["pull_requests_opened_M"+str(i)] = pull_requests_opened_M
            row["pull_requests_merged_M"+str(i)] = pull_requests_merged_M
            row["pull_requests_closed_unmerged_M"+str(i)] = pull_requests_closed_unmerged_M 
            row["pull_requests_reopened_M"+str(i)] = pull_requests_reopened_M
            row["pull_requests_open_at_month_end_M"+str(i)] = pull_requests_open_at_month_end_M 
            print(f"pull_requests_open_at_month_end_M{i}:", pull_requests_open_at_month_end_M)  
            print(f"issues_opened_count_M{i}:", issues_opened_count_M)
            print(f"issues_reopened_count_M{i}:", issues_reopened_count_M)
            print(f"issues_closed_count_M{i}:", issues_closed_count_M)
            print(f"pull_requests_opened_M{i}:", pull_requests_opened_M)
            print(f"pull_requests_merged_M{i}:", pull_requests_merged_M)
            print(f"pull_requests_closed_unmerged_M{i}:", pull_requests_closed_unmerged_M)
            if month == 1:
                month = 12
                year -= 1
            else:
                month -= 1
            i += 1
              
        
    ##### ghsa low, moderate, high, critical, unknown  count before 07.2026 (prediction time)############
        ghsa_url = f"https://api.github.com/advisories?ecosystem=npm&affects={package_name}"
        ghsa_low_count=0
        ghsa_moderate_count=0  
        ghsa_high_count=0
        ghsa_critical_count=0
        ghsa_unknown_count=0
        ghsa_data = get_request(ghsa_url)
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
        print("ghsa_low_count:", ghsa_low_count)
        print("ghsa_moderate_count:", ghsa_moderate_count)  
        print("ghsa_high_count:", ghsa_high_count)
        print("ghsa_critical_count:", ghsa_critical_count)
        print("ghsa_unknown_count:", ghsa_unknown_count)
    
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
            print(f"ghsa_low_count_M{i}:", ghsa_low_count_M)
            print(f"ghsa_moderate_count_M{i}:", ghsa_moderate_count_M)  
            print(f"ghsa_high_count_M{i}:", ghsa_high_count_M)
            print(f"ghsa_critical_count_M{i}:", ghsa_critical_count_M)
            print(f"ghsa_unknown_count_M{i}:", ghsa_unknown_count_M)
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
            if date.fromisoformat("2026-07-01") <= date.fromisoformat(advisory.get("published_at")[:10]) < date.fromisoformat("2026-09-30"):# and is_vulnerable:
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
        print("target_ghsa_low_count_90d:", target_ghsa_low_count_90d)
        print("target_ghsa_moderate_count_90d:", target_ghsa_moderate_count_90d)
        print("target_ghsa_high_count_90d:", target_ghsa_high_count_90d)
        print("target_ghsa_critical_count_90d:", target_ghsa_critical_count_90d)
        print("target_ghsa_unknown_count_90d:", target_ghsa_unknown_count_90d)            
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
