# !/usr/bin/python
# 
# (C) Eaton 2025
# EmilienKia@Eaton.com
#
# BlackDuck normalization script.
# Will normalize the security risk statistics for the specified projects.
# Workaround for the BlackDuck API issue with the remediation status.
# Usage: python normalize.py --site https://blackduck.eaton.com [--token <token>] project@version [project@version ...]
# Token might be specified with BLACKDUCK_TOKEN environment variable
#
import requests

from blackduck import Client
import argparse
import logging
import os
import re

# BlackDuck Rest API : https://blackduck.eaton.com/api-doc/public.html
# BlackDuck Python API : https://github.com/blackducksoftware/hub-rest-api-python

print("BlackDuck normalization script")

parser = argparse.ArgumentParser(description='Normalize BlackDuck project security risk statistics')
parser.add_argument('project', nargs="+", help='BlackDuck projects to look for, on the form project@version')
parser.add_argument('--site', help='BlackDuck instance site', required=True)
parser.add_argument('--token', help='BlackDuck token')
args = parser.parse_args()

if(args.token):
    token = args.token
else:
    token = os.environ.get('BLACKDUCK_TOKEN', '')

if(not token):
    print("BlackDuck token must be specified by --token arg or with BLACKDUCK_TOKEN env variable")
    exit()

if(not args.site):
    print("BlackDuck site must be specified by --site arg")
    exit()
site = args.site

projects = args.project
if(not projects):
    print("BlackDuck project must be specified in the form of project@version")
    exit()
    

print("Look at " + site + " for " +  str(len(projects)) + " project(s)")
print(projects)


projectNameList = []
for proj in projects:
    if(len(proj.split("@")) != 2):
        print("Project '" + proj + "' must be specified in the form of project@version")
        exit()
    projectNameList.append(proj.split("@")[0])    


logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] {%(module)s:%(lineno)d} %(levelname)s - %(message)s"
)

bd = Client(
    token=token,
    base_url=site,
    verify=False  # TLS certificate verification
)

for project in bd.get_resource('projects'):
    projectName = project["name"]
    if(projectName in projectNameList):
        versions = bd.get_resource('versions', project)
        for ver in versions:
            projectVersionName = ver.get('versionName')
            projectFullName = projectName + "@" + projectVersionName
            if(projectFullName in projects):
                print(projectFullName)
                projectId, versionId = re.search(r"/projects/(.+?)/versions/(.+?)$", ver["_meta"]["href"]).group(1, 2)

                bom = bd.get_resource('vulnerable-components', ver, headers={"Accept": "application/vnd.blackducksoftware.bill-of-materials-6+json"})
                for comp in bom:
                    compVulnHref = comp["_meta"]["href"]
                    compHref = re.search(r"^(.+/projects/.+/versions/.+/components/.+/versions/[^/]+)/.*$", compVulnHref).group(1)
                    compVulnApiPath = re.search(r"^.+(/api/.+)$", compVulnHref).group(1)

                    componentName = comp["componentName"]
                    componentVersionName = "<<no-version-name>>"
                    if("componentVersionName" in comp):
                        componentVersionName = comp["componentVersionName"]
                    componentVersionOriginId = "<<no-origin-id>>"
                    if("componentVersionOriginId" in comp):
                        componentVersionOriginId = comp["componentVersionOriginId"]

                    ignored = False
                    if("ignored" in comp and comp["ignored"]):
                        ignored = True
                    
                    remediation = comp["vulnerabilityWithRemediation"]
                    severity = remediation["severity"]
                    remediationStatus = remediation["remediationStatus"]

                    if(severity in ["CRITICAL", "HIGH"] and not ignored and remediationStatus in ["DUPLICATE", "IGNORED", "MITIGATED", "PATCHED", "REMEDIATION_COMPLETE"]):
                        print("  " + componentName + " " + componentVersionName + " " + componentVersionOriginId + " " + remediationStatus + " " + severity)

                        remediationComment = ""
                        if("remediationComment" in remediation):
                            remediationComment = remediation["remediationComment"]
                        print(remediationComment)

                        try:
                            bd.session.put(compVulnApiPath, json={"remediationStatus": "NEW", "comment" : "Revert to new from " + remediationStatus + " to fix BlackDuck issue"})
                        except requests.HTTPError as e:
                            print("Error while resetting component status to new" )
                            print("HTTPError: " + str(e))
                            bd.http_error_handler(e)
                            exit()

                        try:
                            bd.session.put(compVulnApiPath, json={"remediationStatus": remediationStatus, "comment" : remediationComment})
                        except requests.HTTPError as e:
                            print("Error while setting again component status" )
                            print("HTTPError: " + str(e))
                            bd.http_error_handler(e)
                            exit()
