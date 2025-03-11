# !/usr/bin/python
# 
# (C) Eaton 2025
# EmilienKia@Eaton.com
#
# BlackDuck stats script.
# Retrieve stats from many BD projects and siplay them in CSV form
# Stats are : critical components, high components, critical vulnerabilities, high vulnerabilities, high license risks
# Usage: python stats.py --site https://blackduck.eaton.com [--token <token>] project@version [project@version ...]
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

print("BlackDuck stats script")


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

ignored_count = 0
ignoring_states = {"DUPLICATE", "IGNORED", "MITIGATED", "PATCHED", "REMEDIATION_COMPLETE"}

stats = {}

for project in bd.get_resource('projects'):
    projectName = project.get('name')
    versions = bd.get_resource('versions', project)
    for ver in versions:
        projectVersionName = ver.get('versionName')
        projectFullName = projectName + "@" + projectVersionName
        if(projectFullName in projects):
            print(projectFullName)
            stats[projectFullName] = {"critical comp":0, "high comp":0, "critical vuln":0, "high vuln":0, "high license":0}
            bom = bd.get_resource('components', ver)
            for component in bom:
                critical_vuln = 0
                high_vuln = 0

                for security in component["securityRiskProfile"]["counts"]:
                    if(security["count"] > 0):
                        if(security["countType"] == "CRITICAL" ):
                            critical_vuln = security["count"]
                        if(security["countType"] == "HIGH"):
                            high_vuln = security["count"]

                if critical_vuln > 0 :
                    stats[projectFullName]["critical comp"] += 1
                    stats[projectFullName]["critical vuln"] += critical_vuln
                
                if high_vuln > 0 :
                    stats[projectFullName]["high vuln"] += high_vuln
                    if critical_vuln == 0 :
                        stats[projectFullName]["high comp"] += 1

                for license in component["licenseRiskProfile"]["counts"]:
                    if(license["countType"] in ["CRITICAL", "HIGH"]):
                        stats[projectFullName]["high license"] += license["count"]

for proj in projects:
    if(proj in stats):
        print(proj + "," + str(stats[proj]["critical comp"]) + "," + str(stats[proj]["high comp"]) + "," + str(stats[proj]["critical vuln"]) + "," + str(stats[proj]["high vuln"]) + "," + str(stats[proj]["high license"]))

