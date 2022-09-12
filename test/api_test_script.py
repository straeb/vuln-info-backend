import itertools
import json
import requests
import random, string
from colorama import Fore

# Tests API functions
# Not a beauty, but it does what its suppose to do.
# Run on empty (test-)database
# Partly fails if data src of API does not deliver CVEs


baseUrl = "http://localhost:8080/api/v1/"
headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
printResponses = False


def assertEqual(msg, r, bool):

    if printResponses:
        if bool:
            print(Fore.WHITE + str(r.content))
            print(Fore.GREEN + msg)
        else:
            print(Fore.WHITE + str(r.content))
            print(Fore.RED + msg)
            assertEqual.counter +=1
    else:
            if bool:
                print(Fore.GREEN + msg)
            else:
                print(Fore.RED + msg)
                assertEqual.counter +=1


assertEqual.counter = 0

def randomword():
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(20))


def randomVendor():
    return {
        "name": "vendor" + randomword()
    }


def randomUser():
    return {
        "e_mail": randomword() + "@" + randomword() + ".com",
        "password": "test"
    }


def p(str):
    print(Fore.LIGHTYELLOW_EX + str)


def POST(obj, path):
    print(Fore.WHITE, "POST: " + baseUrl + path)
    return requests.post(baseUrl + path, json.dumps(obj), headers=headers)


def GET(path):
    print(Fore.WHITE, "GET: " + baseUrl + path)
    return requests.get(baseUrl + path, headers=headers)


def PATCH(obj, path):
    print(Fore.WHITE, "PATCH: " + baseUrl + path)
    return requests.patch(baseUrl + path, json.dumps(obj), headers=headers)


def DELETE(path):
    print(Fore.WHITE, "DELETE: " + baseUrl + path)
    return requests.delete(baseUrl + path, headers=headers)


# Auth
## Signup

p("Authorisation")
path = "auth/signup"

user = randomUser()

r = POST(user, path)
assertEqual("sign up user ", r, r.status_code == 200)

userName = r.json().get('e_mail')

r = POST(user, path)
assertEqual("duplicate user not accepted ", r, r.status_code == 400)

r = GET("components")
assertEqual("Authorization required", r, r.status_code == 401)

## Login
path = "auth/login"
r = POST(user, path)
assertEqual("login user ", r, r.status_code == 200)
token = r.json().get('token')

assertEqual("token not null", r, token != "")

token = "Bearer " + token
headers = {'Content-type': 'application/json', 'Accept': 'text/plain', 'Authorization': token}

# vendors
p("Vendors")
## Create
path = "vendors"

r = POST(randomVendor(), path)

id1 = r.json().get("id")

assertEqual("create Vendor 1", r, r.status_code == 200)

r = POST(randomVendor(), path)
id2 = r.json().get("id")

assertEqual("create Vendor 2", r, r.status_code == 200)

path = path + "/" + str(id1)

## Delete
r = DELETE(path)
assertEqual("delete vendor 1", r, r.status_code == 200)

vendor = randomVendor()
path = "vendors" + "/" + str(id2)

## update

r = PATCH(vendor, path)
assertEqual("update vendor 2", r, r.status_code == 200)

path = "vendors"

r = POST(vendor, path)
assertEqual("duplicate vendor not accepted", r, r.status_code == 400)

# components
p("Components")
## create
path = "components"

component = {
    "cpe": "cpe:2.3:this:is:*:not:a:cpe",
    "name": randomword(),
    "vendorId": id2,
    "version": "1234.SP4isd"
}

r = POST(component, path)
assertEqual("CPE in wrong format not accepted", r, r.status_code == 400)

p("Refresh RSS Feed")
r = POST("", "config/rss")
assertEqual("RSS up to date", r, r.status_code == 200)

p("1. Get vulnerable cve:")
path = "vulnerabilities"

r = GET(path)
assertEqual("Got vulnerabilities", r, r.status_code == 200)

cve = r.json()[0].get("cve")
p(cve)

r = GET("vulnerabilities/" + cve)
assertEqual("Get vulnerability by cve", r, r.status_code == 200)

p("2. Get CPE for CVE " + "https://cve.circl.lu/api/cve/" + cve)

r = requests.get("https://cve.circl.lu/api/cve/" + cve)
cpe = r.json().get("vulnerable_product")[0]
p(cpe)

component = {
    "cpe": cpe,
    "name": randomword(),
    "vendorId": id2,
    "version": "1234.SP4isd"
}
path = "components"

r = POST(component, path)
assertEqual("Create Component with vendor 2 an vulnerable CPE", r, r.status_code == 200)

compId = r.json().get("id")

# update component

component = {
    "cpe": cpe,
    "name": randomword(),
    "vendorId": id2,
    "version": "678978isd"
}
r = PATCH(component, path + "/" + str(compId))
assertEqual("Updated component", r, r.status_code == 200)

component = {
    "cpe": "cpe:2.3:a:freerdp:gibsnicht:9.0.0:*:*:*:*:*:*:*",
    "name": randomword(),
    "vendorId": id2,
    "version": "1234.wsedfreqferfeqrf"
}

r = POST(component, path)
assertEqual("Create another Component", r, r.status_code == 200)

compId2 = r.json().get("id")

r = DELETE(path + "/" + str(compId2))
assertEqual("Delete second component", r, r.status_code == 200)

r = POST(" ", path + "/" + str(compId) + "/subscribe?user=gibteshoffentlichnicht")
assertEqual("subscribe non existing vendor to component", r, r.status_code == 400)

r = POST(" ", path + "/" + str(compId) + "/subscribe?user=" + userName)
assertEqual("subscribe existing user to component", r, r.status_code == 200)

r = GET(path + "/" + str(compId) + "/vulnerabilities")
assertEqual("Get vulnerabilities for component", r, r.status_code == 200)

r = POST(" ","config/match?from=0&to=-300")
assertEqual("run cpe match", r, r.status_code == 200)

r = GET(path + "/" + str(compId) + "/vulnerabilities")
assertEqual("Get vulnerabilities for component", r, r.status_code == 200)
assertEqual("Contians " + cve, r, str(r.content).__contains__(cve))

r = GET(path + "?for=" + userName)
assertEqual("Get components for this user", r, r.status_code == 200)
assertEqual("User is present", r, str(r.content).__contains__(userName))

# Notifications
p("Notifications")

path = "notifications"

r = GET(path)
assertEqual("Get Notifications", r, r.status_code == 200)

r = GET(path + "?for=" + userName)
assertEqual("Get Notifications for user", r, r.status_code == 200)
assertEqual(cve + " is present", r, str(r.content).__contains__(cve))

r = GET(path + "?cve_id=" + cve)
assertEqual("Get Notification for cve", r, r.status_code == 200)
assertEqual(cve + " is present", r, str(r.content).__contains__(cve))

cvssBase = r.json()[0].get("cvss_base")
link = r.json()[0].get("link")

r = GET(path + "?cvss_base=" + cvssBase)
assertEqual("Get Notification for cvss", r, r.status_code == 200)
assertEqual("Get for cvss_base " + cvssBase, r, str(r.content).__contains__(cvssBase))

r = GET(path + "?link=" + link)
assertEqual("Get Notification for link", r, r.status_code == 200)
assertEqual("Get for link " + link, r, str(r.content).__contains__(link))

r = GET(path + "?cve=false")
assertEqual("Get notifications without cves", r, r.status_code == 200)

r = DELETE("components/" + str(compId))
assertEqual("Delete component", r, r.status_code == 200)

resultVendor = {
    "name": "fail=" + str(assertEqual.counter)
}

r = POST(resultVendor, "vendors")
p("sent result")