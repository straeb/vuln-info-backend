import itertools
import json
import requests
import random, string
from colorama import Fore


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


def POST(obj, path, header):
    print(Fore.WHITE, "POST: " + baseUrl + path)
    return requests.post(baseUrl + path, json.dumps(obj), headers=header)


def GET(path, header):
    print(Fore.WHITE, "GET: " + baseUrl + path)
    return requests.get(baseUrl + path, headers=header)


def PATCH(obj, path, header):
    print(Fore.WHITE, "PATCH: " + baseUrl + path)
    return requests.patch(baseUrl + path, json.dumps(obj), headers=header)


def DELETE(path, header):
    print(Fore.WHITE, "DELETE: " + baseUrl + path)
    return requests.delete(baseUrl + path, headers=header)


# Auth
## Signup

p("Authorisation")
path = "auth/signup"

user1 = randomUser()
user2 = randomUser()

r = POST(user1, path, headers)
assertEqual("sign up user 1", r, r.status_code == 200)

userName1 = r.json().get('e_mail')

r = POST(user2, path, headers)
assertEqual("sign up user 2", r, r.status_code == 200)

userName2 = r.json().get('e_mail')


## Login
path = "auth/login"
r = POST(user1, path, headers)
assertEqual("login user1", r, r.status_code == 200)
token1 = r.json().get('token')

r = POST(user2, path, headers)
assertEqual("login user2", r, r.status_code == 200)
token2 = r.json().get('token')


token1 = "Bearer " + token1
token2 = "Bearer " + token2

headers1 = {'Content-type': 'application/json', 'Accept': 'text/plain', 'Authorization': token1}
headers2 = {'Content-type': 'application/json', 'Accept': 'text/plain', 'Authorization': token2}

# vendors
p("Vendors")
## Create
path = "vendors"

vendor1 = {
    "name": "Apache Software Foundation"
}

r = POST(vendor1, path, headers1)
id1 = r.json().get("id")
assertEqual("Create Vendor 1", r, r.status_code == 200)


vendor2 = {
    "name": "Free RDP"
}

r = POST(vendor2, path, headers1)
id2 = r.json().get("id")
assertEqual("Create Vendor 2", r, r.status_code == 200)


vendor3 = {
    "name": "Microsoft"
}

r = POST(vendor3, path, headers1)
id3 = r.json().get("id")
assertEqual("Create Vendor 3", r, r.status_code == 200)


vendor4 = {
    "name": "Fedora Project"
}

r = POST(vendor4, path, headers1)
id4 = r.json().get("id")
assertEqual("Create Vendor 4", r, r.status_code == 200)

p("Components")
## create
path = "components"

component1 = {
    "cpe": "cpe:2.3:a:apache:log4j:2.11.2:-:*:*:*:*:*:*",
    "name": "Log4j",
    "vendorId": id1,
    "version": "2.11.2"
}

r = POST(component1, path, headers2)
assertEqual("Create Component 1", r, r.status_code == 200)

r = POST(" ", path + "/1/subscribe?user=" + userName1, headers1)
assertEqual("subscribe User 1 to component 1", r, r.status_code == 200)


component2 = {
    "cpe": "cpe:2.3:a:freerdp:freerdp:2.1.2:*:*:*:*:*:*:*",
    "name": "FreeRDP",
    "vendorId": id2,
    "version": "2.1.2"
}
r = POST(component2, path, headers2)
assertEqual("Create Component 2", r, r.status_code == 200)

r = POST(" ", path + "/2/subscribe?user=" + userName1, headers1)
assertEqual("subscribe User 1 to component 2", r, r.status_code == 200)



component3 = {
    "cpe": "cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:x64:*",
    "name": "Windows",
    "vendorId": id3,
    "version": "11"
}
r = POST(component3, path, headers2)
assertEqual("Create Component 3", r, r.status_code == 200)

r = POST(" ", path + "/3/subscribe?user=" + userName1, headers1)
assertEqual("subscribe User 1 to component 3", r, r.status_code == 200)

component4 = {
    "cpe": "cpe:2.3:o:fedoraproject:fedora:35:*:*:*:*:*:*:*",
    "name": "Fedora",
    "vendorId": id4,
    "version": "35"
}
r = POST(component4, path, headers2)
assertEqual("Create Component 4", r, r.status_code == 200)

r = POST(" ", path + "/4/subscribe?user=" + userName1, headers1)
assertEqual("subscribe User 1 to component 4", r, r.status_code == 200)
r = POST(" ", path + "/4/subscribe?user=" + userName2, headers2)
assertEqual("subscribe User 2 to component 4", r, r.status_code == 200)


component5 = {
    "cpe": "cpe:2.3:o:fedoraproject:fedora:36:*:*:*:*:*:*:*",
    "name": "Fedora",
    "vendorId": id4,
    "version": "36"
}
r = POST(component5, path, headers2)
assertEqual("Create Component 5", r, r.status_code == 200)
r = POST(" ", path + "/5/subscribe?user=" + userName2, headers2)
assertEqual("subscribe User 2 to component 5", r, r.status_code == 200)


r = POST(" ", "config/match?from=0&to=-300", headers1)
assertEqual("run cpe match", r, r.status_code == 200)

log4J= "CVE-2021-44228"
freerdp1 = "CVE-2021-41159"
freerdp2 = "CVE-2021-41160"
windows = "CVE-2022-21907"

r = GET(path + "/1/vulnerabilities", headers2)
assertEqual("Get vulnerabilities for component 1: Log4j 2.11.2", r, r.status_code == 200)
assertEqual("Contains " + log4J, r, str(r.content).__contains__(log4J))
assertEqual("Contains " + freerdp1, r, str(r.content).__contains__(freerdp1))
assertEqual("Contains " + freerdp2, r, str(r.content).__contains__(freerdp2))
assertEqual("Contains " + windows, r, str(r.content).__contains__(windows))

r = GET(path + "/2/vulnerabilities", headers1)
assertEqual("Get vulnerabilities for component 2: FreeRDP 2.1.2", r, r.status_code == 200)
assertEqual("Contains " + log4J, r, str(r.content).__contains__(log4J))
assertEqual("Contains " + freerdp1, r, str(r.content).__contains__(freerdp1))
assertEqual("Contains " + freerdp2, r, str(r.content).__contains__(freerdp2))
assertEqual("Contains " + windows, r, str(r.content).__contains__(windows))

r = GET(path + "/3/vulnerabilities", headers2)
assertEqual("Get vulnerabilities for component 3: Windows 11", r, r.status_code == 200)
assertEqual("Contains " + log4J, r, str(r.content).__contains__(log4J))
assertEqual("Contains " + freerdp1, r, str(r.content).__contains__(freerdp1))
assertEqual("Contains " + freerdp2, r, str(r.content).__contains__(freerdp2))
assertEqual("Contains " + windows, r, str(r.content).__contains__(windows))

r = GET(path + "/4/vulnerabilities", headers1)
assertEqual("Get vulnerabilities for component 4: Fedora 34", r, r.status_code == 200)
assertEqual("Contains " + log4J, r, str(r.content).__contains__(log4J))
assertEqual("Contains " + freerdp1, r, str(r.content).__contains__(freerdp1))
assertEqual("Contains " + freerdp2, r, str(r.content).__contains__(freerdp2))
assertEqual("Contains " + windows, r, str(r.content).__contains__(windows))

r = GET(path + "/5/vulnerabilities", headers2)
assertEqual("Get vulnerabilities for component 5: Fedora 36", r, r.status_code == 200)
assertEqual("Contains " + log4J, r, str(r.content).__contains__(log4J))
assertEqual("Contains " + freerdp1, r, str(r.content).__contains__(freerdp1))
assertEqual("Contains " + freerdp2, r, str(r.content).__contains__(freerdp2))
assertEqual("Contains " + windows, r, str(r.content).__contains__(windows))


# Notifications
p("Notifications")

path = "notifications"

r = GET(path + "?for=" + userName1, headers1)
assertEqual("Get Notifications for user1", r, r.status_code == 200)
assertEqual("Contains " + log4J, r, str(r.content).__contains__(log4J))
assertEqual("Contains " + freerdp1, r, str(r.content).__contains__(freerdp1))
assertEqual("Contains " + freerdp2, r, str(r.content).__contains__(freerdp2))
assertEqual("Contains " + windows, r, str(r.content).__contains__(windows))

r = GET(path + "?for=" + userName2, headers2)
assertEqual("Get Notifications for user2", r, r.status_code == 200)
assertEqual("Contains " + log4J, r, str(r.content).__contains__(log4J))
assertEqual("Contains " + freerdp1, r, str(r.content).__contains__(freerdp1))
assertEqual("Contains " + freerdp2, r, str(r.content).__contains__(freerdp2))
assertEqual("Contains " + windows, r, str(r.content).__contains__(windows))


r = GET(path + "?cve_id=" + freerdp1, headers1)
assertEqual("Get Notification for " + freerdp1, r, r.status_code == 200)

title1 = r.json()[0].get("title")
expect1 = "FreeRDP"
assertEqual("Notification Title is 'FreeRDP' ", title1 == expect1)

r = GET(path + "?cve_id=" + freerdp2, headers1)
assertEqual("Get Notifications for " + freerdp2, r, r.status_code == 200)

title1 = r.json()[0].get("title")
title2 = r.json()[1].get("title")
expect1 = "FreeRDP"
expect2 = "FreeRDP + Log4j"
assertEqual("Notification 1 Title is 'FreeRDP' ", title1 == expect1)
assertEqual("Notification 2 Title is 'FreeRDP + Log4j' ", title2 == expect2)

r = GET(path + "?cve_id=" + windows, headers1)
assertEqual("Get Notifications for " + windows, r, r.status_code == 200)

title1 = r.json()[0].get("title")
expect1 = "Windows CVE-2022-21907"
assertEqual("Notification 1 Title is 'Windows CVE-2022-21907' ", title1 == expect1)


resultVendor = {
    "name": "fail=" + str(assertEqual.counter)
}

r = POST(resultVendor, "vendors", headers1)
p("sent result")