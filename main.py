from back import *

CVSS_Scores = []
CVSS_Best_Scores = {}
Count_of_vulns = {}
url = input("Sonar URL: ")
login = input("login: ")
password = input("password: ")

sonar_auth = requests.post(url + "/api/authentication/login",
                           data={"login": login, "password": password})

array_of_project_names = list(get_all_project_names(sonar_auth))
for i in array_of_project_names:
    get_all_files_and_CVSS_from_project(i[0], sonar_auth, CVSS_Scores)
    get_best_CVSS(CVSS_Scores, Count_of_vulns, CVSS_Best_Scores)
    xl_out(i[1], "CVSS.xlsx", CVSS_Best_Scores, Count_of_vulns)
    CVSS_Scores = []
    CVSS_Best_Scores = {}
    Count_of_vulns = {}