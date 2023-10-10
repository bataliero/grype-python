import json
import subprocess
from collections import namedtuple

p1 = subprocess.Popen(["dmesg"], stdout=subprocess.PIPE)
p2 = subprocess.Popen(["grep", "hda"], stdin=p1.stdout, stdout=subprocess.PIPE)
p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
output = p2.communicate()[0]

file = "sbom:a.sbom.cdx.json"
directory = "/home/fukjo/Documents/kube8/test123"
grype_command = ["grype", file, "--output", "json"]
# try:
proc = None
proc = subprocess.run(grype_command, cwd=directory, capture_output=True)
# print(json.loads(proc.sj"vulnerability"]tdout))
data = json.loads(proc.stdout)
# print()

Vulnerabily = namedtuple(
    'Student', ['name', 'severity', 'package', 'version', 'fix'])
vulnerabilites = []

# from dataclasses import dataclass

# @dataclass
# class PageDimensions:
#     width: int
#     height: int

for item in data["matches"]:
    vulne = item["vulnerability"]
    artifact = item["artifact"]

    # Vulnerabilies('Nandini', '19', '2541997')
    id = vulne["id"]
    fix = vulne["fix"]["state"]
    fix_version = vulne["fix"]["versions"]
    severity = vulne["severity"]
    # desc = vulne["description"]
    # desc = vulne["description", ""]
    "" 
    # print()
    if severity == "Negligible":  # and fix == 'wont-fix' or fix == "unknown":
        continue
    vulnerabilites.append(Vulnerabily(
        name=id, severity=severity, package=artifact["name"], version=artifact["version"], fix=fix_version))


def generate_output(vulnerabilities):
    print(*vulnerabilities, sep="\n")
    pass


generate_output(vulnerabilites)

# json_formatted_str = json.dumps(json_object, indent=2)

# print(json_formatted_str)
# print(proc.stdout)
# except Exception as e:
#     print("error")
# proc = subprocess.run(["ls","-l"])

# https://gitlab.com/tymonx/gitlab-ci/-/blob/master/templates/go/base.yml?ref_type=heads
# go_main


# print(str(output))


# te co da sie fixnac to trzeba fixnac
# jak sie nie da to skipowac
# w jaki sposob utworzyc liste supresses?
# jak jest unknow to olac

# odpalic to z github Actions!


# nie failowac jak sa jakies unknow (?)

# --only-fixed - jak sa takie to failowac!


want-fix ->  tez failowac bo pewnie w nastepnej wersji jest rzecz zalatana!

czy pojawil sie nowy blad (diff robi?) - po co mi diff?

gdzie zapisac state?
jaka nastapila zmiana (czy zmiana bedzie failowac teraz system?)

jest ignore file (tam mozna )
mozna tez database nieudapteowac

https://www.howtogeek.com/devops/how-to-find-vulnerabilities-in-containers-and-files-with-grype/

# jak dystrbuowac ignorefile (w pipeline moze da sie zapisac) -> tymon jakos to robi
# po prostu ma zdefiniowany w YAML (ale moze da sie to jakos lepiej zrobic) - wtedy tylko nie bedzie sie dalo rekonfigurwac
# ale jako zmienna mozna przekazac plik