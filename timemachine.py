# -*- coding: utf-8 -*-
import requests
import configparser
from bs4 import BeautifulSoup
import re
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
config = configparser.RawConfigParser()
config.read('conf.ini')
import os
from pathlib import Path
from queue import Queue
from threading import Thread
import ftfy
import yaml

# with open('signatures.yaml', 'r') as file:
#     signatures = yaml.safe_load(file)
#
# siglist = ""
# for sign in signatures['signatures']:
#     x = ''
#     try:
#         x = sign['match']
#     except:
#         x = sign['regex']
#     # print(f"^.*{x}.*$|")
#     siglist+=f"|^.*{x}.*$"

regex = '^.*access.*$|^.*user.*$|^.*key.*$|^.*s3.*$|[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+){2,5}|' \
        '^.*Authorization.*$|^.*settings.*$|^.*Base64.*$|^.*.ini.*$|^.*.log.*$|^.*cscfg.*$|^.*rdp.*$|^.*mdf.*$|' \
        '^.*sdf.*$|^.*sqlite.*$|^.*credential.*$|^.*s3cfg.*$|^.*aws/credentials.*$|^.*htpasswd.*$|^.*docker.*$|^.*session.*$|' \
        '^.*token.*$|^.*account.*$|^.*googleusercontent.*$|^.*.pem.*$|^.*.log.*$|^.*.pkcs12.*$|^.*.p12.*$|^.*.pfx.*$|^.*.asc.*$|' \
        '^.*otr.private_key.*$|^.*.ovpn.*$|^.*.cscfg.*$|^.*.rdp.*$|^.*.mdf.*$|^.*.sdf.*$|^.*.sqlite.*$|' \
        '^.*.bek.*$|^.*.tpm.*$|^.*.fve.*$|^.*.jks.*$|^.*.psafe3.*$|^.*secret_token.rb.*$|^.*.rb.*$|' \
        '^.*.yml.*$|^.*settings.py.*$|^.*.agilekeychain.*$|^.*.keychain.*$|^.*.pcap.*$|' \
        '^.*.gnucash.*$|' \
        '^.*.kwallet.*$|^.*LocalSettings.php.*$|^.*.tblk.*$|^.*Favorites.plist.*$|^.*.xpl.*$|' \
        '^.*.dayone.*$|^.*journal.txt.*$|^.*.rb.*$|^.*proftpdpasswd.*$|^.*.json.*$|^.*.xml.*$|' \
        '^.*recentservers.xml.*$|^.*terraform.tfvars.*$|^.*.exports.*$|^.*.functions.*$|' \
        '^.*.extra.*$|^.*^.*_rsa$.*$|^.*^.*_dsa$.*$|^.*^.*_ed25519$.*$|^.*^.*_ecdsa$.*$|^.*\.?ssh/config$.*$|' \
        '^.*^key(pair)?$.*$|^.*^\.?(bash_|zsh_|sh_|z)?history$.*$|^.*^\.?mysql_history$.*$|^.*^\.?psql_history$.*$|' \
        '^.*^\.?pgpass$.*$|^.*^\.?irb_history$.*$|^.*\.?purple/accounts\.xml$.*$|^.*\.?xchat2?/servlist_?\.conf$.*$|' \
        '^.*\.?irssi/config$.*$|^.*\.?recon-ng/keys\.db$.*$|^.*^\.?dbeaver-data-sources.xml$.*$|^.*^\.?muttrc$.*$|' \
        '^.*^\.?s3cfg$.*$|^.*\.?aws/credentials$.*$|^.*^sftp-config(\.json)?$.*$|^.*^\.?trc$.*$|^.*^\.?(bash|zsh|csh)rc$.*$|' \
        '^.*^\.?(bash_|zsh_)?profile$.*$|^.*^\.?(bash_|zsh_)?aliases$.*$|^.*config(\.inc)?\.php$.*$|^.*^key(store|ring)$.*$|' \
        '^.*^kdbx?$.*$|^.*^sql(dump)?$.*$|^.*^\.?htpasswd$.*$|^.*^(\.|_)?netrc$.*$|^.*\.?gem/credentials$.*$|^.*^\.?tugboat$.*$|' \
        '^.*doctl/config.yaml$.*$|^.*^\.?git-credentials$.*$|^.*config/hub$.*$|^.*^\.?gitconfig$.*$|^.*\.?chef/(.*)\.pem$.*$|' \
        '^.*etc/shadow$.*$|^.*etc/passwd$.*$|^.*^\.?dockercfg$.*$|^.*^\.?npmrc$.*$|^.*^\.?env$.*$|' \
        '^.*(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}.*$|^.*password.*$|^.*secret.*$'

#todo
problem =   '^.*((\"|\'|`)?((?i)aws)?_?((?i)access)_?((?i)key)?_?((?i)id)?(\"|\'|`)?\\s{0,50}(:|=>|=)\\s{0,50}(\"|\'|`)?(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\"|\'|`)?).*$|' \
        '^.*((\"|\'|`)?((?i)aws)?_?((?i)account)_?((?i)id)?(\"|\'|`)?\\s{0,50}(:|=>|=)\\s{0,50}(\"|\'|`)?[0-9]{4}-?[0-9]{4}-?[0-9]{4}(\"|\'|`)?).*$|' \
        '^.*((\"|\'|`)?((?i)aws)?_?((?i)secret)_?((?i)access)?_?((?i)key)?_?((?i)id)?(\"|\'|`)?\\s{0,50}(:|=>|=)\\s{0,50}(\"|\'|`)?[A-Za-z0-9/+=]{40}(\"|\'|`)?).*$|^.*((\"|\'|`)?((?i)aws)?_?((?i)session)?_?((?i)token)?(\"|\'|`)?\\s{0,50}(:|=>|=)\\s{0,50}(\"|\'|`)?[A-Za-z0-9/+=]{16,}(\"|\'|`)?).*$|^.*(?i)artifactory.{0,50}(\"|\'|`)?[a-zA-Z0-9=]{112}(\"|\'|`)?.*$|^.*(?i)codeclima.{0,50}(\"|\'|`)?[0-9a-f]{64}(\"|\'|`)?.*$|^.*EAACEdEose0cBA[0-9A-Za-z]+.*$|^.*((\"|\'|`)?type(\"|\'|`)?\\s{0,50}(:|=>|=)\\s{0,50}(\"|\'|`)?service_account(\"|\'|`)?,?).*$|^.*(?:r|s)k_[live|test]_[0-9a-zA-Z]{24}.*$|^.*[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com.*$|^.*AIza[0-9A-Za-z\\-_]{35}.*$|^.*ya29\\.[0-9A-Za-z\\-_]+.*$|^.*sk_[live|test]_[0-9a-z]{32}.*$|^.*sq0atp-[0-9A-Za-z\-_]{22}.*$|^.*sq0csp-[0-9A-Za-z\-_]{43}.*$|^.*access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}.*$|^.*amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}.*$|^.*SK[0-9a-fA-F]{32}.*$|^.*SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}.*$|^.*key-[0-9a-zA-Z]{32}.*$|^.*[0-9a-f]{32}-us[0-9]{12}.*$|^.*sshpass -p.*[\'|\"].*$|^.*(https\\://outlook\\.office.com/webhook/[0-9a-f-]{36}\\@).*$|^.*(?i)sauce.{0,50}(\"|\'|`)?[0-9a-f-]{36}(\"|\'|`)?.*$|^.*(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}).*$|^.*https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}.*$|^.*(?i)sonar.{0,50}(\"|\'|`)?[0-9a-f]{40}(\"|\'|`)?.*$|^.*(?i)hockey.{0,50}(\"|\'|`)?[0-9a-f]{32}(\"|\'|`)?.*$|^.*([\w+]{1,24})(://)([^$<]{1})([^\s";]{1,}):([^$<]{1})([^\s";/]{1,})@[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,24}([^\s]+).*$|^.*oy2[a-z0-9]{43}.*$|^.*hawk\.[0-9A-Za-z\-_]{20}\.[0-9A-Za-z\-_]{20}.*$|^.*.ppk.*$|^.*heroku.json.*$|^.*.sqldump.*$|^.*dump.sql.*$|^.*id_rsa_pub.*$|^.*mongoid.yml.*$|^.*salesforce.js.*$|^.*.netrc.*$|^.*.remote-sync.json$.*$|^.*.esmtprc$.*$|^.*^deployment-config.json?$.*$|^.*.ftpconfig$.*$|^.*-----BEGIN (EC|RSA|DSA|OPENSSH|PGP) PRIVATE KEY.*$|^.*define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?[\'|"].{10,120}[\'|\"].*$|^.*(?i)(aws_access_key_id|aws_secret_access_key)(.{0,20})?=.[0-9a-zA-Z\/+]{20,40}.*$|^.*(?i)(facebook|fb)(.{0,20})?(?-i)[\'\"][0-9a-f]{32}[\'\"].*$|^.*(?i)(facebook|fb)(.{0,20})?[\'\"][0-9]{13,17}[\'\"].*$|^.*(?i)twitter(.{0,20})?[\'\"][0-9a-z]{35,44}[\'\"].*$|^.*(?i)twitter(.{0,20})?[\'\"][0-9a-z]{18,25}[\'\"].*$|^.*(?i)github(.{0,20})?(?-i)[\'\"][0-9a-zA-Z]{35,40}[\'\"].*$|^.*(?i)heroku(.{0,20})?[\'\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\'\"].*$|^.*(?i)linkedin(.{0,20})?(?-i)[\'\"][0-9a-z]{12}[\'\"].*$|^.*(?i)linkedin(.{0,20})?[\'\"][0-9a-z]{16}[\'\"].*$|^.*\.?idea[\\\/]WebServers.xml$.*$|^.*\.?vscode[\\\/]sftp.json$.*$|^.*web[\\\/]ruby[\\\/]secrets.yml.*$|^.*\.?docker[\\\/]config.json$.*$|^.*ruby[\\\/]config[\\\/]master.key$.*$|^.*\.?mozilla[\\\/]firefox[\\\/]logins.json$.*$'


rgx = re.compile(regex.encode('unicode-escape').decode())

emailx = re.compile(
    r'[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)')

secrets = re.compile(r'^.*access_key.*$|^.*secret_key.*$')



list_of_emails = set()
list_of_keys = set()
loot_bag_zip = set()
class GitTimeMachine():
    def __init__(self):
        self.list_of_pages = []

    def get_raw_url(self, user: str, repo: str, branch: str, filename: str):
        return requests.get(f'https://raw.githubusercontent.com/{user}/{repo}/{branch}/{filename}').text

    def matching(self, str1: str):
        try:
            ret = re.search(rgx, ftfy.fix_encoding(str1))
            emails = re.findall(emailx, ftfy.fix_encoding(str1))
            access_keys = re.findall(secrets, str1)
            if emails:
               list_of_emails.add(emails)
            if access_keys:
                list_of_keys.add(access_keys)
            return ret.group()
        except:
            pass

    def get_branches(self, parameters: str):
        par = str(parameters).split('/')
        user = par[0]
        repo = par[1]
        ret = requests.get(f'https://github.com/{user}/{repo}/branches/all', verify=False)
        soup = BeautifulSoup(ret.content, 'html.parser')
        branches_s = soup.findAll(
            class_='branch-name css-truncate-target v-align-baseline width-fit mr-2 Details-content--shown')
        branches_n = []
        for b in branches_s:
            branches_n.append(f'{b.text}')
        print(f'Branches found {repo}: {branches_n}')
        return branches_n

    # def search_main(self, parameters, query: str):
    #     par = str(parameters).split('/')
    #     user = par[0]
    #     repo = par[1]
    #     s = f'https://github.com/{user}/{repo}/search?q={query}'
    #     ret = requests.get(s, verify=False)
    #     soup = BeautifulSoup(ret.content, 'html.parser')
    #     blocks = soup.findAll(class_='code-list')
    #     return blocks
    #
    def find_extra_pages(self, url: str, branch: str):
        self.list_of_pages.append(url)
        ret = requests.get(url, verify=False, headers={
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'})
        soup = BeautifulSoup(ret.content, 'html.parser')
        next_page = soup.findAll('a', {'href': re.compile(r'after=')})
        if len(next_page) > 0:
            link = re.search(r'href="(.*?)"', str(next_page[0])).groups(1)
            if link[0]:
                self.list_of_pages.append(link[0])
                return self.find_extra_pages(link[0], branch)

        dedup = list(dict.fromkeys(self.list_of_pages))

        print(f'In {branch} found {len(dedup)} pages')
        self.list_of_pages = []
        return dedup

    def create_folders(self, user, repo):
        print(f'creating folder .. hunts/{user}/{repo}')
        if not os.path.exists('hunts'):
            Path('hunts').mkdir()
        path = Path.cwd() / r'hunts' / f'{user}' / repo
        path.mkdir(parents=True, exist_ok=True)

    def check_commits(self, page, parameters, branch: str):
        print(f"checking:", parameters, branch, page)
        par = str(parameters).split('/')
        user = par[0]
        repo = par[1]
        branch_ = re.sub(r'[^a-zA-Z0-9 \n\.]', '', branch)

        s = f'{page}'
        ret = requests.get(s, verify=False, headers={
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'})

        soup = BeautifulSoup(ret.content, 'html.parser')

        commits = soup.findAll('a', {'class': 'tooltipped tooltipped-sw btn-outline btn BtnGroup-item text-mono f6'})
        pat1 = re.compile(r'<span (.*?)>')
        print(f'Found {len(commits)} commits')
        for commit in commits:
            regex = re.search('href=\"(.*?)\"', str(commit))
            commit_url = 'https://github.com' + regex.groups()[0]
            commit_id = commit_url.split('/')[6]
            commit_ret = requests.get(commit_url, verify=False, headers={
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'})

            commit_soup = BeautifulSoup(commit_ret.content, 'html.parser')

            removed_items = commit_soup.findAll('span', {"data-code-marker": "-"})
            added_items = commit_soup.findAll('span', {"data-code-marker": "+"})

            # print(f'Writing off {len(removed_items)} items which where removed')
            for item in removed_items:
                step1_ = str(item).replace(
                    '<span class="blob-code-inner blob-code-marker js-code-nav-pass js-skip-tagsearch" data-code-marker="-">',
                    '').replace('</span>', '')
                step2_ = re.sub(pat1, '', step1_)
                step3_ = re.sub('</span', '', step2_)

                if self.matching(step3_):
                    print(f"{commit_id} | [-] " + step3_ + '\n')
                    loot_bag_zip.add(step3_)
                    with open(f'hunts\{user}\{repo}\\lootbag', 'a+',
                              encoding="utf-8") as r:
                        r.writelines(f"{commit_id} | [-] " + step3_ + '\n')
                    r.close()

            # print(f'Writing off {len(added_items)} items which where added')
            for item in added_items:
                step4_ = str(item).replace(
                    '<span class="blob-code-inner blob-code-marker js-code-nav-pass js-skip-tagsearch" data-code-marker="-">',
                    '').replace('</span>', '')
                step5_ = re.sub(pat1, '', step4_)
                step6_ = re.sub('</span', '', step5_)
                if self.matching(step6_):
                    print(f"{commit_id} | [+] " + step6_ + '\n')
                    loot_bag_zip.add(step6_)
                    with open(f'hunts\{user}\{repo}\\lootbag', 'a+',
                              encoding="utf-8") as a:
                        a.writelines(f"{commit_id} | [+] " + step6_ + '\n')
                    a.close()



class TimeMachineWorker(Thread):

    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        tm = GitTimeMachine()
        while True:
            page, parameter, branch = self.queue.get()
            try:
                tm.check_commits(page, parameter, branch)
            finally:
                self.queue.task_done()


def main():
    queue = Queue()
    tm = GitTimeMachine()

    # inputs
    parameter = 'xcir/libvmod-awsrest'
    search = 'access_key'

    # todo implement Levenshtein distance in python
    # the Levenshtein distance is a string metric for measuring the difference between two sequences. Informally,
    # the Levenshtein distance between two words is the minimum number of single-character edits (insertions, deletions
    # or substitutions) required to change one word into the other.

    # todo Cosine similarity is a measure of similarity between two non-zero vectors of an inner
    # product space that measures the cosine of the angle between them.

    par = str(parameter).split('/')
    user = par[0]
    repo = par[1]

    for b in range(35):
        worker = TimeMachineWorker(queue)
        worker.daemon = True
        worker.start()

    branches = tm.get_branches(parameter)
    for branch in branches:
        print(f'###################### Branch {branch} ##########################################\n')
        branch_ = re.sub(r'[^a-zA-Z0-9 \n\.]', '', branch)
        tm.create_folders(user, repo)
        pages = tm.find_extra_pages(
            f'https://github.com/{user}/{repo}/commits/{branch}', branch)

        n_pages = 0
        for page in pages:
            n_pages += 1
            print(f'[---------------------------Page {n_pages} -----------------------------]\n')
            queue.put((page, parameter, branch))
            queue.join()


    with open(f'hunts\\xcir\\libvmod-awsrest\\emails', 'a+', encoding="utf-8") as a:
        a.writelines(list_of_emails)
    a.close()

    with open(f'hunts\\xcir\\libvmod-awsrest\\keys', 'a+', encoding="utf-8") as a:
        a.writelines(list_of_keys)
    a.close()

    with open(f'hunts\\xcir\\libvmod-awsrest\\lootbag_zip', 'a+', encoding="utf-8") as a:
        a.writelines(loot_bag_zip)
    a.close()

if __name__ == '__main__':
    main()
    time.sleep(5)
