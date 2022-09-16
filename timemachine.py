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
import sys

secret_regex = '^.*access_key.*$|^.*user.*$|^.*key.*$|^.*s3.*$|[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+){2,5}|' \
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
               '^.*(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}.*$|^.*password.*$|^.*secret.*$|^.*secret_key.*$'

rgx = re.compile(secret_regex.encode('unicode-escape').decode())

emailx = re.compile(
    r'[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)')

secrets = re.compile(r'^.*access_key.*$|^.*secret_key.*$')

list_of_emails = []
list_of_keys = []


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
                for mail in emails:
                    with open(f'hunts\\xcir\\libvmod-awsrest\\emails.txt', 'a+', encoding="utf-8") as a:
                        a.writelines(mail+'\n')
                    a.close()

            if access_keys:
                for key in access_keys:
                    with open(f'hunts\\xcir\\libvmod-awsrest\\keys.txt', 'a+', encoding="utf-8") as a:
                        a.writelines(key+'\n')
                    a.close()
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
                    # print(f"{commit_id} | [-] " + step3_ + '\n')
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
                    # print(f"{commit_id} | [+] " + step6_ + '\n')
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


def main(search:str):
    queue = Queue()
    tm = GitTimeMachine()

    parameter = 'xcir/libvmod-awsrest'
    par = str(search).split('/')
    user = par[0]
    repo = par[1]
    tm.create_folders(user, repo)

    for b in range(10):
        worker = TimeMachineWorker(queue)
        worker.daemon = True
        worker.start()

    branches = tm.get_branches(search)
    for branch in branches:
        print(f'###################### Branch {branch} ##########################################\n')
        pages = tm.find_extra_pages(
            f'https://github.com/{user}/{repo}/commits/{branch}', branch)
        n_pages = 0
        for page in pages:
            n_pages += 1
            print(f'[---------------------------Page {n_pages} -----------------------------]\n')
            queue.put((page, search, branch))
            queue.join()


if __name__ == '__main__':
    search = sys.argv[1]
    main(search)
    time.sleep(0.5)
