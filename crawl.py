import os, shutil
import sys
import json
from pydriller import Repository
from git import Repo

ROOT = 'cvelistV5-main\cves'
SAMPLE = os.path.join(ROOT, "2023", "50xxx", "CVE-2023-50249.json")

print(SAMPLE)

def crawlCommit(path, commit_hash):
    res = {}
    local_path = os.path.join("tmp_dir", path.split('/')[-1])

    if not os.path.exists(local_path):
        os.makedirs(local_path)

    if len(os.listdir(local_path)) > 0:
        repo = Repo(local_path)
    else:
        repo = Repo.clone_from(path, local_path)
    
    c_time = repo.commit(commit_hash).authored_datetime.timestamp()

    patch = ""
    softver = ""
    for t in repo.tags:
        ct = t.commit

        if c_time >= ct.authored_datetime.timestamp():
            softver = str(t)
        else:
            patch = str(t)
            break
    
    repo = Repository(path, clone_repo_to= 'tmp_dir')
    for commit in repo.traverse_commits():
        # print(commit.hash)
        if commit.hash != commit_hash:
            continue
        for f in commit.modified_files:
           res[f.filename] = {
               'src':f.source_code, 
               'patched_version':patch, 
               'software_version':softver
            } 
        break

    return res

def parseCommit(url):
    nodes = url.split('/')
    path = []
    for node in nodes:
        if node == 'commit':
            break
        path.append(node)
    path = '/'.join(path)
    path += '.git'

    commit_hash = nodes[-1]
    dict = {
        "url" : url,
        "repo" : path,
        "hashcode" : commit_hash,
        "modified_files" : crawlCommit(path, commit_hash)
    }
    return dict

def parseMetrics(metrics):
    ks = metrics.keys()
    ks = sorted(ks, reverse= True)
    for k in ks:
        if k == 'other':
            continue
        # Pick the latest cvss version
        dict = {
            'scoreType' : k,
            'baseScore' : metrics[k]['baseScore'],
            'vectorString' : metrics[k]['vectorString']
        }
        return dict
    
    return None


def crawl_container(ctn):
    # Vulnerable source code & Patched version :
    container = {}

    # Crawling commits
    commits = []
    if 'references' in ctn.keys():
        for url_dict in ctn['references']:
            url = url_dict['url']
            if "https://github.com/" in url and "/commit/" in url:
                commits.append(parseCommit(url))
    container['commits'] = commits

    # Crawling metrics
    if 'metrics' in ctn.keys():
        metric_dict = parseMetrics(ctn['metrics'])
        if dict != None:
            container['metrics'] = metric_dict

    
        

def crawl(json_path):
    with open(json_path, 'r') as file:
        data = json.load(file)
        cna = data['containers']['cna']
        crawl_container(cna)
        file.close()

crawl(SAMPLE)