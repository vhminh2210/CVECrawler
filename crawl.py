import os, shutil
import sys
import json
from pydriller import Repository
from git import Repo

ROOT = 'cvelistV5-main\cves'
SAMPLE = os.path.join(ROOT, "2023", "50xxx", "CVE-2023-50249.json")

print(SAMPLE)

def is_commit_after(repo, commit_hash1, commit_hash2):
    try:
        # Run git command to check if commit2 is an ancestor of commit1
        is_after = repo.git.merge_base(commit_hash1, commit_hash2) == commit_hash2

        return is_after

    except Exception as e:
        print(f"Error checking commit order: {e}")
        return None

def get_commit_code(path, commit_hash):
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
    for t in repo.tags:
        ct = t.commit

        if c_time >= ct.authored_datetime.timestamp():
            patch = t
        else:
            patch = t
            break
    
    repo = Repository(path, clone_repo_to= 'tmp_dir')
    for commit in repo.traverse_commits():
        # print(commit.hash)
        if commit.hash != commit_hash:
            continue
        for f in commit.modified_files:
           res[f.filename] = {'src':f.source_code, 'patched_version':patch} 
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
    print(path)

    commit_hash = nodes[-1]
    print(commit_hash)

    dict = get_commit_code(path, commit_hash)
    for k in dict.keys():
        print(dict[k]['patched_version'])

def crawl_container(ctn):
    # Vulnerable source code & Patched version :
    if 'references' in ctn.keys():
        for url_dict in ctn['references']:
            url = url_dict['url']
            if "https://github.com/" in url and "/commit/" in url:
                parseCommit(url)


def crawl(json_path):
    with open(json_path, 'r') as file:
        data = json.load(file)
        cna = data['containers']['cna']
        crawl_container(cna)
        file.close()

crawl(SAMPLE)