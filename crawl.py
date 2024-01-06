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
    local_path = os.path.join("tmp_dir", path.split('/')[-2], path.split('/')[-1])

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
    ks = len(metrics)
    ks = sorted(range(ks), key= lambda x:list(metrics[x].keys())[0])
    dict = []
    for k in ks:
        type_str = list(metrics[k].keys())[0]
        if type_str == 'other':
            continue
        dict.append({
            'scoreType' : k,
            'baseScore' : metrics[k][type_str]['baseScore'],
            'vectorString' : metrics[k][type_str]['vectorString']
        })
        return dict
    
    return None

def parseAffected(affected):
    res = []
    for product in affected:
        
        # Default status
        defaultStatus = 'unknown'
        if 'defaultStatus' in product.keys():
            defaultStatus = product['defaultStatus']

        # Product/Open source name
        aName = ""
        if 'packageName' in product.keys():
            aName = product['package']
        if 'product' in product.keys():
            aName = product['product']

        # Vendor/URL
        source = ""
        if 'vendor' in product.keys():
            source = product['vendor']
        if 'collectionURL' in product.keys():
            source = product['collectionURL']

        # Version windows, following CVE format
        pdict = {
            'defaultStatus' : defaultStatus,
            'name' : aName,
            'source' : source,
        }
        if 'versions' in product.keys():
            pdict['versions'] = product['versions']
        else:
            pdict['versions'] = None

        # Other attributes
        added_list = ['defaultStatus', 'packageName', 'product', 'vendor', 'collectionURL', 'versions']
        for k in product.keys():
            pdict[k] = product[k]

        res.append(pdict)
    
    return res


def crawl_container(ctn):
    container = {}

    # Crawling commits for vulnerable source code, patched version, software versions
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
        if metric_dict != None:
            container['metrics'] = metric_dict

    # Relevent exploit info: Crawling affected products
    if 'affected' in ctn.keys():
        affected_dict = parseAffected(ctn['affected'])
        container['affected'] = affected_dict

    return container
        

def crawl(json_path):
    formatted_data = {}
    with open(json_path, 'r') as file:
        data = json.load(file)
        cna = data['containers']['cna']
        formatted_data['cna'] = crawl_container(cna)
        if 'adp' in data['containers'].keys():
            adp = data['containers']['adp']
            formatted_data['adp'] = crawl_container(adp)
        file.close()

    with open('sample.json', 'w') as file:
        json.dump(formatted_data, file, indent= 2)
        file.close()

crawl(SAMPLE)