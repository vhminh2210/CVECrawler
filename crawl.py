import os, shutil
import sys
import json
from pydriller import Repository
from git import Repo

ROOT = 'cvelistV5-main\cves'
SAMPLE = os.path.join(ROOT, "2023", "50xxx", "CVE-2023-50249.json")

def chmod_recursive(path, mode):
    # Code from ChatGPT
    os.chmod(path, mode)
    for root, dirs, files in os.walk(path):
        os.chmod(root, mode)
        for directory in dirs:
            dir_path = os.path.join(root, directory)
            os.chmod(dir_path, mode)
        for file in files:
            file_path = os.path.join(root, file)
            os.chmod(file_path, mode)

def crawlCommit(path, commit_hash, tmp_dir='tmp_dir'):
    res = {}
    local_path = os.path.join(tmp_dir, path.split('/')[-2], path.split('/')[-1])

    if not os.path.exists(local_path):
        os.makedirs(local_path)

    if len(os.listdir(local_path)) > 0:
        repo = Repo(local_path)
    else:
        repo = Repo.clone_from(path, local_path)
    
    c_time = repo.commit(commit_hash).authored_date

    patch = "N/A"
    softver = "N/A"
    for t in repo.tags:
        try:
            # If t is a non-commit object
            ct = t.object.tagged_date
        except:
            # If t is a commit object
            ct = t.commit.authored_date

        if c_time >= ct:
            softver = str(t)
        else:
            patch = str(t)
            break
    
    repo = Repository(local_path)
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

def parseCommit(url, tmp_dir='tmp_dir'):
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
        "modified_files" : crawlCommit(path, commit_hash, tmp_dir)
    }
    return dict

def parseMetrics(metrics):
    ks = len(metrics)
    ks = sorted(range(ks), key= lambda x:list(metrics[x].keys())[0])
    dict = []
    for k in ks:
        type_str = list(metrics[k].keys())[0]
        if type_str not in ['cvssV3_1', 'cvssV3_0', 'cvssV2_0']:
            continue
        dict.append({
            'scoreType' : list(metrics[k].keys())[0],
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
            aName = product['packageName']
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
            if k in added_list:
                continue
            pdict[k] = product[k]

        res.append(pdict)
    
    return res


def crawl_container(ctn, tmp_dir='tmp_dir'):
    
    container = {}

    # Crawling header
    if 'title' in ctn.keys():
        container['title'] = ctn['title']
    else:
        container['title'] = 'N/A'

    container['descriptions'] = []
    if ('descriptions' not in ctn.keys()) or (len(ctn['descriptions']) == 0):
        container['descriptions'].append({
            'lang' : 'N/A',
            'value' : 'N/A'
        })
    else:
        for i in range(len(ctn['descriptions'])):
            container['descriptions'].append({
                'lang' : ctn['descriptions'][i]['lang'],
                'value' : ctn['descriptions'][i]['value']
            })

    # Crawling metadata:
    container['metadata'] = {}
    container['metadata']['orgId'] = ctn['providerMetadata']['orgId']

    if 'dateUpdated' in ctn['providerMetadata'].keys():
        container['metadata']['dateUpdated'] = ctn['providerMetadata']['dateUpdated']
    else:
        container['metadata']['dateUpdated'] = 'N/A'

    if 'dateAssigned' in ctn.keys():
        container['metadata']['dateAssigned'] = ctn['dateAssigned']
    else:
        container['metadata']['dateAssigned'] = 'N/A'

    if 'datePublic' in ctn.keys():
        container['metadata']['datePublic'] = ctn['datePublic']
    else:
        container['metadata']['datePublic'] = 'N/A'

    # Crawling impacts
    container['impacts'] = []
    if ('impacts' not in ctn.keys()) or (len(ctn['impacts']) == 0):
        container['impacts'].append({
            'capecId' : 'N/A',
            'descriptions' : {
                'lang' : 'N/A',
                'value' : 'N/A'
            }
        })
    else:
        for i in range(len(ctn['impacts'])):
            tmp = 'N/A'
            if 'capecId' in ctn['impacts'][i].keys():
                tmp = ctn['impacts'][i]['capecId']
            tmp_vec = []
            for j in range(len(ctn['impacts'][i]['descriptions'])):
                tmp_vec.append({
                    'lang' : ctn['impacts'][i]['descriptions'][j]['lang'],
                    'value' : ctn['impacts'][i]['descriptions'][j]['value']
                })
            container['impacts'].append({
                'capecId' : tmp,
                'descriptions' : tmp_vec
            })

    # Crawling solutions
    if 'solutions' not in ctn.keys():
        container['solutions'] = [{
        'lang' : 'N/A',
        'value' : 'N/A'
    }]

    else:
        container['solutions'] = []
        for i in range(len(ctn['solutions'])):
            container['solutions'].append({
                'lang' : ctn['solutions'][i]['lang'],
                'value' : ctn['solutions'][i]['value']
            })

    # Crawling commits for vulnerable source code, patched version, software versions
    commits = []
    if 'references' in ctn.keys():
        for url_dict in ctn['references']:
            url = url_dict['url']
            if "https://github.com/" in url and "/commit/" in url:
                commits.append(parseCommit(url, tmp_dir))
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
        
def crawlPath(json_path, out_dir='data', out_file='data.json'):
    formatted_data = {}
    with open(json_path, 'r', encoding= 'utf8') as file:
        data = json.load(file)

        # Check published status. REJECTED records are NOT crawled
        if data['cveMetadata']['state'] == 'REJECTED':
            file.close()
            return "", ""
        
        # metadata crawling
        formatted_data['cveMetadata'] = {}
        formatted_data['cveMetadata']['cveId'] = data['cveMetadata']['cveId']
        formatted_data['cveMetadata']['assignerOrgId'] = data['cveMetadata']['assignerOrgId']
        if 'dateUpdated' in data['cveMetadata'].keys():
            formatted_data['cveMetadata']['dateUpdated'] = data['cveMetadata']['dateUpdated']
        else:
            formatted_data['cveMetadata']['dateUpdated'] = 'N/A'
        if 'datePublished' in data['cveMetadata'].keys():
            formatted_data['cveMetadata']['datePublished'] = data['cveMetadata']['datePublished']
        else:
            formatted_data['cveMetadata']['datePublished'] = 'N/A'

        cna = data['containers']['cna']
        formatted_data['cna'] = crawl_container(cna)
        if 'adp' in data['containers'].keys():
            adp = data['containers']['adp']
            formatted_data['adp'] = crawl_container(adp)
        file.close()

    return formatted_data['cveMetadata']['cveId'], formatted_data

class CVECrawler:
    def __init__(self, cve_dir, tmp_dir='tmp_dir', out_dir='data', out_file='data.json'):
        self.cve_dir = cve_dir
        self.tmp_dir = tmp_dir
        self.out_dir = out_dir
        self.out_file = out_file

    def clean(self):
        # print("Cleaning tmp_dir ...")
        # for subdir in os.listdir(self.tmp_dir):
        #     # chmod_recursive(os.path.join(self.tmp_dir, subdir), 0o777)
        #     os.system(f'chmod -R 777 {os.path.join(self.tmp_dir, subdir)}')
        #     shutil.rmtree(os.path.join(self.tmp_dir, subdir))
        pass

    def getCommitCount(self):
        cnt = 0
        nfiles = 0
        for root, _, files in os.walk(self.cve_dir):
            for file in files:
                file_path = os.path.join(root, file)
                nfiles += 1
                print(f"Investigating {file_path} ...")
                with open(file_path, 'r', encoding= 'utf8') as file:
                    data = json.load(file)

                    if data['cveMetadata']['state'] == 'REJECTED':
                        file.close()
                        continue

                ok = False
                ctn = data['containers']['cna']
                if 'references' in ctn.keys():
                    for url_dict in ctn['references']:
                        url = url_dict['url']
                        if "https://github.com/" in url and "/commit/" in url:
                            cnt += 1
                            ok = True
                            break
                if ok:
                    continue

                if 'adp' in data['containers'].keys():
                    ctn = data['containers']['adp']
                    if 'references' in ctn.keys():
                        for url_dict in ctn['references']:
                            url = url_dict['url']
                            if "https://github.com/" in url and "/commit/" in url:
                                cnt += 1
                                ok = True
                                break

        print(f"{cnt}/{nfiles} files has github commit data.")
    
    def crawl(self):
        cnt = 0
        err = 0
        patience = 0

        dirs = []
        att_dirs = []
        err_dirs = []
        new_data = {}
        if not os.path.exists(self.out_dir):
            os.mkdir(self.out_dir)

        dirs.append(self.cve_dir)
        if os.path.isdir(self.cve_dir):
            dirs.pop()
            for dir in os.listdir(self.cve_dir):
                dirs.append(os.path.join(self.cve_dir, dir))

        while len(dirs) > 0:
            # Cleaning tmp_dir every 20 json files crawled
            if patience == 20:
                self.clean()
                patience = 0
            
            dir = dirs[-1]
            dirs.pop()
            if os.path.isdir(dir):
                for subdir in os.listdir(dir):
                    dirs.append(os.path.join(dir, subdir))
            else:
                # json file found
                if(dir.split('.')[-1] == 'json'):
                    patience += 1
                    try:
                        print(f"Crawling through {dir}")
                        cveId, formatted_data = crawlPath(dir, self.out_dir, self.out_file)
                        if len(cveId) == 0:
                            continue
                        new_data[cveId] = formatted_data
                        cnt += 1
                    except:
                        print("An error occured. Attempt crawling this sample later ...")
                        att_dirs.append(dir)
                        err += 1
                        self.clean()
                        continue

        print("Re-attempting error files ...")

        while len(att_dirs) > 0:
            dir = att_dirs[-1]
            att_dirs.pop()
            # json file found
            if(dir.split('.')[-1] == 'json'):
                try:
                    print(f"Crawling through {dir} ...")
                    cveId, formatted_data = crawlPath(dir, self.out_dir, self.out_file)
                    if len(cveId) == 0:
                        continue
                    new_data[cveId] = formatted_data
                    err -= 1
                except:
                    print("An error occured. Please check the error files after execution.")
                    err_dirs.append(dir)
                    self.clean()
                    continue

        with open(os.path.join(self.out_dir, self.out_file), 'w', encoding= 'utf8') as file:
            json.dump(new_data, file, indent= 2)
            file.close()

        print(f"Crawling finished. {cnt}/{cnt + err} files have been successfully crawled.")
        if err > 0:
            print("The following files failed to be crawled : ")
            for dir in err_dirs:
                print(dir)


crawler = CVECrawler(
    cve_dir = 'cvelistV5-main/cves'
)

crawler.getCommitCount()