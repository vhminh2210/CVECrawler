# CVECrawler
A crawling tool for CVE datasets: https://www.cve.org/About/Overview. The input data can be downloaded from: https://github.com/CVEProject/cvelistV5/tree/main/cves

Our crawler requires Python >= 3.10.13.

## Crawling a CVE directory
Use `run.py` to crawl over .json files in `--cve-dir` directory and its sub-directories. The results will be exported to `--out_dir/--out_file`. For example, suppose `--out_dir=data` and `--out_file=data.json`, the crawling results will be dumped into `data/data.json`. For investigating commit source code, a folder `--tmp_dir` will be provided to clone corresponding repos to local machine. Sample command to crawl a CVE directory with default parameters:

```
python run.py --cve_dir='path/to/cve' --tmp_dir='path/to/tmp_dir' --out_dir='path/to/out_dir' --out_file='.json'
```

### Structure of a crawled record
The resulting record consists of all crawled cve records compressed in a json file with `cveId` being the keys. Each `cveId` object is structured as below (mindmap generated using Mindmeister: https://www.mindmeister.com/) :
<p align="center" width="100%">
    <img width="70%" src="https://github.com/vhminh2210/CVECrawler/blob/main/cveMindMap.PNG"> 
</p>

**NOTE:**

 - italic _items_ represent required fields in the corresponding branch. i.e., if the branch is available, the corresponding field must be available.
 - Non-available fileds are replaced by 'N/A' or omitted from the corresponding branch
 - `adp` is an optional container. If such container exists, it will share the structure of `cna` containers.

## Visualizing severity metrics
Use `stats.py --json_dir --out_dir` to visualize:
 - `cvssV2.0, cvssV3.0, cvssV3.1` score histogram
 - `cvssV3.1` vector string histogram

Parameters:
 - `--json_dir`: CVE crawled files in CVECrawler format
 - `--out_dir` : Exporting folder

_**Sample command:**_
```
python stats.py --out_dir='path/to/stats' --json_dir='.json'
```

_**Sample score histogram:**_
<p align="left" width="100%">
    <img width="50%" src="https://github.com/vhminh2210/CVECrawler/blob/main/images/cvssV3_1.png"> 
</p>

_**Sample vector string histogram:**_
<p align="left" width="100%">
    <img width="50%" src="https://github.com/vhminh2210/CVECrawler/blob/main/images/C.png"> 
</p>
