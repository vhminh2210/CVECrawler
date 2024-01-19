# CVECrawler
A crawling tool for CVE datasets: https://www.cve.org/About/Overview 

## Crawling a CVE directory
Use `run.py` to crawl over .json files in `--cve-dir` directory and its sub-directories. The results will be exported to `--out_dir/--out_file`. For example, suppose `--out_dir=data` and `--out_file=data.json`, the crawling results will be dumped into `data/data.json`. For investigating commit source code, a folder `--tmp_dir` will be provided to clone corresponding repos to local machine. Sample command to crawl a CVE directory with default parameters:

```
python run.py --cve_dir='cvelistV5-main' --tmp_dir='tmp_dir' --out_dir='data' --out_file='data.json'
```

## Visualizing severity metrics
Use `stats.py --json_dir --out_dir` to visualize:
 - `cvssV2.0, cvssV3.0, cvssV3.1` score histogram
 - `cvssV3.1` vector string histogram

Parameters:
 - `--json_dir`: CVE crawled files in CVECrawler format
 - `--out_dir` : Exporting folder

_**Sample command:**_
```
python stats.py --out_dir='stats' --json_dir='cveV5_2023_0xxx.json'
```

_**Sample score histogram:**_
<p align="left" width="100%">
    <img width="50%" src="https://github.com/vhminh2210/CVECrawler/blob/main/images/cvssV3_1.png"> 
</p>

_**Sample vector string histogram:**_
<p align="left" width="100%">
    <img width="50%" src="https://github.com/vhminh2210/CVECrawler/blob/main/images/C.png"> 
</p>
