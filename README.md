# CVECrawler
A crawling tool for CVE datasets: https://www.cve.org/About/Overview 

## Crawling a CVE directory
Use `run.py` to crawls over .json files in `--cve-dir` directory. The results will be exported to `--out_dir/--out_file`. For e.g., given `--out_dir=data` and `--out_file=data.json`, the crawling results will be dumped into `data/data.json`. For investigating commit source code, a temporary folder `--tmp_dir` will be provided to clone corresponding repos to local machine. Sample commands to crawl a CVE directory with default parameters:

`python run.py --cve_dir='cvelistV5-main' --tmp_dir='tmp_dir' --out_dir='data' --out_file='data.json`

## Visualizing severity metrics
Use `stats.py --json_dir --out_dir` to visualize:
 - `cvssV2.0, cvssV3.0, cvssV3.1` score histogram
 - `cvssV3.1` vector string histogram
