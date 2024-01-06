import os
from crawl import CVECrawler
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CVE dataset crawl script')
    parser.add_argument('--cve_dir', default='cvelistV5-main', help='CVE directory')
    parser.add_argument('--tmp_dir', default='tmp_dir', help='Temporary directory for cloning repos')
    parser.add_argument('--out_dir', default='data', help='Saving directory')
    parser.add_argument('--out_file', default='data.json', help='Output file. Stored in out-dir')

    args, _ = parser.parse_known_args()

    crawler = CVECrawler(
        cve_dir= args.cve_dir,
        tmp_dir= args.tmp_dir,
        out_dir= args.out_dir,
        out_file= args.out_file
    )

    crawler.crawl()