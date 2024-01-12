import os
import argparse
import json
import matplotlib.pyplot as plt
import numpy as np
import csv
import pandas as pd

VALUES = {
    'AV' : ['N','A','L','P'],
    'AC' : ['L', 'H'],
    'PR' : ['N', 'L', 'H'],
    'UI' : ['N', 'R'],
    'S' : ['U', 'C'],
    'C' : ['N', 'L', 'H'],
    'I' : ['N', 'L', 'H'],
    'A' : ['N', 'L', 'H']
}

DESCRIPTIONS = {
    'AV' : ['Network','Adjacent','Local','Physical'],
    'AC' : ['Low', 'High'],
    'PR' : ['None', 'Low', 'High'],
    'UI' : ['None', 'Required'],
    'S' : ['Unchanged', 'Changed'],
    'C' : ['None', 'Low', 'High'],
    'I' : ['None', 'Low', 'High'],
    'A' : ['None', 'Low', 'High']
}

NAMES = {
    'AV' : 'Attack Vector - AV',
    'AC' : 'Attack Complexity - AC',
    'PR' : 'Privileges Required - PR',
    'UI' : 'User Interaction - UI',
    'S' : 'Scope - S',
    'C' : 'Confidentiality - C',
    'I' : 'Integrity - I',
    'A' : 'Availability - A'
}

def extractVector(vectorString):
    prewords = vectorString.split('/')
    words = []
    for word in prewords:
        words += (word.split(':'))
    if words[1] != '3.1' or words[2] != 'AV' or words[4] != 'AC' or words[-2] != 'A':
        return None
    dict = {}
    for i in range(0, len(words), 2):
        dict[words[i]] = words[i+1]
    return dict    

def plotDfFea(df, FEATURE, out_dir='stats'):
    count_dict = df[FEATURE].value_counts().to_dict()
    names = DESCRIPTIONS[FEATURE]
    values = [count_dict[x] for x in VALUES[FEATURE]]
    fig, ax = plt.subplots()
    ax.bar(names, values)
    ax.set_xlabel("Property")
    ax.set_ylabel("Frequency")
    ax.set_title(f"{NAMES[FEATURE]}")
    fig.savefig(os.path.join(out_dir, f"{FEATURE}.png"))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CVE dataset stats script')
    parser.add_argument('--json_dir', default='cveV5_2023_0xxx.json', help='JSON path')
    parser.add_argument('--out_dir', default= 'stats', help='Output directory for saving stats')

    args, _ = parser.parse_known_args()

    json_file = args.json_dir
    out_dir = args.out_dir

    if not os.path.exists(out_dir):
        os.mkdir(out_dir)

    with open(json_file, 'r', encoding= 'utf8') as file:
        data = json.load(file)
        file.close()
    
    score_dict = {
        'cvssV2_0' : [],
        'cvssV3_0' : [],
        'cvssV3_1' : []
    }
    vector_list = []

    for key, record in data.items():
        ctn = record['cna'] # Vulnerability container
        if 'metrics' not in ctn.keys():
            continue
        for metric in ctn['metrics']:
            score_dict[metric['scoreType']].append(metric['baseScore'])
    
        if metric['scoreType'] == 'cvssV3_1':
            vector_list.append(extractVector(metric['vectorString']))
    
    # Plot score frequency
    for key, value in reversed(score_dict.items()):
        fig, ax = plt.subplots()
        ax.hist(value, bins= range(1, 11), label= key)
        ax.legend()
        ax.set_title(f"{key} frequency")
        ax.set_xlabel("Score")
        ax.set_ylabel("Frequency")
        fig.savefig(os.path.join(out_dir, f'{key}.png'))

    # Stats preparation
    hdr = vector_list[0].keys()
    with open(os.path.join(out_dir, "vec31_stats.csv"), 'w') as file:
        csvwriter = csv.DictWriter(file, fieldnames= hdr)
        csvwriter.writeheader()
        csvwriter.writerows(vector_list)

    df = pd.read_csv(os.path.join(out_dir, 'vec31_stats.csv'))
    for fea in NAMES.keys():
        plotDfFea(df, fea, out_dir=out_dir)