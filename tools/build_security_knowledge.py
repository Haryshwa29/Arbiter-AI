"""Build the small offline factual CVE index from a locally supplied CISA KEV JSON."""
import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
import re


def build(data, source_url, source_sha256):
    entries = data['vulnerabilities']
    if data['count'] != len(entries):
        raise ValueError('CISA catalog count mismatch')
    result = {}
    for item in entries:
        identity = item['cveID']
        if not re.fullmatch(r'CVE-\d{4}-\d{4,12}',identity) or identity in result:
            raise ValueError('Invalid or duplicate CVE identifier')
        date.fromisoformat(item['dateAdded'])
        for key in ('vendorProject','product'):
            if not isinstance(item[key],str) or not 0<len(item[key])<=256:
                raise ValueError('Invalid factual vendor/product')
        result[identity] = {'vendor':item['vendorProject'],'product':item['product'],
            'date_added':item['dateAdded']}
    return {'schema':1,'source':'CISA Known Exploited Vulnerabilities',
        'source_url':source_url,'source_sha256':source_sha256,
        'catalog_version':data['catalogVersion'],'released':data['dateReleased'],
        'count':len(result),'entries':dict(sorted(result.items()))}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kev-file',type=Path,required=True)
    p.add_argument('--source-url',required=True)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    raw=args.kev_file.read_bytes()
    result=build(json.loads(raw),args.source_url,hashlib.sha256(raw).hexdigest())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2,ensure_ascii=True)+'\n',encoding='utf-8')
    print(f"Built {result['count']} factual CVE entries, catalog {result['catalog_version']}; no descriptions or executable advice.")


if __name__=='__main__':main()
