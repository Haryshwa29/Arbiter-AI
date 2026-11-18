"""Independent bounded local inference transport for the L2 engine."""
import re
import json
import time
import urllib.request
from .ingestion.schema import safe_json

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('L2 inference redirects are forbidden')

class L2Transport:
    def __init__(self, model, *, think=True, num_ctx=16384, num_predict=3072):
        if not isinstance(model,str) or not model.strip() or model.lower().endswith((':cloud','-cloud')):
            raise ValueError('L2 requires an installed local model')
        self.model=model
        if type(think) is not bool or type(num_ctx) is not int or not 4096<=num_ctx<=16384 or type(num_predict) is not int or not 256<=num_predict<=3072:
            raise ValueError('invalid bounded L2 generation options')
        self.think,self.num_ctx,self.num_predict=think,num_ctx,num_predict
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        self.usage=[]

    def request(self, path, data=None, timeout=5):
        request=urllib.request.Request('http://127.0.0.1:11434'+path,
            data=json.dumps(data).encode() if data is not None else None,
            headers={'Content-Type':'application/json'})
        with self.opener.open(request,timeout=timeout) as response:
            body=response.read(2*1024*1024+1)
        if len(body)>2*1024*1024: raise ValueError('L2 response too large')
        return safe_json(body)

    def verify(self, remaining=5):
        tags=self.request('/api/tags',timeout=min(5,remaining))
        names={self.model,self.model+':latest'}
        models=[m for m in tags.get('models',[]) if m.get('name') in names]
        if not models or any(m.get('remote_host') or m.get('remote_model') for m in models):
            raise ValueError('L2 model is not verified local')
        metadata=self.request('/api/show',{'model':self.model},timeout=min(5,remaining))
        if metadata.get('remote_host') or metadata.get('remote_model') or not metadata.get('details',{}).get('format'):
            raise ValueError('L2 model is not verified local')
        size=metadata.get('details',{}).get('parameter_size','')
        match=re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)\s*([BM])',size,re.I)
        count=float(match[1])*(1e9 if match[2].upper()=='B' else 1e6) if match else 0
        if count<=4e9: raise ValueError('L2 requires verified parameter metadata above 4B')
        # Metadata is returned for operator inspection; model names are not evidence
        # of parameter count, quality or a larger capacity than L1.
        return metadata.get('details',{})

    def generate(self,prompt,system,deadline=None,format_schema=None):
        if format_schema is not None and not isinstance(format_schema,dict):
            raise ValueError('structured response schema must be an object')
        remaining=(deadline-time.monotonic()) if deadline else 30
        if remaining<=0: raise TimeoutError('L2 reasoning budget exhausted')
        self.verify(remaining)
        remaining=(deadline-time.monotonic()) if deadline else 30
        if remaining<=0: raise TimeoutError('L2 reasoning budget exhausted')
        body=self.request('/api/generate',{'model':self.model,'system':system,'prompt':prompt,
            'stream':False,'format':format_schema if format_schema is not None else 'json','think':self.think,
            'options':{'temperature':0.1,'num_ctx':self.num_ctx,'num_predict':self.num_predict}},timeout=min(90,remaining))
        self.usage.append({key:body.get(key) for key in ('prompt_eval_count','eval_count','load_duration','prompt_eval_duration','eval_duration','done_reason')})
        del self.usage[:-64]
        return body['response']
