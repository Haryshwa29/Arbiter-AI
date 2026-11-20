"""Both endpoints are local fixtures; inference must stay on its chosen origin."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import threading

import pytest

from arbiter.llm import OllamaBackend
from arbiter.ingestion.models import available_models


@contextmanager
def endpoint(handler):
    server=ThreadingHTTPServer(('127.0.0.1',0),handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield 'http://127.0.0.1:'+str(server.server_port)
    finally:server.shutdown();server.server_close();thread.join(2)


@pytest.fixture
def redirected_service():
    contacted=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def reply(self,value):
            body=json.dumps(value).encode()
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length',0)))
            self.reply({'details':{'format':'gguf'}} if self.path=='/api/show' else {'response':'{}'})
    class Other(Handler):
        def do_GET(self):
            contacted.append(self.path);self.reply({'models':[{'name':'local-model'}]})
    with endpoint(Other) as other:
        class Redirect(Handler):
            def do_GET(self):
                self.send_response(302);self.send_header('Location',other+self.path);self.send_header('Content-Length','0');self.end_headers()
        with endpoint(Redirect) as source:yield source,contacted


def test_l1_refuses_a_model_server_redirect_before_sending_a_prompt(redirected_service):
    source,contacted=redirected_service
    with pytest.raises(ValueError,match='redirect'):
        OllamaBackend('local-model',source).generate('Public fixture only','Test')
    assert contacted==[]


def test_model_discovery_cannot_follow_redirects_to_another_service(redirected_service):
    source,contacted=redirected_service
    assert available_models(source)=={'available':False,'models':[]}
    assert contacted==[]
