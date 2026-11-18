from io import BytesIO
from unittest.mock import Mock

import pytest
from arbiter.api.server import make_handler


@pytest.mark.parametrize('length,encoding,consumed',[('4',None,4),('invalid',None,0),
    (str(8*1024*1024+1),None,0),('4','chunked',0)])
def test_post_denial_drains_only_bounded_supported_bodies(length,encoding,consumed):
    handler=make_handler(None).__new__(make_handler(None))
    handler.headers={'Content-Length':length}
    if encoding:handler.headers['Transfer-Encoding']=encoding
    handler.connection=Mock();handler.connection.gettimeout.return_value=10
    handler.rfile=BytesIO(b'body');handler._send_json=Mock()
    handler._reject_post(401,{'error':'unauthenticated'})
    assert handler.rfile.tell()==consumed
    handler._send_json.assert_called_once_with(401,{'error':'unauthenticated'})
    assert handler.connection.settimeout.call_args.args==(10,)


def test_post_denial_remains_bounded_when_the_client_does_not_finish_uploading():
    cls=make_handler(None);handler=cls.__new__(cls)
    handler.headers={'Content-Length':'4'};handler.connection=Mock()
    handler.connection.gettimeout.return_value=None
    handler.rfile=Mock();handler.rfile.read.side_effect=TimeoutError()
    handler._send_json=Mock()
    handler._reject_post(403,{'error':'csrf token missing or invalid'})
    handler._send_json.assert_called_once()
    assert handler.connection.settimeout.call_args_list[0].args==(1,)
    assert handler.connection.settimeout.call_args.args==(None,)
