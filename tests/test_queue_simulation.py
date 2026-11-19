import pytest
from tools.simulate_checkpoint_queue import simulate


def record(n,stamp,cost):
    return {'record':n,'sample_id':str(n),'event':{'timestamp':stamp},'elapsed_s':cost,
        'l1_elapsed_s':cost,'l2_elapsed_s':0,'first_stage':{'tier':'llm'},'second_stage':None}


def test_virtual_wait_accumulates_and_idle_time_drains_the_queue():
    rows,summary=simulate([record(1,'2022-01-15T00:00:00Z',5),
        record(2,'2022-01-15T00:00:01Z',2),record(3,'2022-01-15T00:00:20Z',1)])
    assert [r['simulated_queue_wait_s'] for r in rows]==[0,4,0]
    assert rows[1]['simulated_end_to_end_s']==6
    assert summary['dataset_span_s']==20
    assert summary['maximum_simulated_wait']['record']==2
    assert next(iter(summary['hours'].values()))['service_s']==8


def test_nonchronological_input_and_invalid_cost_are_rejected():
    with pytest.raises(ValueError,match='chronological'):
        simulate([record(1,'2022-01-15T00:00:01Z',1),record(2,'2022-01-15T00:00:00Z',1)])
    with pytest.raises(ValueError,match='cost'):
        simulate([record(1,'2022-01-15T00:00:00Z',float('nan'))])
