#!/usr/bin/env python3
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

PIPE = Path(__file__).with_name('num_pipeline.py')

def run(args):
    p = subprocess.run(['python', str(PIPE), *args], text=True, capture_output=True)
    return p.returncode, p.stdout + p.stderr

with tempfile.TemporaryDirectory() as td0:
    td = Path(td0)

    # RUN lifecycle
    snapshot = {
        'inbox_folder_id':'inbox-id',
        'files':[{'id':'f1','name':'a.jpg','size':123,'sha256':'a'*64}]
    }
    (td/'snapshot.json').write_text(json.dumps(snapshot),encoding='utf-8')
    run_dir = td/'run'
    rc,out = run(['init-run',str(td/'snapshot.json'),str(run_dir),'--run-id','RUN_TEST'])
    assert rc == 0 and (run_dir/'manifest.json').exists() and (run_dir/'run_state.json').exists()
    assert not (run_dir/'verdict.json').exists()

    # Geometry + binding
    spec = td/'spec.txt'; spec.write_text('SPEC TEST\n',encoding='utf-8')
    ref = td/'ref.bin'; ref.write_bytes(b'reference')
    sh=lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    cfg={
      'schema_version':'2.0','canonical_spec_file_id':'spec','canonical_spec_sha256':sh(spec),
      'reference_file_id':'ref','reference_sha256':sh(ref),'canvas':[474,474],
      'transform_model':'SIMILARITY_LS_3PT','post_transform_policy':'FORBID',
      'max_control_residual_px':0.01,'max_validation_residual_px':1.0,'max_allowed_deformation':0.0,
      'zones':[{
          'id':'z','reference_points':[[0,0],[100,0],[0,100]],
          'diagnostic_region':{'type':'BINARY_MASK_RLE','canvas':[474,474],'runs':[[4740,40],[5214,40]],'source':'USER_MARKUP_FULL_REFERENCE','approved':True},
          'validation_points':[{'id':'V1','description':'fixed check point','reference':[20,20]}]
      }]
    }
    good={'zone_id':'z','coin_points':[[0,0],[100,0],[0,100]],'transform_provenance':'C1_C2_C3_ONLY','post_transforms':[],
          'validation_points':[{'id':'V1','coin':[20,20]}]}
    bad={'zone_id':'z','coin_points':[[0,0],[100,0],[0,100]],'transform_provenance':'ECC_GLOBAL_AFTER_APPROX_NORMALIZATION','post_transforms':['ECC_AFFINE'],
         'validation_points':[{'id':'V1','coin':[20,20]}]}
    for name,obj in [('cfg.json',cfg),('good.json',good),('bad.json',bad)]:
        (td/name).write_text(json.dumps(obj),encoding='utf-8')
    rc,out = run(['verify-binding',str(td/'cfg.json'),str(spec),str(ref)])
    assert rc == 0 and '"result": "PASS"' in out
    rc,out = run(['validate-geometry',str(td/'good.json') if False else str(td/'cfg.json'),str(td/'good.json')])
    assert rc != 0 and 'PREALIGN_NOT_PASS' in out
    rc,out = run(['validate-geometry',str(td/'cfg.json'),str(td/'bad.json')])
    assert rc != 0 and 'BAD_PROVENANCE' in out and 'POST_TRANSFORM_FORBIDDEN' in out
    bad_ref=dict(good)
    bad_ref['validation_points']=[{'id':'V1','coin':[20,20],'reference':[999,999]}]
    (td/'bad_ref.json').write_text(json.dumps(bad_ref),encoding='utf-8')
    rc,out = run(['validate-geometry',str(td/'cfg.json'),str(td/'bad_ref.json')])
    assert rc != 0 and 'VALIDATION_REFERENCE_NOT_ALLOWED' in out

    missing_val=dict(good)
    missing_val['validation_points']=[]
    (td/'missing_val.json').write_text(json.dumps(missing_val),encoding='utf-8')
    rc,out = run(['validate-geometry',str(td/'cfg.json'),str(td/'missing_val.json')])
    assert rc != 0 and 'VALIDATION_POINTS_MISSING' in out

    # User-defined diagnostic region: missing/bad regions and legacy fields must fail closed.
    cfg_missing_region=json.loads(json.dumps(cfg)); del cfg_missing_region['zones'][0]['diagnostic_region']
    (td/'cfg_missing_region.json').write_text(json.dumps(cfg_missing_region),encoding='utf-8')
    rc,out = run(['lint-geometry-config',str(td/'cfg_missing_region.json')])
    assert rc != 0 and 'diagnostic_region is not manually approved yet' in out

    cfg_bad_region=json.loads(json.dumps(cfg)); cfg_bad_region['zones'][0]['diagnostic_region']['runs']=[[10,5],[12,4]]
    (td/'cfg_bad_region.json').write_text(json.dumps(cfg_bad_region),encoding='utf-8')
    rc,out = run(['lint-geometry-config',str(td/'cfg_bad_region.json')])
    assert rc != 0 and 'REGION_INVALID' in out

    cfg_unapproved=json.loads(json.dumps(cfg)); cfg_unapproved['zones'][0]['diagnostic_region']['approved']=False
    (td/'cfg_unapproved.json').write_text(json.dumps(cfg_unapproved),encoding='utf-8')
    rc,out = run(['lint-geometry-config',str(td/'cfg_unapproved.json')])
    assert rc != 0 and 'REGION_INVALID' in out

    cfg_legacy=json.loads(json.dumps(cfg)); cfg_legacy['zones'][0]['diagnostic_polygon']=[[10,10],[50,10],[50,50]]
    (td/'cfg_legacy.json').write_text(json.dumps(cfg_legacy),encoding='utf-8')
    rc,out = run(['lint-geometry-config',str(td/'cfg_legacy.json')])
    assert rc != 0 and 'LEGACY_DIAGNOSTIC_ZONE_FIELD' in out


    # Verdict receipt reads nested run_state.gates.
    state=json.loads((run_dir/'run_state.json').read_text(encoding='utf-8'))
    state['gates']={k:'PASS' for k in state['gates']}
    state['artifacts']={'manifest.json':state['manifest_sha256']}
    (run_dir/'run_state.json').write_text(json.dumps(state),encoding='utf-8')
    rc,out = run(['verdict-receipt',str(run_dir/'run_state.json')])
    assert rc != 0 and 'PREALIGN_RECEIPT_MISSING' in out
    state['artifacts']['prealign_gate_ref.json']='f'*64
    (run_dir/'run_state.json').write_text(json.dumps(state),encoding='utf-8')
    rc,out = run(['verdict-receipt',str(run_dir/'run_state.json')])
    assert rc == 0 and 'VERDICT_RECEIPT' in out

    # Review router: fixable rejection returns work to GEOMETER with detailed reason.
    bad_gate = td/'bad_gate.json'
    rc,out = run(['validate-geometry',str(td/'cfg.json'),str(td/'bad.json'),'--output',str(bad_gate)])
    assert rc != 0 and bad_gate.exists()
    review=json.loads(bad_gate.read_text(encoding='utf-8'))
    review['reviewer']='MACHINE_GATE'; review['stage']='GEOMETRY'
    review['issues']=[issue for issue in review['issues'] if issue['code'] in {'BAD_PROVENANCE','POST_TRANSFORM_FORBIDDEN'}]
    (td/'review.json').write_text(json.dumps(review),encoding='utf-8')
    for expected_attempt in (1,2,3):
        rc,out = run(['route-review',str(run_dir),str(td/'review.json')])
        assert rc == 9 and '"result": "REWORK"' in out and '"target_stage": "GEOMETER"' in out
        assert f'"rework_attempt": {expected_attempt}' in out and 'returned to GEOMETER' in out
    rc,out = run(['route-review',str(run_dir),str(td/'review.json')])
    assert rc == 10 and '"result": "HARD_STOP"' in out and 'REWORK_LIMIT_EXCEEDED' in out
    assert 'automatic work stopped' in out
    state_after=json.loads((run_dir/'run_state.json').read_text(encoding='utf-8'))
    assert state_after['workflow_status']=='HARD_STOP'
    assert len(state_after['review_history'])==4
    assert (run_dir/'review_decision_001.json').exists() and (run_dir/'review_decision_004.json').exists()

    # A corrected result accepted by the same reviewer/stage resumes the same RUN.
    run_dir3=td/'run3'
    rc,out = run(['init-run',str(td/'snapshot.json'),str(run_dir3),'--run-id','RUN_TEST_3'])
    assert rc == 0
    rc,out = run(['route-review',str(run_dir3),str(td/'review.json')])
    assert rc == 9 and '"result": "REWORK"' in out
    pass_review={'reviewer':'MACHINE_GATE','stage':'GEOMETRY','result':'PASS'}
    (td/'pass_review.json').write_text(json.dumps(pass_review),encoding='utf-8')
    rc,out = run(['route-review',str(run_dir3),str(td/'pass_review.json')])
    assert rc == 0 and 'resolved_previous_status' in out
    resumed=json.loads((run_dir3/'run_state.json').read_text(encoding='utf-8'))
    assert resumed['workflow_status']=='ACTIVE' and resumed['gates']['GEOMETRY_PASS']=='PENDING'

    # Configuration/source-class failure is HARD_STOP immediately and is described.
    run_dir2=td/'run2'
    rc,out = run(['init-run',str(td/'snapshot.json'),str(run_dir2),'--run-id','RUN_TEST_2'])
    assert rc == 0
    hard_review={'reviewer':'MACHINE_GATE','stage':'GEOMETRY_CONFIG','result':'STOP',
                 'issues':[{'code':'CONFIG_MISSING','message':'max_validation_residual_px is TBD'}]}
    (td/'hard_review.json').write_text(json.dumps(hard_review),encoding='utf-8')
    rc,out = run(['route-review',str(run_dir2),str(td/'hard_review.json')])
    assert rc == 10 and '"result": "HARD_STOP"' in out and 'CONFIG_MISSING' in out
    assert 'max_validation_residual_px is TBD' in out and '"returned_for_rework": false' in out.lower()

print('ALL_TESTS_PASS')