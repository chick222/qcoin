#!/usr/bin/env python3
"""Deterministic synthetic prealignment tests with positive and adversarial cases."""
import tempfile,json,hashlib,subprocess,copy,math,sys
from pathlib import Path
import numpy as np,cv2
from num_pipeline import (create_prealign,validate_prealign,sha256_file,validate_geometry_proposal,
                          initialize_run,commit_prealign,verdict_receipt,sha256_obj,migrate_run_prealign)

def saved(path,obj):path.write_text(json.dumps(obj),encoding='utf-8')

with tempfile.TemporaryDirectory() as td:
    p=Path(td)
    size=600;center=np.array([300.,300.]); rawcenter=np.array([310.,295.]); rad=180.
    angle=math.radians(24);c=math.cos(angle);s=math.sin(angle)
    rot=np.array([[c,-s],[s,c]])
    A=rot@np.diag([190/180,150/180])@rot.T
    direction=np.eye(3);direction[:2,:2]=A;direction[:2,2]=rawcenter-A@center
    rim_ref=[[center[0]+rad*math.cos(t),center[1]+rad*math.sin(t)] for t in np.linspace(0,2*math.pi,64,endpoint=False)]
    rim_raw=[list(rawcenter + A@(np.array(v)-center)) for v in rim_ref]
    ref=np.zeros((size,size,3),dtype=np.uint8)
    cv2.circle(ref,tuple(center.astype(int)),int(rad),(110,110,110),-1,cv2.LINE_AA)
    cv2.circle(ref,tuple(center.astype(int)),int(rad),(240,240,240),3,cv2.LINE_AA)
    pts=[[240.,225.],[360.,215.],[255.,350.],[360.,345.]]
    for q in pts:cv2.circle(ref,tuple(np.array(q,dtype=int)),6,(230,150,150),-1,cv2.LINE_AA)
    raw=cv2.warpAffine(ref,direction[:2,:],(size,size),flags=cv2.INTER_LINEAR)
    rawfile=p/'raw.png';reffile=p/'reference.png';normfile=p/'normalized.png'
    cv2.imwrite(str(rawfile),raw);cv2.imwrite(str(reffile),ref)
    zone={'id':'z','reference_points':[[200.,200.],[350.,200.],[200.,350.]],
          'diagnostic_region':{'type':'BINARY_MASK_RLE','canvas':[size,size],'runs':[[500*size+500,3]],'approved':True,'source':'USER_MARKUP_FULL_REFERENCE'},
          'validation_points':[{'id':'V1','reference':[350.,350.],'description':'validation'}]}
    cfg={'schema_version':'3.1','canonical_spec_file_id':'s','canonical_spec_sha256':'f'*64,
         'reference_file_id':'r','reference_sha256':sha256_file(reffile),'canvas':[size,size],
         'transform_model':'SIMILARITY_LS_3PT','post_transform_policy':'FORBID',
         'max_control_residual_px':3.,'max_validation_residual_px':6.,'max_allowed_deformation':0.,'zones':[zone]}
    def mark(q):return {'raw':list(rawcenter + A@(np.array(q)-center)),'reference':q,'role':'COMMON_NONDIAGNOSTIC_CONTOUR'}
    annotations={'annotation_status':'GEOMETER_CONFIRMED','input_file_id':'input_001','reference_file_id':'r','raw_rim_points':rim_raw,
                 'reference_rim_points':rim_ref,
                 'orientation_controls':[mark(pts[0]),mark(pts[1])],
                 'orientation_validation':[mark(pts[2]),mark(pts[3])]}
    saved(p/'cfg.json',cfg);saved(p/'annotations.json',annotations)
    prep=create_prealign(cfg,annotations,rawfile,reffile,normfile)
    receipt=validate_prealign(cfg,prep,rawfile,reffile,normfile)
    assert receipt['result']=='PASS',receipt
    saved(p/'prealign.json',prep);saved(p/'prealign_gate.json',receipt)
    cmd=[sys.executable,str(Path(__file__).parent/'num_pipeline.py'),'validate-prealign',str(p/'cfg.json'),str(p/'prealign.json'),str(rawfile),str(reffile),str(normfile)]
    assert subprocess.run(cmd,capture_output=True).returncode==0
    # A tampered image must not be able to use a PASS receipt.
    tampered=normfile.read_bytes();normfile.write_bytes(tampered[:400]+bytes([tampered[400]^1])+tampered[401:])
    assert validate_prealign(cfg,prep,rawfile,reffile,normfile)['result']=='STOP'
    normfile.write_bytes(tampered)
    altered=copy.deepcopy(prep);altered['raw_to_normalized'][0][0]*=1.01
    assert validate_prealign(cfg,altered,rawfile,reffile,normfile)['result']=='STOP'
    leak=copy.deepcopy(prep);leak['orientation_controls'][0]['reference']=[501,500]
    assert validate_prealign(cfg,leak,rawfile,reffile,normfile)['result']=='STOP'
    # A fabricated receipt passed to the standalone geometry CLI is not sufficient.
    proposal={'zone_id':'z','coin_points':[[200.,200.],[350.,200.],[200.,350.]],
      'validation_points':[{'id':'V1','coin':[350.,350.]}],
      'transform_provenance':'C1_C2_C3_ONLY','post_transforms':[],
      'prealign_receipt':receipt['prealign_receipt'],'normalized_sha256':receipt['normalized_sha256']}
    saved(p/'proposal.json',proposal)
    call=[sys.executable,str(Path(__file__).parent/'num_pipeline.py'),'validate-geometry',str(p/'cfg.json'),str(p/'proposal.json')]
    assert subprocess.run(call,capture_output=True).returncode!=0
    call += ['--prealign-report',str(p/'prealign_gate.json'),'--prealign-artifact',str(p/'prealign.json'),
             '--raw',str(rawfile),'--reference',str(reffile),'--normalized',str(normfile)]
    assert subprocess.run(call,capture_output=True).returncode==0
    # Preserve old RUN review counters after adoption; no bypass via commit.
    snapshot={'inbox_folder_id':'f','files':[{'id':'input_001','name':'raw.png','size':rawfile.stat().st_size,'sha256':sha256_file(rawfile)}]}
    init=initialize_run(snapshot,p/'run','RUN_SYNTHETIC')
    mfpath=p/'run'/'manifest.json'
    mf=json.loads(mfpath.read_text())
    mf['canonical_sources']={'averse_A_reference_id':'r'}
    saved(mfpath,mf)
    statepath=p/'run'/'run_state.json';state=json.loads(statepath.read_text())
    state['manifest_sha256']=sha256_obj(mf)
    state['gates']['SOURCES_PASS']='PASS';state['gates']['BRANCH_PASS']='PASS'
    state['gates'].pop('PREALIGN_PASS')  # emulate old legacy active RUN
    state['gates']['GEOMETRY_PASS']='REWORK';state['workflow_status']='REWORK'
    state['rework_counters']={'GEOMETRY|CONTROL_RESIDUAL,VALIDATION_RESIDUAL':3}
    saved(statepath,state)
    migration=migrate_run_prealign(p/'run')
    assert migration['result']=='PASS' and migration['changed']
    migrated=json.loads(statepath.read_text())
    assert migrated['gates']['PREALIGN_PASS']=='PENDING'
    assert migrated['gates']['GEOMETRY_PASS']=='REWORK'
    assert migrated['rework_counters']==state['rework_counters']
    assert not migrate_run_prealign(p/'run')['changed']
    commit=commit_prealign(p/'run',receipt,prep,normfile,rawfile,reffile,cfg)
    assert commit['result']=='PASS',commit
    updated=json.loads(statepath.read_text())
    assert updated['gates']['PREALIGN_PASS']=='PASS'
    assert updated['gates']['GEOMETRY_PASS']=='REWORK'
    assert updated['rework_counters']==state['rework_counters']
    assert verdict_receipt(updated)['result']=='STOP'
    # Human manipulation of a gate alone cannot yield verdict receipt.
    updated['workflow_status']='ACTIVE';updated['gates']={g:'PASS' for g in updated['gates']}
    assert verdict_receipt(updated)['result']=='PASS'  # valid artifact records are present
    empty=copy.deepcopy(updated);empty['artifacts']={}
    assert verdict_receipt(empty)['result']=='STOP'
print('PREALIGN_TESTS_PASS')