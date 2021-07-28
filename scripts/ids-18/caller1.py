import os
from multiprocessing import Pool

def execute(cmd):
    os.system(cmd)

samplers = ['FFS.py','SGS.py']
cmds=[]
for ratio in [ 0.1, 0.01]:
    for sampler_script in samplers:
        cmd = 'python3 {} --ratio {}'.format(sampler_script,ratio)
        cmds.append(cmd)
        os.system(cmd)


