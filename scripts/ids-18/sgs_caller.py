import os
for ratio in [ 0.01]:
        cmd = 'python3 SGS.py --ratio {}'.format(ratio)
        os.system(cmd)
