mkdir bundle
cd package
tar --exclude='.[^/]*' --exclude='__pycache__' --exclude='./tests' --exclude='./AnomaliEnrichment.py' -cvf ../bundle/intezer.tgz .