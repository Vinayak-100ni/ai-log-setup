✅ STEP 0 — Install Required System Packages

Run this:
```bash
sudo apt update
sudo apt install -y python3.12-venv python3.12-full python3-pip
```

If your version is different, check with:
```bash
python3 --version
```

If it shows 3.12.x, then python3.12-venv is correct.

✅ STEP 1 — Create Virtual Environment

Now run:
```bash
cd ~
python3 -m venv docker-ai-env
```

If successful, you will see no error.

✅ STEP 2 — Activate It
```bash
source docker-ai-env/bin/activate
```

Your prompt should now show:

(docker-ai-env) ubuntu:~$

✅ STEP 3 — Upgrade pip (Important)
```bash
pip install --upgrade pip
```

✅ STEP 4 — Install Required Libraries
```bash
pip install pandas scikit-learn requests
```
✅ STEP 5 — Verify Everything

Check python path:
```bash
which python
```

It must show:
```bash
/root/docker-ai-env/bin/python
```

Check pandas:
```bash
python -c "import pandas; print('Pandas OK')"
```

If it prints:

Pandas OK


You're good.

✅ STEP 6 — Run Your Script

Now:
```bash
python py.py
```
