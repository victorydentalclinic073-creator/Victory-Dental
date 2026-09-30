import os, uuid, secrets, hashlib, hmac
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import psycopg
from psycopg.rows import dict_row

DATABASE_URL=os.getenv('DATABASE_URL','')
TOKEN_HOURS=int(os.getenv('TOKEN_HOURS','12'))
ADMIN_EMAIL=os.getenv('ADMIN_EMAIL','admin@victorydental.local').lower()
ADMIN_PASSWORD=os.getenv('ADMIN_PASSWORD','')
CORS_ORIGINS=[x.strip() for x in os.getenv('CORS_ORIGINS','').split(',') if x.strip()]

app=FastAPI(title='Victory Dental Clinic API', version='3.0')
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS or ['*'], allow_credentials=False, allow_methods=['*'], allow_headers=['*'])

def db():
    if not DATABASE_URL:
        raise RuntimeError('DATABASE_URL is not configured')
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)

def now(): return datetime.now(timezone.utc).isoformat()

def hashpw(password, salt=None):
    salt=salt or secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 210000)
    return salt.hex()+':'+digest.hex()

def checkpw(password, stored):
    try:
        salt_hex,digest_hex=stored.split(':',1)
        digest=hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt_hex), 210000)
        return hmac.compare_digest(digest.hex(),digest_hex)
    except Exception: return False

def init():
    with db() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'admin',created_at TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS patients(id TEXT PRIMARY KEY,number INTEGER UNIQUE NOT NULL,name TEXT NOT NULL,phone TEXT,dob TEXT,gender TEXT,notes TEXT,registered TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS appointments(id TEXT PRIMARY KEY,patient_id TEXT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,date TEXT NOT NULL,time TEXT NOT NULL,reason TEXT NOT NULL,status TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS treatments(id TEXT PRIMARY KEY,patient_id TEXT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,date TEXT NOT NULL,tooth TEXT,procedure TEXT NOT NULL,charge DOUBLE PRECISION NOT NULL DEFAULT 0,paid DOUBLE PRECISION NOT NULL DEFAULT 0,notes TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS audit(id BIGSERIAL PRIMARY KEY,user_id BIGINT,action TEXT NOT NULL,entity TEXT,entity_id TEXT,created_at TEXT NOT NULL)''')
        if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            if not ADMIN_PASSWORD: raise RuntimeError('Set ADMIN_PASSWORD before first production start')
            c.execute('INSERT INTO users(email,password_hash,role,created_at) VALUES(%s,%s,%s,%s)',(ADMIN_EMAIL,hashpw(ADMIN_PASSWORD),'admin',now()))

def auth(authorization: Optional[str]=Header(None)):
    if not authorization or not authorization.lower().startswith('bearer '): raise HTTPException(401,'Authentication required')
    token=authorization.split(' ',1)[1]
    with db() as c:
        row=c.execute('SELECT s.*,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=%s',(token,)).fetchone()
    if not row or row['expires_at'] < now(): raise HTTPException(401,'Session expired')
    return row

def audit(user,action,entity=None,entity_id=None):
    with db() as c: c.execute('INSERT INTO audit(user_id,action,entity,entity_id,created_at) VALUES(%s,%s,%s,%s,%s)',(user['user_id'],action,entity,entity_id,now()))

class Login(BaseModel): email:str; password:str
class Patient(BaseModel): id:Optional[str]=None; number:Optional[int]=None; name:str; phone:str=''; dob:str=''; gender:str=''; notes:str=''; registered:Optional[str]=None
class Appointment(BaseModel): id:Optional[str]=None; patientId:str; date:str; time:str; reason:str; status:str='Scheduled'
class Treatment(BaseModel): id:Optional[str]=None; patientId:str; date:str; tooth:str=''; procedure:str; charge:float=Field(0,ge=0); paid:float=Field(0,ge=0); notes:str=''
class ClinicState(BaseModel): patients:list[dict]=[]; appointments:list[dict]=[]; treatments:list[dict]=[]

@app.on_event('startup')
def startup(): init()
@app.get('/api/health')
def health(): return {'ok':True,'service':'victory-dental-clinic','database':'postgresql'}
@app.post('/api/login')
def login(x:Login):
    with db() as c: u=c.execute('SELECT * FROM users WHERE email=%s',(x.email.lower(),)).fetchone()
    if not u or not checkpw(x.password,u['password_hash']): raise HTTPException(401,'Invalid email or password')
    token=secrets.token_urlsafe(32); exp=(datetime.now(timezone.utc)+timedelta(hours=TOKEN_HOURS)).isoformat()
    with db() as c: c.execute('INSERT INTO sessions(token,user_id,expires_at) VALUES(%s,%s,%s)',(token,u['id'],exp))
    return {'token':token,'email':u['email'],'role':u['role'],'expires_at':exp}
@app.post('/api/logout')
def logout(user=Depends(auth), authorization: Optional[str]=Header(None)):
    token=authorization.split(' ',1)[1]
    with db() as c: c.execute('DELETE FROM sessions WHERE token=%s',(token,))
    return {'ok':True}

def rows(sql, args=()):
    with db() as c: return [dict(r) for r in c.execute(sql,args).fetchall()]

@app.get('/api/patients')
def patients(user=Depends(auth)): return rows('SELECT * FROM patients ORDER BY number')
@app.post('/api/patients')
def add_patient(x:Patient,user=Depends(auth)):
    pid=x.id or str(uuid.uuid4())
    with db() as c:
        nums={r['number'] for r in c.execute('SELECT number FROM patients').fetchall()}; n=1
        while n in nums: n+=1
        c.execute('INSERT INTO patients(id,number,name,phone,dob,gender,notes,registered) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',(pid,n,x.name,x.phone,x.dob,x.gender,x.notes,x.registered or datetime.now().date().isoformat()))
    audit(user,'create','patient',pid); return {'id':pid,'number':n}
@app.put('/api/patients/{pid}')
def update_patient(pid:str,x:Patient,user=Depends(auth)):
    with db() as c:
        if not c.execute('SELECT 1 FROM patients WHERE id=%s',(pid,)).fetchone(): raise HTTPException(404,'Patient not found')
        c.execute('UPDATE patients SET name=%s,phone=%s,dob=%s,gender=%s,notes=%s WHERE id=%s',(x.name,x.phone,x.dob,x.gender,x.notes,pid))
    audit(user,'update','patient',pid); return {'ok':True}
@app.delete('/api/patients/{pid}')
def delete_patient(pid:str,user=Depends(auth)):
    with db() as c: c.execute('DELETE FROM patients WHERE id=%s',(pid,))
    audit(user,'delete','patient',pid); return {'ok':True}

@app.get('/api/appointments')
def appointments(user=Depends(auth)): return rows('SELECT * FROM appointments ORDER BY date,time')
@app.post('/api/appointments')
def add_appointment(x:Appointment,user=Depends(auth)):
    aid=x.id or str(uuid.uuid4())
    with db() as c: c.execute('INSERT INTO appointments(id,patient_id,date,time,reason,status) VALUES(%s,%s,%s,%s,%s,%s)',(aid,x.patientId,x.date,x.time,x.reason,x.status))
    audit(user,'create','appointment',aid); return {'id':aid}
@app.put('/api/appointments/{aid}')
def update_appointment(aid:str,x:Appointment,user=Depends(auth)):
    with db() as c: c.execute('UPDATE appointments SET patient_id=%s,date=%s,time=%s,reason=%s,status=%s WHERE id=%s',(x.patientId,x.date,x.time,x.reason,x.status,aid))
    audit(user,'update','appointment',aid); return {'ok':True}
@app.delete('/api/appointments/{aid}')
def delete_appointment(aid:str,user=Depends(auth)):
    with db() as c: c.execute('DELETE FROM appointments WHERE id=%s',(aid,))
    audit(user,'delete','appointment',aid); return {'ok':True}

@app.get('/api/treatments')
def treatments(user=Depends(auth)): return rows('SELECT * FROM treatments ORDER BY date')
@app.post('/api/treatments')
def add_treatment(x:Treatment,user=Depends(auth)):
    if x.paid>x.charge: raise HTTPException(400,'Amount paid cannot exceed charge')
    tid=x.id or str(uuid.uuid4())
    with db() as c: c.execute('INSERT INTO treatments(id,patient_id,date,tooth,procedure,charge,paid,notes) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',(tid,x.patientId,x.date,x.tooth,x.procedure,x.charge,x.paid,x.notes))
    audit(user,'create','treatment',tid); return {'id':tid}
@app.put('/api/treatments/{tid}')
def update_treatment(tid:str,x:Treatment,user=Depends(auth)):
    if x.paid>x.charge: raise HTTPException(400,'Amount paid cannot exceed charge')
    with db() as c: c.execute('UPDATE treatments SET patient_id=%s,date=%s,tooth=%s,procedure=%s,charge=%s,paid=%s,notes=%s WHERE id=%s',(x.patientId,x.date,x.tooth,x.procedure,x.charge,x.paid,x.notes,tid))
    audit(user,'update','treatment',tid); return {'ok':True}
@app.delete('/api/treatments/{tid}')
def delete_treatment(tid:str,user=Depends(auth)):
    with db() as c: c.execute('DELETE FROM treatments WHERE id=%s',(tid,))
    audit(user,'delete','treatment',tid); return {'ok':True}

@app.get('/api/reports/summary')
def summary(user=Depends(auth)):
    with db() as c:
        p=c.execute('SELECT COUNT(*) n FROM patients').fetchone()['n']; a=c.execute('SELECT COUNT(*) n FROM appointments').fetchone()['n']; t=c.execute('SELECT COUNT(*) n FROM treatments').fetchone()['n']; paid=c.execute('SELECT COALESCE(SUM(paid),0) n FROM treatments').fetchone()['n']; charge=c.execute('SELECT COALESCE(SUM(charge),0) n FROM treatments').fetchone()['n']
    return {'patients':p,'appointments':a,'treatments':t,'paid':paid,'balance':max(charge-paid,0)}
@app.get('/api/audit')
def audit_rows(user=Depends(auth)): return rows('SELECT * FROM audit ORDER BY id DESC')

@app.get('/api/state')
def get_state(user=Depends(auth)):
    out={'patients':rows('SELECT * FROM patients ORDER BY number'),'appointments':rows('SELECT * FROM appointments ORDER BY date,time'),'treatments':rows('SELECT * FROM treatments ORDER BY date')}
    for a in out['appointments']: a['patientId']=a.pop('patient_id')
    for t in out['treatments']: t['patientId']=t.pop('patient_id')
    return out
@app.put('/api/state')
def put_state(s:ClinicState,user=Depends(auth)):
    with db() as c:
        c.execute('DELETE FROM patients'); c.execute('DELETE FROM appointments'); c.execute('DELETE FROM treatments')
        for p in s.patients: c.execute('INSERT INTO patients(id,number,name,phone,dob,gender,notes,registered) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',(p.get('id'),int(p.get('number')),p.get('name',''),p.get('phone',''),p.get('dob',''),p.get('gender',''),p.get('notes',''),p.get('registered') or datetime.now().date().isoformat()))
        for a in s.appointments: c.execute('INSERT INTO appointments(id,patient_id,date,time,reason,status) VALUES(%s,%s,%s,%s,%s,%s)',(a.get('id'),a.get('patientId'),a.get('date'),a.get('time'),a.get('reason',''),a.get('status','Scheduled')))
        for t in s.treatments: c.execute('INSERT INTO treatments(id,patient_id,date,tooth,procedure,charge,paid,notes) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',(t.get('id'),t.get('patientId'),t.get('date'),t.get('tooth',''),t.get('procedure',''),float(t.get('charge',0)),float(t.get('paid',0)),t.get('notes','')))
    audit(user,'sync','clinic_state','victory-dental-clinic'); return {'ok':True,'saved_at':now()}

# Serve the browser app from the same HTTPS origin in production.
frontend=os.path.abspath(os.path.join(os.path.dirname(__file__),'..','frontend'))
if os.path.isdir(frontend):
    app.mount('/', StaticFiles(directory=frontend, html=True), name='frontend')
