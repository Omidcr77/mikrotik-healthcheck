#!/usr/bin/env python3
"""Read-only MikroTik audit. Python 3.10+; RouterOS v6/v7 best effort.
No router configuration writes, scans, packet captures, or disconnects.
"""
from __future__ import annotations
import argparse, base64, getpass, hashlib, html, ipaddress, json, math, re, sys, time, uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
VERSION='1.0.0'
ERROR=re.compile(r'(?im)^(?:syntax error|bad command name|expected |failure:|not enough permissions|no such command|input does not match|invalid value|Script Error)')
SENSITIVE=re.compile(r'password|secret|private-key|preshared-key',re.I)
# Fixed commands and property allowlists. No exports, script contents, or PPP secrets.
SPECS={
'identity':('/system identity','print','name'),
'interfaces':('/interface','print stats-detail','name,type,running,disabled,dynamic,link-downs,last-link-down-time,last-link-up-time,rx-byte,tx-byte,rx-packet,tx-packet,rx-error,tx-error,rx-drop,tx-drop,tx-queue-drop'),
'ethernet':('/interface ethernet','print stats','name,running,disabled,rx-bytes,tx-bytes,rx-packet,tx-packet,rx-broadcast,tx-broadcast,rx-multicast,tx-multicast,rx-fcs-error,rx-align-error,rx-overflow,tx-fcs-error,tx-late-collision,tx-excessive-collision'),
'ethernet_config':('/interface ethernet','print detail','name,running,disabled,loop-protect,loop-protect-status'),
'bridges':('/interface bridge','print detail','name,running,disabled,protocol-mode,igmp-snooping,vlan-filtering,dhcp-snooping'),
'bridge_ports':('/interface bridge port','print detail','interface,bridge,disabled,inactive,bpdu-guard,edge,horizon'),
'eoip':('/interface eoip','print detail','name,running,disabled,remote-address,local-address,tunnel-id,keepalive,actual-mtu'),
'arp':('/ip arp','print detail','address,mac-address,interface,status,complete,invalid,disabled'),
'leases':('/ip dhcp-server lease','print detail','address,mac-address,src-mac-address,server,status,dynamic,disabled,active-address,last-seen'),
'dhcp':('/ip dhcp-server','print detail','name,interface,address-pool,disabled,invalid,conflict-detection'),
'pools':('/ip pool','print detail','.id,name,ranges,next-pool,used,available,total'),
'pool_used':('/ip pool used','print detail','pool,address,owner'),
'addresses':('/ip address','print detail','address,interface,actual-interface,disabled,invalid,dynamic,network'),
'hotspots':('/ip hotspot','print detail','name,interface,address-pool,profile,disabled,invalid'),
'hs_profiles':('/ip hotspot profile','print detail','name,hotspot-address,dns-name,use-radius,radius-accounting,radius-interim-update,login-by'),
'hs_active':('/ip hotspot active','print detail','server,user,address,mac-address,login-by,uptime,radius'),
'hs_hosts':('/ip hotspot host','print detail','server,address,to-address,mac-address,authorized,bypassed'),
'ppp_active':('/ppp active','print detail','name,service,address,caller-id,uptime,radius'),
'nat':('/ip firewall nat','print detail','.id,chain,action,disabled,dynamic,src-address,dst-address,src-address-list,dst-address-list,in-interface,out-interface,in-interface-list,out-interface-list,protocol,src-port,dst-port,to-addresses,to-ports,comment'),
'wg_peers':('/interface wireguard peers','print detail','name,interface,disabled,comment,allowed-address,current-endpoint-address,current-endpoint-port,last-handshake,rx,tx'),
'logging':('/system logging','print detail','topics,action,disabled'),
'logging_actions':('/system logging action','print detail','name,target,memory-lines,disk-lines-per-file,disk-file-count'),
'logs':('/log','print','time,topics,message'),
'files':('/file','print detail','name,type,size,last-modified'),
'graphing':('/tool graphing interface','print detail','interface,store-on-disk,disabled'),
'routes':('/ip route','print detail','dst-address,gateway,active,disabled,dynamic,distance,routing-table,check-gateway'),
'health_table':('/system health','print detail','name,value,type'),
}
SCALARS={'identity':'/system identity print','resource':'/system resource print','health':'/system health print','tracking':'/ip firewall connection tracking print','ppp_aaa':'/ppp aaa print','dude':'/dude print'}

def clean(value):
    if isinstance(value,dict):return {str(k):clean(v) for k,v in value.items() if not SENSITIVE.search(str(k))}
    if isinstance(value,list):return [clean(v) for v in value]
    if isinstance(value,str):return re.sub(r'(?i)((?:password|secret|private-key|preshared-key)\s*[=:]\s*)(?:"[^"]*"|\S+)',r'\1[redacted]',value)
    return value

def number(v):
    if isinstance(v,list):return number(v[0]) if len(v)==1 else None
    if isinstance(v,bool) or v is None:return None
    try:
        n=float(str(v).replace(' ','').replace(',',''));return n if math.isfinite(n) else None
    except (ValueError,TypeError):return None

def yes(v):return v is True or str(v).lower() in ('yes','true','on','1')
def no(v):return v is False or str(v).lower() in ('no','false','off','0')
def items(v):return v if isinstance(v,list) else [x.strip() for x in str(v or '').split(',') if x.strip()]

def size_bytes(v):
    n=number(v)
    if n is not None:return n
    m=re.fullmatch(r'([\d.]+)\s*(KiB|MiB|GiB|TiB|kB|MB|GB|B)',str(v))
    if not m:return None
    return float(m[1])*{'B':1,'KiB':1024,'MiB':1024**2,'GiB':1024**3,'TiB':1024**4,'kB':1000,'MB':1000**2,'GB':1000**3}[m[2]]

def duration(v):
    s=str(v or '');total=0.0
    for amount,unit in re.findall(r'(\d+(?:\.\d+)?)(w|d|h|ms|us|ns|m|s)',s):
        total+=float(amount)*{'w':604800,'d':86400,'h':3600,'m':60,'s':1,'ms':.001,'us':.000001,'ns':.000000001}[unit]
    m=re.search(r'(\d+):(\d+):(\d+(?:\.\d+)?)',s)
    if m:total+=int(m[1])*3600+int(m[2])*60+float(m[3])
    return total if total or s in ('0s','00:00:00') else None

def parse_scalars(text):
    result={}
    for line in text.splitlines():
        m=re.match(r'^\s*([\w-]+):\s*(.*?)\s*$',line)
        if m:result[m[1]]=m[2]
    return result

def parse_frames(text):
    """RouterOS string lengths count bytes; delimiters may occur inside UTF-8 values."""
    blob=text.encode('utf-8');rows=[];current=None;pos=0
    token=re.compile(rb'@@ROW@@|@@FIELD@@(\d+):(\d+):')
    while True:
        m=token.search(blob,pos)
        if not m:break
        if m[0]==b'@@ROW@@':
            current={};rows.append(current);pos=m.end();continue
        if current is None:raise ValueError('Field before row')
        kl,vl=int(m[1]),int(m[2]);end=m.end()+kl+vl
        if end>len(blob):raise ValueError('Truncated length-framed field')
        key=blob[m.end():m.end()+kl].decode('utf-8')
        current[key]=blob[m.end()+kl:end].decode('utf-8');pos=end
    if not rows and text.strip():raise ValueError('Unrecognized legacy response')
    return rows

def parse_detail(text):
    """Last-resort CLI record parser; unsupported tabular formats fail explicitly."""
    flags={}
    for line in text.splitlines():
        if line.startswith('Flags:') or re.match(r'^\s+[A-Z*] - ',line):
            flags.update({k:v.lower() for k,v in re.findall(r'([A-Z*]) - ([\w-]+)',line)})
    rows=[]
    for block in re.split(r'(?m)^\s*(?=\d+\s)',text):
        head=re.match(r'(\d+)\s+([A-Z* ]*)(?=\s|[a-z.])',block)
        if not head:continue
        row=dict(re.findall(r'([\w.-]+)=("(?:\\.|[^"\\])*"|[^\s]+)',block))
        if not row:continue
        for k,v in list(row.items()):
            if v.startswith('"'):row[k]=v[1:-1].replace('\\"','"')
        for flag,name in flags.items():row[name]=flag in head[2]
        rows.append(row)
    if not rows and any(line.strip() and not line.startswith(('Flags:','Columns:')) for line in text.splitlines()):
        raise ValueError('Classic output cannot be parsed safely')
    return rows

@dataclass
class Result:
    rows:list
    status:str='ok'
    method:str=''
    note:str=''
    timestamp:float=0

class Reader:
    def __init__(self,ssh,timeout=12,output_limit=8_000_000):
        self.ssh=ssh;self.timeout=timeout;self.output_limit=output_limit;self.json_support=None;self.methods={}
    def execute(self,command):
        marker='__AUDIT_DONE_'+uuid.uuid4().hex+'__'
        ch=self.ssh.get_transport().open_session(timeout=self.timeout)
        data=bytearray();err=bytearray();deadline=time.monotonic()+self.timeout;status='timeout'
        try:
            ch.settimeout(self.timeout);ch.exec_command(command+'; :put "'+marker+'"')
            while time.monotonic()<deadline:
                if ch.recv_ready():data.extend(ch.recv(65536))
                if ch.recv_stderr_ready():err.extend(ch.recv_stderr(65536))
                if len(data)+len(err)>self.output_limit:status='truncated';break
                if marker.encode() in data:status='ok';break
                if ch.exit_status_ready() and not ch.recv_ready() and not ch.recv_stderr_ready():status='incomplete';break
                time.sleep(.02)
        finally:ch.close()
        text=data.decode('utf-8',errors='replace').replace('\r','').split(marker,1)[0].strip('\n')
        errors=err.decode('utf-8',errors='replace').strip()
        if ERROR.search(text) or errors:status='unsupported/error'
        return text,status,clean(errors or (text[:250] if status!='ok' else ''))
    def scalar(self,name):
        try:
            text,status,note=self.execute(SCALARS[name]);rows=[parse_scalars(text)] if status=='ok' else []
            if status=='ok' and not rows[0]:return Result([],'unparsed','scalar','No recognizable scalar properties',time.time())
            return Result(rows,status,'scalar',note,time.time())
        except Exception as exc:return Result([],'error','scalar',str(exc),time.time())
    def table(self,name):
        if name=='identity':return self.scalar('identity')
        path,verb,fields=SPECS[name];base=f'{path} {verb} as-value proplist={fields}'
        legacy=(':foreach auditRow in=['+path+' '+verb+' as-value] do={ :put "@@ROW@@"; '
                ':foreach auditKey,auditVal in=$auditRow do={ '
                ':if ([:typeof [:find ",'+fields+'," ("," . $auditKey . ",")]] != "nil") do={ '
                ':local auditText [:tostr $auditVal]; :put ("@@FIELD@@" . [:len $auditKey] . ":" . [:len $auditText] . ":" . $auditKey . $auditText) } } }')
        candidates=[('json',':put [:serialize to=json options=json.no-string-conversion value=['+base+']]'),('framed',legacy)]
        if name not in ('wg_peers',):candidates.append(('classic',f'{path} {verb} without-paging'))
        preferred=self.methods.get(name)
        if preferred:candidates.sort(key=lambda x:x[0]!=preferred)
        errors=[]
        for method,command in candidates:
            if method=='json' and self.json_support is False:continue
            try:
                text,status,note=self.execute(command)
                if status in ('timeout','truncated','incomplete'):return Result([],status,method,note or 'Incomplete response excluded from analysis',time.time())
                if status!='ok':
                    if method=='json' and re.search(r'bad command name serialize',text,re.I):self.json_support=False
                    errors.append(f'{method}: {note}');continue
                if method=='json':
                    rows=json.loads(text);rows=[rows] if isinstance(rows,dict) else rows
                    if not isinstance(rows,list) or not all(isinstance(r,dict) for r in rows):raise ValueError('Not a table')
                    self.json_support=True
                elif method=='framed':rows=parse_frames(text)
                else:rows=parse_detail(text)
                allowed=set(fields.split(','))|{'radius','authorized','bypassed'}
                rows=[{k:v for k,v in clean(r).items() if k in allowed} for r in rows]
                self.methods[name]=method;return Result(rows,'ok',method,'',time.time())
            except Exception as exc:errors.append(f'{method}: {exc}')
        return Result([],'unavailable','','; '.join(errors)[:800],time.time())

def ros_quote(value):
    return '"'+str(value).replace('\\','\\\\').replace('"','\\"').replace('$','\\$')+'"'

def link_snapshot(reader, interfaces):
    result=[];errors=[]
    for r in interfaces.rows:
        if not yes(r.get('running')) or not r.get('name'):continue
        name=r['name']
        command='/interface ethernet monitor [find where name='+ros_quote(name)+'] once'
        try:
            text,status,note=reader.execute(command)
            parsed=parse_scalars(text)
            if status=='ok' and parsed:
                result.append(dict(parsed,name=name))
            else:errors.append(name+': '+status+' '+note)
        except Exception as exc:errors.append(name+': '+str(exc))
    return Result(result,'partial' if errors else 'ok','monitor','; '.join(errors),time.time())

def collect(reader,interval=25,progress=print):
    data={};first=['resource','interfaces','ethernet','arp']
    for name in first:
        progress(f'Reading {name} ...');data[name]=reader.scalar(name) if name in SCALARS else reader.table(name)
    for name in list(SCALARS)+list(SPECS):
        if name in data:continue
        progress(f'Reading {name} ...');data[name]=reader.scalar(name) if name in SCALARS else reader.table(name)
    progress('Reading Ethernet link negotiation ...')
    data['ethernet_links']=link_snapshot(reader,data['ethernet_config']) if data['ethernet_config'].status=='ok' else Result([],'unavailable',note='Ethernet inventory unavailable')
    ht=data['health_table']
    if ht.status=='ok' and ht.rows:
        data['health']=Result([{str(r.get('name')):r.get('value') for r in ht.rows}],'ok',ht.method,'',ht.timestamp)
    wait=max(0,interval-(time.time()-max(data[k].timestamp for k in first)))
    if wait:progress(f'Waiting {wait:.0f}s for second sample ...');time.sleep(wait)
    for name in first:
        progress(f'Second sample: {name} ...');data[name+'_after']=reader.scalar(name) if name in SCALARS else reader.table(name)
    return data

def ip(v):
    try:return ipaddress.ip_address(str(v))
    except ValueError:return None

def network(v):
    try:return ipaddress.ip_network(str(v),strict=False)
    except ValueError:return None

def ranges(v):
    result=[]
    for part in items(v):
        try:
            if '-' in part:
                a,b=part.split('-',1);result.append((int(ipaddress.ip_address(a)),int(ipaddress.ip_address(b))))
            else:
                n=network(part)
                if n:result.append((int(n.network_address),int(n.broadcast_address)))
        except ValueError:pass
    return result

def analyze(data,portal_ip=None):
    findings=[];rates=[];checks=[]
    def rows(k):
        r=data.get(k);return r.rows if r and r.status=='ok' else []
    def scalar(k):return next(iter(rows(k)),{})
    def available(*keys):return all(k in data and data[k].status=='ok' for k in keys)
    def add(level,title,evidence,action,category):findings.append(dict(severity=level,title=title,evidence=clean(evidence),action=action,category=category))
    resource=scalar('resource_after') or scalar('resource')
    cpu=number(str(resource.get('cpu-load','')).rstrip('%'))
    if cpu is not None:
        checks.append(f'Latest CPU: {cpu:g}% (point-in-time, not a sustained-load test).')
        if cpu>=85:add('warning','High CPU at sample time',f'{cpu:g}%','Profile CPU during the symptom and compare samples before changing services.','Resources')
    for fk,tk,label in [('free-memory','total-memory','RAM'),('free-hdd-space','total-hdd-space','storage')]:
        free,total=size_bytes(resource.get(fk)),size_bytes(resource.get(tk))
        if free is not None and total:
            pct=free/total*100;checks.append(f'{label}: {free/1024**2:.1f} MiB free ({pct:.1f}%).')
            if pct<15:add('high' if pct<5 else 'warning',f'Low free {label}',f'{pct:.1f}% free','Identify the consumer; preserve backups and live databases. Do not delete files blindly.','Resources')
    health=scalar('health')
    for k,v in health.items():
        if any(x in k for x in ['psu','fan-state']) and str(v).lower() in ('fail','failed','error'):
            add('high',f'Hardware sensor: {k}',f'{k}={v}','Verify power feeds and hardware. A disconnected redundant PSU can report failure.','Hardware')
        if 'temperature' in k and number(v) is not None and number(v)>=80:
            add('warning','Elevated temperature sensor',f'{k}={v}','Check cooling and model-specific specifications; 80 C is a review threshold, not a universal failure limit.','Hardware')
    tracking=scalar('tracking');used,cap=number(tracking.get('total-entries')),number(tracking.get('max-entries'))
    if used is not None and cap:
        checks.append(f'Connection tracking: {int(used):,} / {int(cap):,} entries ({100*used/cap:.1f}%).')
        if used/cap>.8:add('warning','Connection table approaching capacity',f'{used:g}/{cap:g}','Investigate connection sources; do not flush all customer connections.','Resources')
    for r in rows('ethernet_links'):
        if r.get('status')=='link-ok' and no(r.get('full-duplex')):
            add('warning','Ethernet link negotiated half duplex',r,'Check negotiation settings and the remote port; do not force speed blindly.','Interfaces')
        checks.append('Link '+str(r.get('name'))+': '+str(r.get('rate','unknown speed'))+', full duplex='+str(r.get('full-duplex','unknown')))
    reset_names=[];rebooted=False
    u1,u2=duration(scalar('resource').get('uptime')),duration(scalar('resource_after').get('uptime'))
    if u1 is not None and u2 is not None and u2<u1:
        rebooted=True;add('high','Router restarted during audit',f'Uptime changed from {u1}s to {u2}s','Investigate power/reboot logs; interval comparisons are suppressed.','Hardware')
    for dataset in ['ethernet','interfaces']:
        if not available(dataset,dataset+'_after') or rebooted:continue
        before={r.get('name'):r for r in rows(dataset)};dt=data[dataset+'_after'].timestamp-data[dataset].timestamp
        if dt<1:continue
        error_fields=['rx-fcs-error','rx-align-error','rx-overflow','tx-fcs-error','tx-late-collision','tx-excessive-collision'] if dataset=='ethernet' else ['rx-error','tx-error','rx-drop','tx-drop','tx-queue-drop','link-downs']
        for r in rows(dataset+'_after'):
            name=r.get('name')
            if name not in before:continue
            previous=before[name];diff={}
            for k in set(r)&set(previous):
                a,b=number(previous[k]),number(r[k])
                if a is not None and b is not None:diff[k]=b-a
            if any(diff.get(k,0)<0 for k in error_fields+['rx-bytes','tx-bytes','rx-packet','tx-packet','rx-byte','tx-byte']):
                reset_names.append(name);continue
            changes={k:int(diff[k]) for k in error_fields if diff.get(k,0)>0}
            if changes:add('warning',f'Counters increasing: {name}',{'interval_seconds':round(dt,1),'increments':changes},'Correlate with link and remote-device counters. Tunnel TX errors are not proof of cable failure or a loop.','Interfaces')
            if dataset=='ethernet' and not no(r.get('running')):
                def rate(k):return diff[k]/dt if k in diff else None
                rr=dict(interface=name,seconds=round(dt,1))
                for k in ['rx-bytes','tx-bytes','rx-packet','tx-packet','rx-broadcast','rx-multicast']:
                    val=rate(k);rr[k]=round(val*8/1e6 if 'bytes' in k else val,2) if val is not None else None
                rates.append(rr);bc,mc=rate('rx-broadcast'),rate('rx-multicast')
                if (bc is not None and bc>1000) or (mc is not None and mc>5000):add('warning',f'High broadcast/multicast rate: {name}',rr,'Inspect downstream MAC tables, STP changes and multicast sources. Threshold exceedance is not proof of a loop.','Loops / storms')
        checks.append(f'{dataset} interval: {dt:.1f} seconds; only complete samples used.')
    if reset_names:add('info','Counter resets detected',sorted(set(reset_names)),'Rates for reset counters were omitted; repeat with a stable interval.','Coverage')
    if rates and all(r.get('rx-broadcast') is not None and r['rx-broadcast']<=1000 and r.get('rx-multicast') is not None and r['rx-multicast']<=5000 for r in rates):checks.append('No Ethernet broadcast/multicast review threshold exceeded. Intermittent or encapsulated downstream storms remain possible.')
    conflicts=[r for r in rows('leases') if r.get('status') in ('conflict','declined')]
    if conflicts:
        arp={(r.get('interface'),r.get('address')):r for r in rows('arp')};dhcp={r.get('name'):r.get('interface') for r in rows('dhcp')};ev=[]
        for r in conflicts:
            x=dict(r);x['interface']=dhcp.get(r.get('server'));x['arp_mac']=arp.get((x['interface'],r.get('address')),{}).get('mac-address');ev.append(x)
        add('high','DHCP reports address conflicts',ev,'Trace each MAC on the affected switch/AP. Check manual IPs inside the pool and rogue DHCP. Resolve the owner before clearing conflict leases.','IP conflicts')
    elif available('leases'):checks.append('No DHCP conflict/declined lease states in the snapshot.')
    if available('arp','arp_after'):
        a={(r.get('interface'),r.get('address')):r.get('mac-address') for r in rows('arp') if r.get('mac-address')};b={(r.get('interface'),r.get('address')):r.get('mac-address') for r in rows('arp_after') if r.get('mac-address')}
        changes=[{'interface':k[0],'ip':k[1],'before':a[k],'after':b[k]} for k in a.keys()&b.keys() if a[k]!=b[k]]
        if changes:add('warning','IP-to-MAC mappings changed',changes,'Check duplicate IPs, failover/VRRP or legitimate replacements. A change alone does not prove a conflict.','IP conflicts')
        else:checks.append('No MAC changes for matching IP/interface pairs in the two ARP snapshots.')
    if available('hs_active','ppp_active'):
        grouped=defaultdict(list)
        for kind in ['hs_active','ppp_active']:
            for r in rows(kind):
                if r.get('address'):grouped[r['address']].append({'kind':kind,'user':r.get('user',r.get('name')),'server':r.get('server')})
        dup={k:v for k,v in grouped.items() if len(v)>1}
        if dup:add('warning','Repeated subscriber IPs across active sessions',dup,'Verify routing domains. Overlapping addresses across separate VRFs are not necessarily conflicts.','IP conflicts')
        else:checks.append('No repeated IPs across captured active Hotspot and PPP sessions.')
    poolmap={r.get('name'):r for r in rows('pools')};poolids={r.get('.id') for r in rows('pools')};usage=Counter(r.get('pool') for r in rows('pool_used'))
    for name,r in poolmap.items():
        total=number(r.get('total'))
        if total is None:total=sum(b-a+1 for a,b in ranges(r.get('ranges')))
        used=number(r.get('used'))
        if used is None and available('pool_used'):used=usage[name]
        if total and used is not None and used/total>=.85:add('warning',f'Address pool near capacity: {name}',{'used':used,'total':total,'next_pool':r.get('next-pool')},'Check utilization and any next-pool before expanding; avoid static-device overlaps.','DHCP / Hotspot')
    for r in rows('dhcp'):
        if not yes(r.get('disabled')) and yes(r.get('invalid')):add('high',f'Invalid DHCP server: {r.get("name")}',r,'Check interface state, interface address and address pool.','DHCP / Hotspot')
    profiles={r.get('name'):r for r in rows('hs_profiles')}
    for r in rows('hotspots'):
        if yes(r.get('disabled')):continue
        pool=r.get('address-pool')
        if available('pools') and pool and pool!='none' and pool not in poolmap and pool not in poolids:add('high',f'Unresolved Hotspot pool: {r.get("name")}',{'pool':pool,'interface':r.get('interface')},'Verify the intended subnet and replace the stale reference with the correct pool during a controlled change.','DHCP / Hotspot')
        p=profiles.get(r.get('profile'),{});addr=ip(p.get('hotspot-address'));assigned=[a.get('address') for a in rows('addresses') if a.get('interface')==r.get('interface') and not yes(a.get('disabled'))];nets=[network(a) for a in assigned]
        if available('addresses','hs_profiles') and addr and not addr.is_unspecified and not any(n and addr in n for n in nets):add('warning',f'Hotspot address differs from interface subnet: {r.get("name")}',{'hotspot_address':str(addr),'interface_addresses':assigned,'profile':r.get('profile')},'Validate intended addressing and any deliberately routed portal address before changing the profile.','DHCP / Hotspot')
        if yes(p.get('use-radius')) and no(p.get('radius-accounting')):add('warning',f'Hotspot RADIUS accounting disabled: {r.get("name")}',{'profile':r.get('profile')},'Verify accounting requirements with the portal/RADIUS administrator.','Authentication')
    for r in rows('eoip'):
        if not yes(r.get('disabled')) and no(r.get('running')):add('warning',f'Enabled EoIP tunnel is down: {r.get("name")}',r,'Check the remote device, transport reachability, GRE filtering and matching tunnel ID. No remote probe was performed.','Tunnels')
    for r in rows('wg_peers'):
        if yes(r.get('disabled')):continue
        age=duration(r.get('last-handshake'))
        if not r.get('last-handshake') and not r.get('current-endpoint-address'):add('info',f'WireGuard peer has no learned endpoint: {r.get("name",r.get("interface"))}',r,'May be normal for an offline/on-demand client. Correlate with TX errors and routes before treating it as an outage.','Tunnels')
        elif age is not None and age>600:add('info',f'Old WireGuard handshake: {r.get("name",r.get("interface"))}',r,'Check expected traffic/keepalive; idle peers need not maintain recent handshakes.','Tunnels')
    logs=rows('logs');failures=[r for r in logs if 'authentication failed' in str(r.get('message','')).lower()]
    if len(failures)>=20:
        users=Counter()
        for r in failures:
            m=re.search(r'user (.*?) authentication failed',r.get('message',''));users[m[1] if m else '(unspecified)']+=1
        add('warning','Repeated authentication failures in retained logs',{'count':len(failures),'log_records':len(logs),'first_log':logs[0].get('time') if logs else '', 'last_log':logs[-1].get('time') if logs else '', 'top_users':users.most_common(10)},'Check RADIUS rejection reasons and customer account/credential state. Retries are not proof of an Ethernet storm.','Authentication')
    for label,pattern,action in [('Loop/conflict-related log messages',r'loop|duplicate address|address conflict','Corroborate the named devices with switch MAC/STP history and counters.'),('Hotspot address-allocation errors',r'failed to get IP address|unknown id \(4\)','Check stale pool references, DHCP availability and the host MAC on the relevant site.')]:
        matches=[r for r in logs if re.search(pattern,r.get('message',''),re.I)]
        if matches:add('warning',label,matches[-15:],action,'Logs')
    if available('logging') and not any(not yes(r.get('disabled')) and 'warning' in items(r.get('topics')) for r in rows('logging')):
        add('warning','No enabled explicit warning logging rule found','Other topic-based rules may still capture some warnings.','Review logging coverage and retention; consider remote logging for intermittent faults.','Observability')
    ports=[r for r in rows('bridge_ports') if not yes(r.get('disabled'))]
    for r in rows('bridges'):
        members=[p for p in ports if p.get('bridge')==r.get('name')]
        if not yes(r.get('disabled')) and len(members)>1 and r.get('protocol-mode')=='none':add('warning',f'Spanning tree disabled: {r.get("name")}',{'ports':[p.get('interface') for p in members]},'Review topology and downstream STP before enabling it; avoid blanket changes.','Loops / storms')
    off=[r.get('name') for r in rows('ethernet_config') if yes(r.get('running')) and (r.get('loop-protect-status')=='off' or r.get('loop-protect') in ('off','default'))]
    if off:add('info','Ethernet loop-protect is not active on some ports',off,'Not evidence of a loop. Review downstream STP and storm control. Loop-protect can shut down ports and needs topology planning.','Loops / storms')
    for r in rows('nat'):
        if yes(r.get('disabled')) or yes(r.get('dynamic')):continue
        if r.get('chain')=='srcnat' and r.get('action')=='masquerade' and r.get('src-address') and not any(r.get(k) for k in ['out-interface','out-interface-list','dst-address','dst-address-list']):add('warning','Broad masquerade may hide subscriber identity from internal portals',r,'Evaluate rule order and the actual portal flow. Preserve customer IP only after confirming return routing. This candidate is not proof a flow is translated.','Portal / NAT')
        if r.get('chain')=='dstnat' and r.get('action')=='dst-nat' and str(r.get('to-ports'))=='80' and r.get('protocol')=='tcp' and not r.get('dst-port'):add('warning','TCP redirect to HTTP lacks a destination-port restriction',r,'Review whether this should match TCP 80 only. HTTPS redirected to plain HTTP cannot provide valid TLS.','Portal / NAT')
    if portal_ip:checks.append(f'Portal target: {portal_ip}. Source IP at the web server and RADIUS session matching are NOT verified by this router-only audit.')
    large=sorted([r for r in rows('files') if size_bytes(r.get('size')) is not None],key=lambda r:size_bytes(r.get('size')),reverse=True)[:8]
    dude=scalar('dude')
    if yes(dude.get('enabled')):add('info','The Dude is enabled on this router',{'status':dude.get('status'),'largest_files':large},'Monitor database/WAL growth and storage I/O. Never delete a live database or WAL as a quick cleanup.','Storage')
    graph=[r for r in rows('graphing') if not yes(r.get('disabled')) and yes(r.get('store-on-disk'))]
    if graph:add('info','Interface graphs are stored on disk',graph,'Review disk write workload together with databases and logs. This setting alone does not prove a performance problem.','Storage')
    f1,f2=size_bytes(scalar('resource').get('free-hdd-space')),size_bytes(scalar('resource_after').get('free-hdd-space'))
    if f1 is not None and f2 is not None and f1-f2>5*1024**2:add('warning','Free storage fell during the audit',{'before_MiB':round(f1/1024**2,1),'after_MiB':round(f2/1024**2,1)},'Track a longer interval. Database journals fluctuate; do not extrapolate a disk-full date from this sample.','Storage')
    incomplete=[{'check':k,'status':r.status,'note':r.note} for k,r in data.items() if r.status!='ok']
    if incomplete:add('info','Some checks were unavailable or incomplete',incomplete,'Review permissions, version support and timeouts. Missing data is not treated as healthy.','Coverage')
    grouped_findings={}
    for f in findings:
        key=(f['severity'],f['category'],f['title'])
        if key not in grouped_findings:grouped_findings[key]=dict(f)
        else:
            g=grouped_findings[key]
            if not g.get('_grouped'):
                g['evidence']=[g['evidence']];g['_grouped']=True
            g['evidence'].append(f['evidence'])
    findings=list(grouped_findings.values())
    for f in findings:f.pop('_grouped',None)
    findings.sort(key=lambda r:{'high':0,'warning':1,'info':2}[r['severity']])
    return {'findings':findings,'rates':rates,'checks':checks,'resource':resource,'health':health,'identity':scalar('identity').get('name','Unknown'),'largest_files':large}

def report_html(report):
    esc=lambda v:html.escape(str(v),quote=True)
    result=report['analysis'];findings=result['findings'];counts=Counter(f['severity'] for f in findings)
    def evidence(v):return esc(v if isinstance(v,str) else json.dumps(v,ensure_ascii=False,indent=2))
    cards=''.join(f'<article class="finding {esc(f["severity"])}" data-severity="{esc(f["severity"])}"><div class="eyebrow">{esc(f["category"])} / {esc(f["severity"].upper())}</div><h3>{esc(f["title"])}</h3><p>{esc(f["action"])}</p><details><summary>Evidence</summary><pre>{evidence(f["evidence"])}</pre></details></article>' for f in findings)
    rate_rows=''.join('<tr>'+''.join(f'<td>{esc(r.get(k) if r.get(k) is not None else "Not available")}</td>' for k in ['interface','seconds','rx-bytes','tx-bytes','rx-packet','rx-broadcast','rx-multicast'])+'</tr>' for r in result['rates'])
    coverage=''.join(f'<tr><td>{esc(k)}</td><td>{esc(v["status"])}</td><td>{esc(v["method"])}</td><td>{esc(v["note"])}</td></tr>' for k,v in report['coverage'].items())
    metrics=[('HIGH',counts['high']),('REVIEW',counts['warning']),('INFORMATION',counts['info']),('CHECKS READ',sum(v['status']=='ok' for v in report['coverage'].values()))]
    metric_html=''.join(f'<div class="metric"><strong>{v}</strong><span>{k}</span></div>' for k,v in metrics)
    checks=''.join(f'<li>{esc(c)}</li>' for c in result['checks'])
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MikroTik health audit</title><style>
:root{color-scheme:light;--ink:#142534;--muted:#566777;--border:#dbe4ea}*{box-sizing:border-box}body{margin:0;background:#f3f6f8;color:var(--ink);font:16px/1.6 system-ui,sans-serif}header{background:#102d3b;color:white;padding:48px max(24px,calc((100vw - 1120px)/2))}header p{color:#bcd2dc}.eyebrow{font-size:12px;letter-spacing:.08em;text-transform:uppercase;font-weight:700}h1{font-size:clamp(28px,4vw,44px);line-height:1.2;margin:14px 0}h2{margin-top:36px}h3{margin:8px 0;font-size:20px}main{max-width:1168px;margin:auto;padding:28px 24px 64px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.metric,.panel,.finding{background:white;border:1px solid var(--border);border-radius:12px;padding:22px}.metric strong{display:block;font-size:34px}.metric span{font-size:12px;color:var(--muted);letter-spacing:.08em}.finding{margin:16px 0;border-left:5px solid #3e7e9b}.finding.high{border-left-color:#bd3545}.finding.warning{border-left-color:#c88a22}.finding p{margin:8px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f6f8;padding:16px;border-radius:8px;font-size:12px}summary{cursor:pointer;color:#35667e;font-weight:600}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:12px;border-bottom:1px solid var(--border);vertical-align:top}th{font-size:12px;color:var(--muted);background:#f8fafb}.scroll{overflow:auto}button{background:white;color:var(--ink);border:1px solid #b7c8d3;border-radius:6px;padding:9px 14px;margin:0 6px 8px 0;cursor:pointer}button[aria-pressed=true]{background:#102d3b;color:white}.note{color:var(--muted)}a{color:#226984}.hidden{display:none}footer{margin-top:32px;font-size:13px;color:var(--muted)}@media(max-width:650px){.metrics{grid-template-columns:repeat(2,1fr)}}@media print{header{background:white;color:black;padding:20px}header p{color:black}body{background:white}.filters{display:none}.hidden{display:block}.finding{break-inside:avoid}main{padding:0}.scroll{overflow:visible}details>pre{display:block}}
</style></head><body><header><div class="eyebrow">Read-only network diagnostics</div><h1>MikroTik health audit</h1><p>'''+esc(result['identity'])+' / '+esc(report['host'])+' / RouterOS '+esc(result['resource'].get('version','unknown'))+'</p><p>'+esc(report['created_at'])+'''</p></header><main><div class="metrics">'''+metric_html+'''</div><div class="panel" style="margin-top:20px"><strong>Snapshot, not a clean bill of health.</strong><p>No router configuration changes, captures, scans, counter resets or disconnects were performed. A router-only audit cannot rule out downstream-only loops, intermittent faults, rogue DHCP servers or application session-matching failures. Findings are review items; repeated items are not necessarily separate root causes.</p></div><h2>Findings and next steps</h2><div class="filters"><button data-filter="all" aria-pressed="true">All</button><button data-filter="high" aria-pressed="false">High</button><button data-filter="warning" aria-pressed="false">Review</button><button data-filter="info" aria-pressed="false">Information</button><button id="print">Print / save PDF</button></div>'''+(cards or '<p>No findings generated from available data. Review coverage and limitations.</p>')+'''<h2>Measured traffic</h2><p class="note">Mbps and packets/second, using each dataset's own sample interval. Counter resets/reboots invalidate comparisons.</p><div class="panel scroll"><table><thead><tr><th>Interface</th><th>Seconds</th><th>RX Mbps</th><th>TX Mbps</th><th>RX pps</th><th>Broadcast pps</th><th>Multicast pps</th></tr></thead><tbody>'''+rate_rows+'''</tbody></table></div><h2>Observations</h2><div class="panel"><ul>'''+checks+'''</ul><details><summary>Hardware sensors</summary><pre>'''+evidence(result['health'])+'''</pre></details></div><h2>Collection coverage</h2><p class="note">Unsupported features and incomplete reads are explicit. Older releases can provide less coverage. Legacy SSH algorithms are not automatically weakened.</p><div class="panel scroll"><table><thead><tr><th>Check</th><th>Status</th><th>Parser</th><th>Details</th></tr></thead><tbody>'''+coverage+'''</tbody></table></div><footer>Generated by MikroTik Healthcheck '''+VERSION+'''. Reports contain network addresses and subscriber identifiers. No SSH password or key material is included.<br>References: <a href="https://help.mikrotik.com/docs/spaces/ROS/pages/8323191/Ethernet">Ethernet counters</a> / <a href="https://help.mikrotik.com/docs/spaces/ROS/pages/23396469/Loop%2BProtect">Loop Protect</a> / <a href="https://help.mikrotik.com/docs/spaces/ROS/pages/24805500/DHCP">DHCP</a></footer></main><script>
document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('[data-filter]').forEach(x=>x.setAttribute('aria-pressed',String(x===b)));document.querySelectorAll('.finding').forEach(x=>x.classList.toggle('hidden',b.dataset.filter!=='all'&&x.dataset.severity!==b.dataset.filter));}));document.getElementById('print').addEventListener('click',()=>{document.querySelectorAll('details').forEach(x=>x.open=true);window.print();});
</script></body></html>'''

def write_reports(data,host,outdir,portal_ip=None):
    report={'tool_version':VERSION,'created_at':datetime.now(timezone.utc).isoformat(),'host':host,'analysis':analyze(data,portal_ip),'coverage':{k:{'status':r.status,'method':r.method,'note':clean(r.note),'timestamp':r.timestamp,'row_count':len(r.rows)} for k,r in data.items()}}
    outdir=Path(outdir);outdir.mkdir(parents=True,exist_ok=True)
    stamp=datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6];stem=outdir/('mikrotik-audit-'+stamp)
    hf,jf=stem.with_suffix('.html'),stem.with_suffix('.json')
    hf.write_text(report_html(report),encoding='utf-8');jf.write_text(json.dumps(clean(report),ensure_ascii=False,indent=2),encoding='utf-8')
    return hf,jf,report

def connect(args,password):
    try:import paramiko
    except ImportError:raise RuntimeError('Install first: python -m pip install -r requirements.txt') from None
    known=Path(args.known_hosts).expanduser();known.parent.mkdir(parents=True,exist_ok=True)
    class VerifyHost(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self,client,hostname,key):
            fp='SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
            print(f'\nNew SSH host: {hostname}\nKey: {key.get_name()} {fp}')
            accepted=args.fingerprint==fp if args.fingerprint else input('Verify this fingerprint with your administrator. Trust and remember? [yes/no]: ').strip().lower()=='yes'
            if not accepted:raise paramiko.SSHException('Host key not trusted')
            client.get_host_keys().add(hostname,key.get_name(),key);client.save_host_keys(str(known))
    client=paramiko.SSHClient();client.load_system_host_keys()
    if known.exists():client.load_host_keys(str(known))
    client.set_missing_host_key_policy(VerifyHost())
    try:
        client.connect(args.host,port=args.port,username=args.user,password=password,timeout=args.timeout,banner_timeout=args.timeout,auth_timeout=args.timeout,look_for_keys=False,allow_agent=False)
        key=client.get_transport().get_remote_server_key();actual='SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        if args.fingerprint and actual!=args.fingerprint:raise paramiko.SSHException('Pinned fingerprint does not match')
        return client
    except Exception:client.close();raise

def demo_data():
    t=time.time();d={}
    def put(k,rs,when=t):d[k]=Result(rs,'ok','demo','Synthetic data; no router contacted',when)
    put('identity',[{'name':'DEMO - Branch Gateway'}])
    put('resource',[{'version':'7.x DEMO','board-name':'Synthetic router','uptime':'1d','cpu-load':'29%','free-memory':'2GiB','total-memory':'4GiB','free-hdd-space':'400MiB','total-hdd-space':'1GiB'}])
    put('resource_after',[dict(d['resource'].rows[0],uptime='1d30s')],t+30)
    put('health',[{'psu1-state':'ok','psu2-state':'fail','cpu-temperature':'58'}])
    put('ethernet',[{'name':'ether1','running':True,'rx-bytes':0,'tx-bytes':0,'rx-packet':0,'rx-broadcast':0,'rx-multicast':0}])
    put('ethernet_after',[{'name':'ether1','running':True,'rx-bytes':300000000,'tx-bytes':30000000,'rx-packet':500000,'rx-broadcast':90,'rx-multicast':60}],t+30)
    put('leases',[{'address':'10.0.35.91','server':'dhcp35','status':'conflict','src-mac-address':'02:00:00:00:00:91'}]);put('dhcp',[{'name':'dhcp35','interface':'eoip35'}])
    put('arp',[{'address':'10.0.35.91','interface':'eoip35','mac-address':'02:00:00:00:00:91'}]);put('arp_after',d['arp'].rows,t+30)
    put('hotspots',[{'name':'hs1','interface':'eoip1','profile':'profile1','address-pool':'*DEAD'}]);put('hs_profiles',[{'name':'profile1','hotspot-address':'10.0.18.1'}]);put('addresses',[{'address':'10.0.14.1/23','interface':'eoip1'}]);put('pools',[])
    put('eoip',[{'name':'eoip12','running':False,'disabled':False,'remote-address':'10.0.1.12'}]);put('logging',[{'topics':['warning'],'disabled':True,'action':'memory'}]);put('nat',[{'chain':'srcnat','action':'masquerade','src-address':'10.0.14.0/23'}])
    d['wg_peers']=Result([],'unavailable','demo','Example unsupported feature',t)
    return d

def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--host',help='Router IP or hostname; prompted if omitted');p.add_argument('--user',help='SSH username; prompted if omitted');p.add_argument('--port',type=int,default=22)
    p.add_argument('--interval',type=int,default=25,help='Minimum seconds between samples (5-300)');p.add_argument('--timeout',type=int,default=12,help='Per-command deadline in seconds (3-120)')
    p.add_argument('--portal-ip',help='Optional internal portal IP for report context');p.add_argument('--output',default='reports',help='Local report directory')
    p.add_argument('--known-hosts',default=str(Path.home()/'.mikrotik-healthcheck'/'known_hosts'));p.add_argument('--fingerprint',help='Expected SHA256 SSH host-key fingerprint')
    p.add_argument('--demo',action='store_true',help='Generate synthetic example without connecting');args=p.parse_args()
    if not 5<=args.interval<=300 or not 3<=args.timeout<=120 or not 1<=args.port<=65535:p.error('interval: 5-300, timeout: 3-120, port: 1-65535')
    if args.portal_ip and ip(args.portal_ip) is None:p.error('--portal-ip must be a valid IP address')
    print(f'\nMikroTik Healthcheck {VERSION} | read-only audit\n')
    try:
        if args.demo:args.host='DEMO - no router contacted';data=demo_data()
        else:
            args.host=args.host or input('Router IP / hostname: ').strip();args.user=args.user or input('SSH username [admin]: ').strip() or 'admin'
            if not args.host or any(c.isspace() for c in args.host):p.error('Enter a hostname or IP without spaces')
            password=getpass.getpass('SSH password (hidden): ');client=connect(args,password);password=None
            try:data=collect(Reader(client,args.timeout),args.interval)
            finally:client.close()
        hf,jf,report=write_reports(data,args.host,args.output,args.portal_ip);counts=Counter(x['severity'] for x in report['analysis']['findings'])
        print(f'\nFinished: {counts["high"]} high, {counts["warning"]} review, {counts["info"]} informational findings.')
        print(f'HTML report: {hf.resolve()}\nJSON report: {jf.resolve()}\nNo router configuration changes. Review collection coverage before drawing conclusions.')
        return 0
    except KeyboardInterrupt:print('\nCancelled. Router configuration was not changed.',file=sys.stderr);return 130
    except Exception as exc:
        print(f'\nAudit could not finish: {clean(str(exc))}',file=sys.stderr);print('Check SSH access, credentials, permissions and host-key trust. No router configuration changes were requested.',file=sys.stderr);return 1

if __name__=='__main__':raise SystemExit(main())
