#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
坚果VPN 账号池轮换 (GitHub Actions 定时跑)
- 扫描账号池: 找有有效订阅的号, 没有就 claim_free
- 拉取节点 -> 生成 QX 格式 -> PATCH 到指定 Gist 文件
- 环境变量: GIST_TOKEN(gist scope token), GIST_ID
"""
import json, os, time, base64, urllib.request, urllib.parse

API = 'https://api.edublogapi.com'
GIST_TOKEN = os.environ['GIST_TOKEN']
GIST_ID = os.environ['GIST_ID']
FILE = 'nut-qx.txt'
POOL = json.load(open('pool.json'))

def req(url, data=None, hdr=None, method=None):
    h = {'Content-Type': 'application/json'}
    if hdr: h.update(hdr)
    r = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None, headers=h, method=method)
    return urllib.request.urlopen(r, timeout=30)

def post(path, data, hdr=None):
    return json.load(req(API + path, data, hdr))

def active_sub(jwt):
    try:
        j = post('/v1/public/user/subscribe', None, {'Authorization': jwt})
        now = time.time()
        act = [x for x in j['data']['list'] if x['status'] == 1 and x['expire_time'] > now]
        return max(act, key=lambda x: x['expire_time']) if act else None
    except Exception:
        return None

def build_conf(sub_token):
    r = req(API + '/api/subscribe?token=%s&flag=clash' % sub_token, hdr={'User-Agent': 'ClashforWindows/0.20.39'})
    raw = base64.b64decode(r.read().decode().strip()).decode()
    lines = []
    for l in raw.splitlines():
        l = l.strip()
        if not l.startswith('vless://'): continue
        try:
            main, frag = l[8:].split('#')
            name = urllib.parse.unquote(frag)
            hp, qs = main.split('?')
            q = dict(p.split('=', 1) for p in qs.split('&'))
            uuid, hp2 = hp.split('@', 1)
            host, port = hp2.rsplit(':', 1)
            lines.append('vless=%s:%s, method=none, password=%s, obfs=over-tls, obfs-host=%s, reality-base64-pubkey=%s, reality-hex-shortid=%s, vless-flow=xtls-rprx-vision, tls-verification=false, udp=true, fast-open=true, tag=%s'
                         % (host, port, uuid, q['sni'], q['pbk'], q['sid'], name))
        except Exception:
            pass
    return lines

def patch_gist(text):
    body = json.dumps({'files': {FILE: {'content': text}}}).encode()
    r = urllib.request.Request('https://api.github.com/gists/' + GIST_ID, data=body,
        headers={'Authorization': 'token ' + GIST_TOKEN, 'Content-Type': 'application/json'}, method='PATCH')
    urllib.request.urlopen(r, timeout=30)
    print('gist patched,', len(text), 'bytes')

def main():
    n = len(POOL)
    for k in range(n):
        idx = k
        acc = POOL[idx]
        try:
            jwt = post('/v1/auth/login', {'email': acc['email'], 'password': acc['password']})['data']['token']
            act = active_sub(jwt)
            if not act:
                c = post('/v1/public/subscribe/claim_free', {}, {'Authorization': jwt})
                if not (c.get('code') == 200 and c.get('data', {}).get('success')):
                    print('[skip] %s: %s' % (acc['email'], c.get('msg', c.get('code'))))
                    continue
                for _ in range(3):
                    time.sleep(2)
                    act = active_sub(jwt)
                    if act: break
            if not act:
                print('[skip] %s: no-active-sub' % acc['email']); continue
            lines = build_conf(act['token'])
            if not lines:
                print('[skip] %s: empty nodes' % acc['email']); continue
            patch_gist('\n'.join(lines) + '\n')
            print('[ok] %s -> %d nodes, expire %s' % (acc['email'], len(lines), act['expire_time']))
            return
        except Exception as e:
            print('[err] %s: %s' % (acc['email'], e))
    print('WARN: 全池不可用')

main()
