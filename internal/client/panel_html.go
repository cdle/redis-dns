package client

import "html/template"

// panelTmpl is the single-page test panel. Served at /panel.
var panelTmpl = template.Must(template.New("panel").Parse(`<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>redis-dns 测试面板</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--tx:#e6edf3;--dim:#8b949e;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--acc:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:18px;margin:0 0 4px}
.sub{color:var(--dim);font-size:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:14px 16px;margin-bottom:16px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:6px 0}
button{background:var(--acc);color:#000;border:0;border-radius:6px;padding:7px 14px;font:inherit;font-weight:600;cursor:pointer}
button.ghost{background:transparent;color:var(--acc);border:1px solid var(--bd)}
button:disabled{opacity:.5;cursor:not-allowed}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--bd);vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px}
.tag{border:1px solid var(--bd);border-radius:4px;padding:1px 6px;font-size:11px;color:var(--dim);margin-left:4px}
.path-local{color:var(--ok)}
.path-upstream{color:var(--warn)}
.rc-noerror{color:var(--ok)}
.rc-nxdomain,.rc-servfail{color:var(--bad)}
.ans{color:var(--dim);font-size:12px;word-break:break-all}
.stat{color:var(--dim)}
.err{color:var(--bad)}
#cacheBox{max-height:260px;overflow:auto}
input[type=checkbox]{accent-color:var(--acc);vertical-align:-2px}
label.pl{cursor:pointer;margin-right:10px;white-space:nowrap}
input[type=text],select{background:var(--bg);color:var(--tx);border:1px solid var(--bd);border-radius:6px;padding:6px 8px;font:inherit}
a{color:var(--acc)}
.legend{color:var(--dim);font-size:12px;margin-top:6px}
</style>
</head>
<body>
<div class="wrap">
  <h1>redis-dns 测试面板</h1>
  <div class="sub">经客户端真实解析链路（本地缓存 → Redis → bwg → 上游）实测 · 本地缓存 <b id="cacheCount">{{.CachedEntries}}</b> 条 · <a href="/reverse/stats">/reverse/stats</a></div>

  <div class="card">
    <div class="row" id="presets">{{range .Presets}}<label class="pl"><input type="checkbox" name="q" value="{{.Name}}|{{.Type}}" data-tag="{{.Tag}}" checked>{{.Name}} <span style="color:var(--dim)">{{.Type}}</span></label>{{end}}
      <input type="text" id="custom" placeholder="自定义域名，如 example.com" style="min-width:230px">
      <select id="customType"><option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option><option>TXT</option><option>NS</option><option>SOA</option></select>
    </div>
    <div class="row">
      <button id="go">▶ 执行测试</button>
      <button id="cold" class="ghost">❄ 清缓存后测试</button>
      <button id="onlyUp" class="ghost">只测国外</button>
      <button id="onlyCn" class="ghost">只测国内</button>
      <button id="selAll" class="ghost">全选</button>
      <span id="elapsed" class="stat"></span>
    </div>
  </div>

  <div class="card">
    <table><thead><tr><th>域名</th><th>类型</th><th>延迟</th><th>路径</th><th>RCODE</th><th>最小TTL</th><th>答案</th></tr></thead>
    <tbody id="rows"></tbody></table>
    <div class="legend">路径 <span class="path-local">local</span>=本地缓存命中；<span class="path-upstream">upstream</span>=经 Redis→SOCKS5→bwg→上游完整链路。同一查询再点一次「执行」即为缓存命中表现。</div>
  </div>

  <div class="card">
    <div class="row"><b>本地缓存内容</b> <button id="refreshCache" class="ghost" style="padding:3px 10px">刷新</button></div>
    <div id="cacheBox"><table><thead><tr><th>域名</th><th>类型</th><th>剩余TTL</th><th>RCODE</th><th>答案数</th></tr></thead><tbody id="cacheRows"></tbody></table></div>
  </div>
</div>

<script>
const esc = s => { const d=document.createElement('div'); d.textContent=(s??'')+''; return d.innerHTML; };
const rows = document.getElementById('rows');

function selQueries(){
  const qs=[...document.querySelectorAll('#presets input[name=q]:checked')].map(c=>{
    const [name,type]=c.value.split('|'); return {name,type};
  });
  const cn=document.getElementById('custom').value.trim();
  if(cn) qs.push({name:cn, type:document.getElementById('customType').value});
  return qs;
}
function setChecked(fn){
  document.querySelectorAll('#presets input[name=q]').forEach(c=>{
    const [name,type]=c.value.split('|');
    c.checked=fn(name,type,c.dataset.tag);
  });
}

async function run(clearFirst){
  const btns=[document.getElementById('go'),document.getElementById('cold')];
  btns.forEach(b=>b.disabled=true);
  try{
    if(clearFirst) await fetch('/panel/cache/clear',{method:'POST'});
    const qs=selQueries();
    const t0=performance.now();
    const r=await fetch('/panel/run',{method:'POST','Content-Type':'application/json',body:JSON.stringify({queries:qs})});
    const data=await r.json();
    const wall=performance.now()-t0;
    document.getElementById('elapsed').textContent =
      '总耗时(含网络) '+wall.toFixed(1)+' ms · 服务端并发耗时 '+data.elapsed_ms.toFixed(1)+' ms · '+data.results.length+' 项';
    rows.innerHTML=data.results.map(x=>{
      const rc=(x.rcode||'').toLowerCase();
      const path=x.path==='local'?'<span class="path-local">local</span>':'<span class="path-upstream">upstream</span>';
      const rcHtml=rc?'<span class="rc-'+esc(rc)+'">'+esc(x.rcode)+'</span>':'—';
      const ans=(x.answers&&x.answers.length)
        ? x.answers.map(a=>'<div class="ans">'+esc(a)+'</div>').join('')
        : (x.error?'<span class="err">'+esc(x.error)+'</span>':'<span class="ans">空应答</span>');
      return '<tr><td>'+esc(x.name)+(x.tag?' <span class="tag">'+esc(x.tag)+'</span>':'')+'</td><td>'+esc(x.type)+'</td>'+
        '<td>'+(x.latency_ms!=null?x.latency_ms.toFixed(1)+' ms':'—')+'</td><td>'+path+'</td><td>'+rcHtml+'</td>'+
        '<td>'+(x.ttl_min_sec>=0?x.ttl_min_sec+'s':'—')+'</td><td>'+ans+'</td></tr>';
    }).join('');
    refreshCache();
  }catch(e){
    rows.innerHTML='<tr><td colspan="7" class="err">'+esc(String(e))+'</td></tr>';
  }finally{ btns.forEach(b=>b.disabled=false); }
}

async function refreshCache(){
  try{
    const r=await fetch('/panel/cache'); const list=await r.json();
    document.getElementById('cacheCount').textContent=list.length;
    document.getElementById('cacheRows').innerHTML=list.map(x=>
      '<tr><td>'+esc(x.name)+'</td><td>'+esc(x.type)+'</td><td>'+x.ttl_sec+'s</td><td>'+esc(x.rcode||'—')+'</td><td>'+x.answers+'</td></tr>').join('');
  }catch(e){ document.getElementById('cacheRows').innerHTML='<tr><td colspan="5" class="err">'+esc(String(e))+'</td></tr>'; }
}

document.getElementById('go').onclick=()=>run(false);
document.getElementById('cold').onclick=()=>run(true);
document.getElementById('refreshCache').onclick=refreshCache;
document.getElementById('onlyUp').onclick=()=>{ setChecked((n,t,p)=>p==='国外'); };
document.getElementById('onlyCn').onclick=()=>{ setChecked((n,t,p)=>p==='国内'); };
document.getElementById('selAll').onclick=()=>{ setChecked(()=>true); };
document.getElementById('custom').addEventListener('keydown',e=>{ if(e.key==='Enter') run(false); });

refreshCache();
</script>
</body>
</html>`))
