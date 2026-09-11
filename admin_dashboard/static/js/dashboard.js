/* All event-derived content is inserted as text, never interpreted as HTML. */
(() => {
  const page = document.body.dataset.page;
  const canManage = document.body.dataset.role === 'ADMIN';
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const $ = id => document.getElementById(id);
  let busy = false, currentPage = Number(new URLSearchParams(location.search).get('page') || 1), totalPages = 1;
  let ipKind = '';
  const node = (tag, text, cls) => { const el=document.createElement(tag); if(text!==undefined)el.textContent=text; if(cls)el.className=cls; return el; };
  const number = v => Number(v||0).toLocaleString();
  const date = v => v ? new Date(v).toISOString().replace('T',' ').slice(0,19) : '—';
  const badge = value => node('span',value||'INFO','badge '+String(value||'INFO').replace(/[^A-Z_]/g,''));
  const link = e => { const a=node('a',e.incident_id ? e.incident_id.slice(0,18)+'…' : 'Legacy event'); if(e.incident_id){a.href='/events/'+encodeURIComponent(e.incident_id);a.title=e.incident_id;} return a; };
  function notice(message) { $('notice').textContent=message; $('notice').hidden=false; }
  async function api(path, method='GET', data) {
    const response=await fetch(path,{method,credentials:'same-origin',headers:{'X-CSRF-Token':csrf,...(data ? {'Content-Type':'application/json'} : {})},...(data?{body:JSON.stringify(data)}:{})});
    if(response.status===401){location.href='/login';throw new Error('Session expired');}
    const result=await response.json();
    if(!response.ok)throw new Error(result.error||'Request failed');
    return result;
  }
  function table(id, headers, rows) {
    const parent=$(id); if(!parent)return;
    parent.replaceChildren();
    if(!rows.length){parent.append(node('div','No matching activity yet.','empty'));return;}
    const t=node('table'),thead=node('thead'),tr=node('tr');
    headers.forEach(x=>tr.append(node('th',x)));thead.append(tr);t.append(thead);
    const body=node('tbody');
    rows.forEach(row=>{const tr=node('tr');row.forEach(value=>{const td=node('td');value instanceof Node?td.append(value):td.textContent=value??'—';tr.append(td);});body.append(tr);});
    t.append(body);parent.append(t);
  }
  function events(data) {
    table('recent-events',['Time (UTC)','Incident ID','Source IP','Method','Path','Category','Severity','Rules','Score','Decision','Status'],
      data.items.map(e=>[date(e.timestamp),link(e),e.source_ip,e.method,e.path,e.category_name||e.attack_category,badge(e.severity),(e.matched_rules||[]).join(', '),e.threat_score,badge(e.decision),e.response_status]));
    if($('event-total'))$('event-total').textContent=number(data.total)+' matching events';
    pagination(data);
  }
  function pagination(data) {
    if(!$('page-count'))return;
    totalPages=data.pages;
    $('page-count').textContent='Page '+data.page+' of '+data.pages;
    $('prev-page').disabled=currentPage<=1;$('next-page').disabled=currentPage>=data.pages;
  }
  function summary(data) {
    document.querySelectorAll('[data-metric]').forEach(el=>el.textContent=number(data[el.dataset.metric]));
    $('alert-count').textContent=number(data.active_alerts);
  }
  function analytics(data) {
    WafCharts.analytics(data);
    if($('severity-count'))$('severity-count').textContent=number((data.severity.HIGH||0)+(data.severity.CRITICAL||0))+' HIGH + CRITICAL';
    table('top-ips',['Source IP','Attacks','Stopped','Last seen','Primary attack','Status'],
      data.top_ips.map(x=>[x.source_ip,number(x.attacks),number(x.blocked),date(x.last_seen),x.primary_category,x.status]));
    table('analytics-table',['Module','Attack category','Attacks','Share','Stopped','Avg score','Top source','Top endpoint'],
      data.categories.map(c=>[c.code,c.name,number(c.count),c.percentage+'%',number(c.blocked),c.average_score,c.top_ip,c.top_path]));
    if($('top-paths')){
      $('top-paths').replaceChildren();
      data.top_paths.forEach((x,i)=>{const r=node('div',undefined,'rank-item');r.append(node('small',String(i+1).padStart(2,'0')),node('span',x.path),node('b',number(x.attacks)));$('top-paths').append(r);});
      if(!data.top_paths.length)$('top-paths').append(node('p','No targeted endpoints yet.','empty'));
    }
  }
  function toggle(kind,id,enabled) {
    const b=node('button',enabled?'Enabled':'Disabled','toggle '+(enabled?'on':''));
    b.setAttribute('aria-pressed',String(enabled));
    if(!canManage)b.disabled=true;
    b.addEventListener('click',async()=>{b.disabled=true;try{const r=await api('/api/'+kind+'/'+encodeURIComponent(id),'PUT',{enabled:!enabled});notice(r.message);await refresh(true);}catch(e){notice(e.message);}finally{b.disabled=false;}});
    return b;
  }
  function rules(data){
    $('detectors').replaceChildren();
    data.detectors.forEach((d,i)=>{const el=node('article',undefined,'detector');el.append(node('span','0'+(i+1),'tag'),node('p',d.id.replaceAll('_',' ')),toggle('detectors',d.id,d.enabled));$('detectors').append(el);});
    table('rules-table',['Rule ID','Name','Category','Severity','Score','Action','State','Configure'],
      data.rules.map(r=>{const edit=node('button','Edit','secondary');edit.addEventListener('click',()=>{for(const key of ['id','score','action','severity'])$('edit-rule-'+key).value=r[key];$('edit-rule-literals').disabled=!r.pattern_editable;$('edit-rule-literals').value=(r.literal_patterns||[]).join('\n');$('rule-form').scrollIntoView({block:'center'});});return [r.id,r.name,r.category,badge(r.severity),r.score,r.action||'BLOCK',toggle('rules',r.id,r.enabled),edit];}));
  }
  function acknowledgeButton(id,done) {
    if(done)return badge('ACKNOWLEDGED');
    const button=node('button','Acknowledge','secondary');
    if(!canManage)button.disabled=true;
    button.addEventListener('click',()=>ack(id,button));return button;
  }
  async function ack(id,button) {
    button.disabled=true;
    try{await api('/api/alerts/'+id+'/acknowledge','POST');notice('Alert acknowledged.');if(page==='detail')button.textContent='Acknowledged';await refresh(true);}catch(e){notice(e.message);button.disabled=false;}
  }
  function alerts(data) {
    table('alerts-table',['Time (UTC)','Incident','Source IP','Category','Severity','Message','Status'],
      data.items.map(a=>[date(a.timestamp),link(a),a.source_ip,a.category,badge(a.severity),a.message,acknowledgeButton(a.id,a.acknowledged)]));
    pagination(data);
  }
  function ipPolicies(data){
    table('ip-table',['IP address','Policy','Reason','Created','Expires / remaining','Added by','Incident','Scope','Source','Trust mode','Action'],
      data.map(p=>{const button=node('button',p.kind==='temporary'?'Unblock':'Remove','secondary');
        button.addEventListener('click',async()=>{try{await api('/api/ip','POST',{operation:'remove',kind:p.kind,ip:p.ip});notice('Policy removed; the WAF applies the change on its next request.');await refresh(true);}catch(e){notice(e.message);}});
        return [p.ip,p.kind,p.reason,date(p.created_at*1000),p.expires_at?date(p.expires_at*1000)+' / '+Math.max(0,Math.ceil(p.expires_at-Date.now()/1000))+'s':'Never',p.added_by,p.incident_id||'—',p.scope,p.source,p.trust_mode,button];}));
  }
  function status(data) {
    if($('backend-state'))$('backend-state').textContent='Backend '+data.backend;
    $('live-state').textContent=data.status==='online'?'WAF connected':'WAF '+data.status;
    $('live-dot').classList.toggle('offline',data.status!=='online');
    if(page!=='system')return;
    $('system-cards').replaceChildren();
    for(const[label,value]of [['WAF',data.status],['Backend',data.backend],['Dashboard',data.dashboard],['Database',data.database]]){
      const card=node('article',undefined,'metric');card.append(node('div',label),node('strong',value),node('small','Live service status'));$('system-cards').append(card);
    }
    const dl=node('dl');
    for(const[label,value]of [['WAF URL',data.waf_url],['Backend host',data.backend_host],['Backend port',data.backend_port],['Dashboard port',data.dashboard_port],['Enabled rules',data.enabled_rules],['Detection',data.detection_enabled],['Prevention',data.prevention_enabled],['Rate limiting',data.rate_limiting_enabled],['Temporary blocking',data.temporary_blocking_enabled]]){
      dl.append(node('dt',label),node('dd',value===true?'Enabled':value===false?'Disabled':value??'Unavailable'));
    }
    $('system-info').replaceChildren(dl);
    table('rate-table',['Source IP','Request count','Limit','Window (seconds)','Remaining (seconds)'],(data.rate_limits||[]).map(r=>[r.source_ip,r.request_count,r.limit,r.window,r.remaining_seconds]));
    table('brute-table',['Source IP','Failed attempts','Block remaining (seconds)'],(data.brute_force||[]).map(r=>[r.source_ip,r.failures,r.remaining_seconds]));
  }
  function eventQuery(){
    const args=new URLSearchParams(location.search);args.set('page',currentPage);
    for(const kind of ['csv','json'])if($(kind+'-export')){const q=new URLSearchParams(args);q.set('format',kind);q.delete('page');$(kind+'-export').href='/api/events/export?'+q;}
    return args;
  }
  function evaluation(data){
    if(!data.available){$('evaluation-source').textContent=data.message;return;}
    const r=data.report,m=r.effectiveness,p=r.performance;
    $('evaluation-source').textContent='Run '+r.run_id+' · '+date(r.created_at)+' UTC · '+r.dataset;
    $('evaluation-cards').replaceChildren();
    for(const [label,value]of [['Detection rate',m.detection_rate],['Blocking rate',m.blocking_rate],['False positive rate',m.false_positive_rate],['Precision',m.precision]]){const el=node('article',undefined,'metric');el.append(node('div',label),node('strong',value==null?'Unavailable':(value*100).toFixed(1)+'%'),node('small','Measured synthetic scenarios'));$('evaluation-cards').append(el);}
    table('comparison-table',['Category','Without WAF','Direct status','With WAF','Protected status'],r.comparison.map(x=>[x.category,x.without_waf,x.direct_status,x.with_waf,x.protected_status]));
    table('effectiveness-table',['Category','Tested','Detected','Blocked'],m.per_attack.map(x=>[x.code,x.tested,x.detected,x.blocked]));
    table('performance-table',['Path','Samples','Mean ms','P95 ms','Requests/s','CPU % (one core)','Sampled RSS MiB'],['direct','protected'].map(key=>{const x=p[key];return [key,x.samples,x.mean_latency_ms.toFixed(2),x.p95_latency_ms.toFixed(2),x.requests_per_second.toFixed(2),x.cpu_percent_one_core.toFixed(2),x.peak_sampled_rss_mib.toFixed(2)];}));
    $('performance-note').textContent='Observed overhead: '+p.overhead_ms.toFixed(2)+' ms. '+p.methodology+' '+p.caveat;
    $('evaluation-limitations').textContent=r.limitations.join('\n')+'\nTP '+m.true_positives+' / FP '+m.false_positives+' / TN '+m.true_negatives+' / FN '+m.false_negatives;
  }
  async function refresh(force=false){
    if(busy||(!force&&document.hidden))return;
    busy=true;
    try{
      const tasks=[api('/api/dashboard/summary').then(summary),api('/api/system/status').then(status)];
      if(page==='overview')tasks.push(api('/api/events/recent').then(events),api('/api/attacks/stats').then(analytics),api('/api/charts/attacks').then(WafCharts.timeline));
      if(page==='attacks'){const q=new URLSearchParams(location.search);if(!q.has('period'))q.set('period','24h');tasks.push(api('/api/attacks/stats?'+q).then(analytics),api('/api/charts/attacks?'+q).then(WafCharts.timeline));}
      if(page==='events'||page==='live')tasks.push(api('/api/events/recent?'+eventQuery()).then(events));
      if(page==='alerts')tasks.push(api('/api/alerts?page='+currentPage+($('active-alerts').checked?'&active=true':'')).then(alerts));
      if(page==='rules')tasks.push(api('/api/rules').then(rules));
      if(page==='evaluation')tasks.push(api('/api/evaluation').then(evaluation));
      if(page==='settings')tasks.push(api('/api/audit?page='+currentPage).then(d=>{table('audit-table',['UTC','Administrator','Action','Target','Old value','New value'],d.items.map(r=>[date(r.timestamp*1000),r.actor,r.action,r.target,r.old_value,r.new_value]));$('audit-page').textContent='Page '+d.page;$('audit-prev').disabled=currentPage===1;$('audit-next').disabled=d.items.length<25;}));
      if(page==='map')tasks.push(api('/api/attack-map').then(d=>{WafCharts.sources(d.sources);table('map-sources',['IP','Location','Attack','Severity','Attempts','Stopped','Rules','Last seen'],d.sources.map(r=>[r.source_ip,r.location,r.attack_category,badge(r.severity),r.attempts,r.blocked,r.matched_rules.join(', '),date(r.last_seen)]));}));
      if(page==='rates')tasks.push(api('/api/rate-limits').then(d=>table('rate-activity',['IP','Requests','Limit','Window','Remaining seconds','Status'],d.entries.map(r=>[r.source_ip,r.request_count,r.limit,r.window,r.remaining_seconds,r.request_count>=r.limit?'Rate limited':'Normal']))));
      if(page==='ip')tasks.push(api('/api/ip/blocked?kind='+ipKind+'&ip='+encodeURIComponent($('ip-search').value)).then(ipPolicies));
      await Promise.all(tasks);
      $('updated-at').textContent=new Date().toISOString().slice(11,19)+' UTC';
    }catch(error){notice(error.message);$('live-state').textContent='Refresh unavailable';$('live-dot').classList.add('offline');}
    finally{busy=false;}
  }
  const menuButton=$('mobile-menu');
  const sidebar=document.querySelector('.sidebar');
  function setNavigation(open){sidebar.classList.toggle('open',open);menuButton.setAttribute('aria-expanded',String(open));}
  menuButton.addEventListener('click',()=>setNavigation(!sidebar.classList.contains('open')));
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&sidebar.classList.contains('open')){setNavigation(false);menuButton.focus();}});
  document.addEventListener('click',event=>{if(sidebar.classList.contains('open')&&!sidebar.contains(event.target)&&!menuButton.contains(event.target))setNavigation(false);});
  for(const [id,delta]of [['prev-page',-1],['next-page',1]])if($(id))$(id).addEventListener('click',()=>{currentPage=Math.min(totalPages,Math.max(1,currentPage+delta));refresh(true);});
  if($('active-alerts'))$('active-alerts').addEventListener('change',()=>{currentPage=1;refresh(true);});
  if($('ip-search'))$('ip-search').addEventListener('input',()=>refresh(true));
  document.querySelectorAll('[data-ip-kind]').forEach(b=>b.addEventListener('click',()=>{ipKind=b.dataset.ipKind;refresh(true);}));
  document.querySelectorAll('.ack').forEach(b=>b.addEventListener('click',()=>ack(b.dataset.id,b)));
  if($('ip-form'))$('ip-form').addEventListener('submit',async e=>{e.preventDefault();const data=Object.fromEntries(new FormData(e.target));data.operation='add';
    if(data.kind==='whitelist'&&data.trust_mode==='FULL_BYPASS'){if(!confirm('Disable inspection and policy blocks for this trusted IP?'))return;data.confirm_full_bypass=true;}
    try{const result=await api('/api/ip','POST',data);notice(result.message);await refresh(true);}catch(error){notice(error.message);}});
  refresh();setInterval(refresh,3000);
  if(!canManage){for(const id of ['ip-form','rate-form','rule-form'])if($(id))$(id).querySelectorAll('button,input,textarea,select').forEach(el=>el.disabled=true);}
  for(const [id,delta] of [['audit-prev',-1],['audit-next',1]])if($(id))$(id).addEventListener('click',()=>{currentPage=Math.max(1,currentPage+delta);refresh(true);});
  if($('rule-form'))$('rule-form').addEventListener('submit',async e=>{e.preventDefault();const data=Object.fromEntries(new FormData(e.target));const id=data.id;delete data.id;data.score=Number(data.score);if('literal_patterns' in data)data.literal_patterns=data.literal_patterns.split('\n').map(s=>s.trim()).filter(Boolean);try{await api('/api/rules/'+encodeURIComponent(id)+'/configuration','PUT',data);notice('Rule configuration saved and audited.');await refresh(true);}catch(err){notice(err.message);}});
  if($('rate-form'))$('rate-form').addEventListener('submit',async e=>{e.preventDefault();const data=Object.fromEntries(new FormData(e.target));for(const k in data)data[k]=k.endsWith('_enabled')?data[k]==='true':Number(data[k]);try{await api('/api/rate-limits','PUT',data);notice('Protection thresholds saved.');}catch(err){notice(err.message);}});
})();
