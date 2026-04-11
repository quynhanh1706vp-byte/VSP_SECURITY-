var _poamData=[],_poamPage=0,_poamPageSize=15,_poamSort={col:'scheduled_completion',dir:1};

async function _loadPoam(){
  if(!window.TOKEN)return;
  var h={Authorization:'Bearer '+window.TOKEN};
  try{
    var d=await fetch('/api/p4/rmf',{headers:h}).then(function(r){return r.json();});
    _poamData=d.poam_items||[];
    var total=_poamData.length;
    var open_=_poamData.filter(function(x){return x.status==='open';}).length;
    var remed=_poamData.filter(function(x){return x.status==='in_remediation';}).length;
    var closed=_poamData.filter(function(x){return x.status==='closed';}).length;
    var ch=_poamData.filter(function(x){return x.severity==='CRITICAL'||x.severity==='HIGH';}).length;
    var s=function(id,v){var e=document.getElementById(id);if(e)e.textContent=v;};
    s('poam-k-total',total);s('poam-k-open',open_);s('poam-k-remediation',remed);
    s('poam-k-closed',closed);s('poam-k-crit',ch);
    s('poam-summary-lbl',total+' items \xb7 '+open_+' open \xb7 '+closed+' closed');
    _poamPage=0;_renderPoamTable();
    var now=new Date();var od=_poamData.filter(function(x){return x.status!=="closed"&&x.scheduled_completion&&new Date(x.scheduled_completion)<now;}).length;var ode=document.getElementById("poam-k-overdue");if(ode)ode.textContent=od;
    var now=new Date();var od=_poamData.filter(function(x){return x.status!=="closed"&&x.scheduled_completion&&new Date(x.scheduled_completion)<now;}).length;var ode=document.getElementById("poam-k-overdue");if(ode)ode.textContent=od;
  }catch(e){console.error('_loadPoam',e);}
}

function _renderPoamTable(){
  var q=((document.getElementById('poam-search')||{}).value||'').toLowerCase();
  var sf=(document.getElementById('poam-status-filter')||{}).value||'';
  var sv=(document.getElementById('poam-sev-filter')||{}).value||'';
  var rows=_poamData.filter(function(x){
    return(!q||(x.id||'').toLowerCase().includes(q)||(x.weakness_name||'').toLowerCase().includes(q)||(x.control_id||'').toLowerCase().includes(q))
      &&(!sf||x.status===sf)&&(!sv||x.severity===sv);
  });

  // Sort
  rows.sort(function(a,b){
    var va=a[_poamSort.col]||'', vb=b[_poamSort.col]||'';
    return va<vb?-_poamSort.dir:va>vb?_poamSort.dir:0;
  });
  var total=rows.length,start=_poamPage*_poamPageSize,end=Math.min(start+_poamPageSize,total);
  var tbody=document.getElementById('poam-tbody');
  if(!tbody)return;
  var sp2={CRITICAL:'pill-fail',HIGH:'pill-warn',MEDIUM:'pill-warn',LOW:'pill-queue'};
  var stp={open:'pill-fail',in_remediation:'pill-warn',closed:'pill-pass'};
  if(!rows.slice(start,end).length){
    tbody.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--t3);padding:20px">No items</td></tr>';
  }else{
    tbody.innerHTML=rows.slice(start,end).map(function(x){
      var due=(x.scheduled_completion||'').slice(0,10)||'—';
      var dc='';
      if(due!=='—'){var dd=new Date(due),now=new Date();if(dd<now)dc='color:var(--red)';else if(dd-now<30*864e5)dc='color:var(--amber)';}
      var mit=(x.mitigation_plan||'—');if(mit.length>40)mit=mit.slice(0,40)+'…';
      var tr=document.createElement('tr');
      tr.style.cursor='pointer';
      tr.dataset.id=x.id;
      tr.innerHTML='<td class="mono f10 c-blue">'+x.id+'</td>'
        +'<td class="f12" style="max-width:200px">'+(x.weakness_name||'—')+'</td>'
        +'<td class="mono f10 c-purple">'+(x.control_id||'—')+'</td>'
        +'<td><span class="pill '+(sp2[x.severity]||'pill-queue')+'" style="font-size:9px">'+x.severity+'</span></td>'
        +'<td><span class="pill '+(stp[x.status]||'pill-queue')+'" style="font-size:9px">'+x.status+'</span></td>'
        +'<td class="mono-sm c-t3">'+mit+'</td>'
        +'<td class="mono-sm" style="'+dc+'">'+due+'</td>';
      tr.onclick=function(){_showPoamDetail(this.dataset.id);};
      tr.onmouseenter=function(){this.style.background='var(--surface2)';};
      tr.onmouseleave=function(){this.style.background='';};
      return tr.outerHTML;
    }).join('');
  }
  var pag=document.getElementById('poam-pagination');
  if(pag){
    var pages=Math.ceil(total/_poamPageSize);
    if(pages<=1){pag.innerHTML='';}
    else{
      var cur=_poamPage;
      var html='<span style="font-size:10px;color:var(--t3);font-family:var(--font-mono)">'+(start+1)+'–'+end+' of '+total+'</span><div style="display:flex;gap:4px">';
      if(cur>0)html+='<button class="btn btn-ghost" style="padding:2px 8px;font-size:10px" onclick="_poamGoPage('+(cur-1)+')">&#8249;</button>';
      for(var pi=Math.max(0,cur-2);pi<=Math.min(pages-1,cur+2);pi++)
        html+='<button class="btn '+(pi===cur?'btn-primary':'btn-ghost')+'" style="padding:2px 8px;font-size:10px" onclick="_poamGoPage('+pi+')">'+(pi+1)+'</button>';
      if(cur<pages-1)html+='<button class="btn btn-ghost" style="padding:2px 8px;font-size:10px" onclick="_poamGoPage('+(cur+1)+')">&#8250;</button>';
      pag.innerHTML=html+'</div>';
    }
  }
  var cnt=document.getElementById('poam-count');if(cnt)cnt.textContent=total+' items';
}

function _poamGoPage(p){_poamPage=p;_renderPoamTable();}

function _showPoamDetail(id){
  var x=_poamData.find(function(i){return i.id===id;});
  if(!x)return;
  var sc={CRITICAL:'var(--red)',HIGH:'var(--amber)',MEDIUM:'var(--orange)',LOW:'var(--t3)'}[x.severity]||'var(--t3)';
  var stp={open:'pill-fail',in_remediation:'pill-warn',closed:'pill-pass'}[x.status]||'pill-queue';
  var due=(x.scheduled_completion||'').slice(0,10)||'—';
  var cl=(x.closed_date||'').slice(0,10)||'—';
  var modal=document.getElementById('poam-detail-modal');
  if(!modal){
    modal=document.createElement('div');
    modal.id='poam-detail-modal';
    modal.className='modal-overlay';
    modal.onclick=function(e){if(e.target===modal)modal.classList.remove('open');};
    var box=document.createElement('div');
    box.className='modal-box';
    box.style.maxWidth='580px';
    var head=document.createElement('div');
    head.className='modal-head';
    var titleEl=document.createElement('div');
    titleEl.id='pdm-title';
    titleEl.className='modal-title';
    var closeBtn=document.createElement('button');
    closeBtn.className='modal-close';
    closeBtn.textContent='✕';
    closeBtn.onclick=function(){modal.classList.remove('open');};
    head.appendChild(titleEl);
    head.appendChild(closeBtn);
    var body=document.createElement('div');
    body.id='pdm-body';
    body.className='modal-body';
    box.appendChild(head);
    box.appendChild(body);
    modal.appendChild(box);
    document.body.appendChild(modal);
  }
  document.getElementById('pdm-title').innerHTML='<span class="mono c-blue">'+x.id+'</span> — '+(x.weakness_name||'');
  document.getElementById('pdm-body').innerHTML=
    '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px">'
    +'<div style="background:var(--surface2);border-radius:8px;padding:10px;text-align:center"><div style="font-size:9px;color:var(--t3);margin-bottom:4px">SEVERITY</div><span style="font-size:16px;font-weight:700;color:'+sc+'">'+x.severity+'</span></div>'
    +'<div style="background:var(--surface2);border-radius:8px;padding:10px;text-align:center"><div style="font-size:9px;color:var(--t3);margin-bottom:4px">STATUS</div><span class="pill '+stp+'">'+x.status+'</span></div>'
    +'<div style="background:var(--surface2);border-radius:8px;padding:10px;text-align:center"><div style="font-size:9px;color:var(--t3);margin-bottom:4px">CONTROL</div><span class="mono f12 c-purple">'+(x.control_id||'—')+'</span></div>'
    +'</div>'
    +'<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px">'
    +'<div style="background:var(--surface2);border-radius:8px;padding:10px"><div style="font-size:9px;color:var(--t3);margin-bottom:4px">DUE DATE</div><div class="mono-sm">'+due+'</div></div>'
    +'<div style="background:var(--surface2);border-radius:8px;padding:10px"><div style="font-size:9px;color:var(--t3);margin-bottom:4px">CLOSED DATE</div><div class="mono-sm">'+cl+'</div></div>'
    +'</div>'
    +'<div style="background:var(--surface2);border-radius:8px;padding:12px;margin-bottom:10px"><div style="font-size:9px;color:var(--t3);margin-bottom:6px">MITIGATION PLAN</div><div class="f12 c-t2" style="line-height:1.7">'+(x.mitigation_plan||'—')+'</div></div>'
    +(x.finding_id?'<div style="background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.2);border-radius:8px;padding:10px;margin-bottom:10px"><div style="font-size:9px;color:var(--blue);margin-bottom:4px">FINDING ID</div><span class="mono-sm c-blue">'+x.finding_id+'</span></div>':'');
  modal.classList.add('open');
}

function _exportPoamCSV(){
  var rows=[['ID','Weakness','Control','Severity','Status','Mitigation','Due','Closed','Finding ID']];
  _poamData.forEach(function(x){
    rows.push([x.id,x.weakness_name||'',x.control_id||'',x.severity||'',x.status||'',
      x.mitigation_plan||'',(x.scheduled_completion||'').slice(0,10),(x.closed_date||'').slice(0,10),x.finding_id||'']);
  });
  var csv=rows.map(function(r){return r.map(function(v){return '"'+(v||'').toString().replace(/"/g,'""')+'"';}).join(',');}).join('\n');
  var a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);
  a.download='poam_'+new Date().toISOString().slice(0,10)+'.csv';
  a.click();
}

function _poamSetSort(col){
  if(_poamSort.col===col)_poamSort.dir*=-1;
  else{_poamSort.col=col;_poamSort.dir=1;}
  _poamPage=0;_renderPoamTable();
}

function _poamOverdueCount(){
  var now=new Date();
  return _poamData.filter(function(x){
    return x.status!=='closed'&&x.scheduled_completion&&new Date(x.scheduled_completion)<now;
  }).length;
}
