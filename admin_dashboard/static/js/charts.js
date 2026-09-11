/* Chart.js is served locally; mutate datasets and call update('none') when polling. */
window.WafCharts = (() => {
  const instances = {};
  const colors = ['#55dfbc','#74a8ff','#b79aff','#f4bd68','#ff788b','#70d2ef'];
  function render(id, type, labels, datasets, extra = {}) {
    const canvas = document.getElementById(id);
    if (!canvas || !window.Chart) return;
    if (!instances[id]) {
      Chart.defaults.color = '#8493a8';
      Chart.defaults.font.family = "'Segoe UI', system-ui, sans-serif";
      Chart.defaults.font.size = 10;
      const circular = type === 'doughnut';
      instances[id] = new Chart(canvas, {
        type, data: {labels, datasets},
        options: {responsive:true, maintainAspectRatio:false, animation:false,
          plugins:{legend:{display:circular || type==='line',position:'bottom',labels:{usePointStyle:true,boxWidth:6,padding:16}},tooltip:{enabled:true}},
          ...(circular ? {cutout:'72%'} : {scales:{x:{grid:{display:false},ticks:{maxTicksLimit:8}},y:{beginAtZero:true,grid:{color:'#1b2938'},ticks:{precision:0}}}}),
          ...extra}
      });
    } else {
      instances[id].data.labels = labels;
      instances[id].data.datasets = datasets;
      instances[id].update('none');
    }
  }
  return {
    sources(rows) {
      const located=rows.filter(r=>Number.isFinite(r.latitude)&&Number.isFinite(r.longitude));
      render('source-map','scatter',[],[{label:'Attack sources',data:located.map(r=>({x:r.longitude,y:r.latitude,source:r})),backgroundColor:'#ff788b',pointRadius:7}],
        {scales:{x:{min:-180,max:180,title:{display:true,text:'Longitude'},grid:{color:'#243347'}},y:{min:-90,max:90,title:{display:true,text:'Latitude'},grid:{color:'#243347'}}},
         onClick:(_event,elements,chart)=>{if(elements.length){const r=chart.data.datasets[0].data[elements[0].index].source;document.getElementById('map-detail').textContent=JSON.stringify(r,null,2);}}});
    },
    analytics(data) {
      render('category-chart','bar',data.categories.map(c=>c.code),
        [{label:'Attacks',data:data.categories.map(c=>c.count),backgroundColor:colors,borderRadius:3}],{indexAxis:'y'});
      const severity=['INFO','LOW','MEDIUM','HIGH','CRITICAL'];
      render('severity-chart','bar',severity,[{label:'Events',data:severity.map(k=>data.severity[k]||0),
        backgroundColor:['#60748d','#74a8ff','#f4bd68','#ff788b','#b79aff'],borderRadius:3}]);
      render('action-chart','doughnut',['Allowed','Blocked','Rate limited'],[{data:['ALLOW','BLOCK','RATE_LIMIT'].map(k=>data.actions[k]||0),
        backgroundColor:['#55dfbc','#ff788b','#f4bd68'],borderWidth:0}]);
      for (const [id,list,key] of [['ip-chart',data.top_ips,'source_ip'],['path-chart',data.top_paths,'path']])
        render(id,'bar',list.map(x=>x[key]),[{label:'Attacks',data:list.map(x=>x.attacks),backgroundColor:'#74a8ff',borderRadius:3}],{indexAxis:'y'});
    },
    timeline(data) {
      render('timeline-chart','line',data.map(x=>x.minute.slice(5).replace('T',' ')),[
        {label:'Allowed',data:data.map(x=>x.allowed),borderColor:'#55dfbc',backgroundColor:'#55dfbc12',fill:true,pointRadius:0,tension:.25,borderWidth:2},
        {label:'Attacks',data:data.map(x=>x.attacks),borderColor:'#ff788b',pointRadius:0,tension:.25,borderWidth:2},
        {label:'Stopped',data:data.map(x=>x.blocked),borderColor:'#74a8ff',pointRadius:0,tension:.25,borderWidth:1.5}
      ]);
    }
  };
})();
