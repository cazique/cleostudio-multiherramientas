#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script final que genera TODAS las herramientas con diseño homogéneo
NO usa .format() para evitar problemas con llaves
"""

import os

print("🎨 Generando TODAS las herramientas con diseño homogéneo...")
print("=" * 70)


# Función helper para generar cada herramienta
def create_tool(filename, title, icon, color, description, features, content, script):
    """Crea un archivo HTML de herramienta sin usar .format()"""

    html = f'''{{%extends "base.html" %}}
{{%block title %}}{title}{{%endblock %}}
{{%block extra_styles %}}
<style>
.tool-page {{background:white;min-height:calc(100vh - 200px);padding:3rem 0}}
.tool-header {{text-align:center;margin-bottom:2rem;max-width:800px;margin:0 auto;padding:0 1rem}}
.tool-header h1 {{font-size:2.5rem;font-weight:700;color:#2c3e50;margin-bottom:1rem}}
.tool-icon {{font-size:3rem;margin-bottom:1rem}}
.tool-description {{font-size:1.1rem;color:#7f8c8d;line-height:1.6;margin-bottom:1.5rem}}
.tool-features {{background:#f8f9fa;padding:1.5rem;border-radius:10px;text-align:left;max-width:600px;margin:0 auto}}
.tool-features h3 {{font-size:1rem;font-weight:600;color:#2c3e50;margin-bottom:0.75rem}}
.input-card {{max-width:700px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}}
.input-group-modern {{display:flex;gap:0.75rem;margin-bottom:1.5rem;flex-wrap:wrap}}
.input-group-modern input,.input-group-modern select,.input-group-modern textarea {{flex:1;min-width:200px;padding:0.9rem 1.2rem;border:2px solid #e9ecef;border-radius:8px;font-size:1rem}}
.input-group-modern input:focus,.input-group-modern select:focus,.input-group-modern textarea:focus {{outline:none;border-color:{color};box-shadow:0 0 0 3px {color}20}}
.btn-main {{background:{color};color:white;border:none;padding:0.9rem 2rem;border-radius:8px;font-weight:600;font-size:1rem;cursor:pointer;transition:all 0.3s;white-space:nowrap}}
.btn-main:hover {{transform:translateY(-2px);box-shadow:0 6px 16px {color}50}}
.btn-main:disabled {{background:#ccc;cursor:not-allowed;transform:none}}
.results-card {{max-width:900px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}}
.alert {{padding:1rem 1.5rem;border-radius:8px;margin-bottom:1rem}}
.alert-danger {{background:#fee;color:#c00;border:1px solid #fcc}}
.alert-success {{background:#efe;color:#060;border:1px solid #cfc}}
.spinner-border {{width:2rem;height:2rem;border:3px solid {color}30;border-top-color:{color};border-radius:50%;animation:spin 0.8s linear infinite}}
@keyframes spin {{to {{transform:rotate(360deg)}}}}
</style>
{{%endblock %}}
{{%block content %}}
<div class="tool-page"><div class="container">
<div class="tool-header">
<div class="tool-icon">{icon}</div>
<h1>{title}</h1>
<p class="tool-description">{description}</p>
<div class="tool-features">
<h3>✨ Características:</h3>
<ul>{features}</ul>
</div>
</div>
{content}
</div></div>
{{%endblock %}}
{script}
'''

    with open(f'templates/{filename}', 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"✅ templates/{filename}")


# ===== SPF CHECK =====
create_tool(
    'spf-check.html',
    'SPF Check',
    '🛡️',
    '#55efc4',
    'Verifica los registros SPF (Sender Policy Framework) de un dominio para validar la autenticación de correo electrónico.',
    '<li>Consulta registros TXT para SPF</li><li>Identifica servidores autorizados</li><li>Previene spoofing de email</li><li>Resultados instantáneos</li>',
    '''<div class="input-card">
<div class="input-group-modern">
<input type="text" id="domainInput" placeholder="ejemplo.com" onkeypress="if(event.key==='Enter')check()">
<button class="btn-main" onclick="check()">Verificar SPF</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div><p>Consultando...</p></div>
<div id="error" class="alert alert-danger" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5>📋 Registros SPF</h5><div id="resultsContent"></div></div></div>''',
    '''{%block scripts %}
<script>
async function check(){const d=document.getElementById('domainInput').value.trim();if(!d){document.getElementById('error').textContent='Por favor ingresa un dominio';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('domain',d);const r=await fetch('/api/spf-check',{method:'POST',body:fd});const data=await r.json();if(data.success){let h='<div class="alert alert-success"><strong>✓ Dominio:</strong> '+data.domain+' | <strong>Total:</strong> '+data.total+'</div><div class="list-group">';data.records.forEach(x=>h+='<div class="list-group-item"><code>'+x+'</code></div>');h+='</div>';document.getElementById('resultsContent').innerHTML=h;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error de conexión';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{%endblock %}'''
)

# ===== DKIM CHECK =====
create_tool(
    'dkim-check.html',
    'DKIM Check',
    '🔑',
    '#81ecec',
    'Verifica los registros DKIM (DomainKeys Identified Mail) para autenticar emails y prevenir falsificaciones.',
    '<li>Valida firmas DKIM</li><li>Selector personalizado</li><li>Previene phishing</li><li>Verificación instantánea</li>',
    '''<div class="input-card">
<div class="input-group-modern">
<input type="text" id="domainInput" placeholder="ejemplo.com" style="flex:2">
<input type="text" id="selectorInput" placeholder="Selector (default)" value="default" style="flex:1">
<button class="btn-main" onclick="check()">Verificar</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div></div>
<div id="error" class="alert alert-danger" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5>📋 Registros DKIM</h5><div id="resultsContent"></div></div></div>''',
    '''{%block scripts %}
<script>
async function check(){const d=document.getElementById('domainInput').value.trim(),s=document.getElementById('selectorInput').value.trim()||'default';if(!d){document.getElementById('error').textContent='Ingresa un dominio';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('domain',d);fd.append('selector',s);const r=await fetch('/api/dkim-check',{method:'POST',body:fd});const data=await r.json();if(data.success){let h='<div class="alert alert-success"><strong>✓ Selector:</strong> '+data.selector+' | <strong>Total:</strong> '+data.total+'</div><div class="list-group">';data.records.forEach(x=>h+='<div class="list-group-item"><code style="word-break:break-all">'+x+'</code></div>');h+='</div>';document.getElementById('resultsContent').innerHTML=h;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{%endblock %}'''
)

# ===== DMARC CHECK =====
create_tool(
    'dmarc-check.html',
    'DMARC Check',
    '📣',
    '#a29bfe',
    'Consulta la política DMARC de un dominio para verificar cómo se manejan los emails no autenticados.',
    '<li>Verifica política DMARC</li><li>Consulta registros _dmarc</li><li>Mejora seguridad</li><li>Fácil de usar</li>',
    '''<div class="input-card">
<div class="input-group-modern">
<input type="text" id="domainInput" placeholder="ejemplo.com" onkeypress="if(event.key==='Enter')check()">
<button class="btn-main" onclick="check()">Verificar DMARC</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div></div>
<div id="error" class="alert alert-danger" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5>📋 Política DMARC</h5><div id="resultsContent"></div></div></div>''',
    '''{%block scripts %}
<script>
async function check(){const d=document.getElementById('domainInput').value.trim();if(!d){document.getElementById('error').textContent='Ingresa dominio';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('domain',d);const r=await fetch('/api/dmarc-check',{method:'POST',body:fd});const data=await r.json();if(data.success){let h='<div class="alert alert-success"><strong>✓ Dominio:</strong> '+data.domain+'</div><div class="list-group">';data.records.forEach(x=>h+='<div class="list-group-item"><code>'+x+'</code></div>');h+='</div>';document.getElementById('resultsContent').innerHTML=h;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{%endblock %}'''
)

# ===== MX LOOKUP =====
create_tool(
    'mx-lookup.html',
    'MX Lookup',
    '📮',
    '#74b9ff',
    'Consulta los registros MX (Mail eXchange) de un dominio para identificar sus servidores de correo.',
    '<li>Lista servidores de correo</li><li>Muestra prioridades MX</li><li>Valida configuración</li><li>Resultados ordenados</li>',
    '''<div class="input-card">
<div class="input-group-modern">
<input type="text" id="domainInput" placeholder="ejemplo.com" onkeypress="if(event.key==='Enter')check()">
<button class="btn-main" onclick="check()">Consultar MX</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div></div>
<div id="error" class="alert alert-danger" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5>📮 Servidores de Correo</h5><div id="resultsContent"></div></div></div>''',
    '''{%block scripts %}
<script>
async function check(){const d=document.getElementById('domainInput').value.trim();if(!d){document.getElementById('error').textContent='Ingresa dominio';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('domain',d);const r=await fetch('/api/mx-lookup',{method:'POST',body:fd});const data=await r.json();if(data.success){let h='<div class="alert alert-success"><strong>✓ Dominio:</strong> '+data.domain+' | <strong>Servidores:</strong> '+data.total+'</div><table class="table table-hover"><thead><tr><th>Prioridad</th><th>Servidor</th></tr></thead><tbody>';data.mx_records.forEach(x=>h+='<tr><td><span class="badge bg-primary">'+x.priority+'</span></td><td><code>'+x.server+'</code></td></tr>');h+='</tbody></table>';document.getElementById('resultsContent').innerHTML=h;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{%endblock %}'''
)

# ===== DNS LOOKUP =====
create_tool(
    'dns-lookup.html',
    'DNS Lookup',
    '🔍',
    '#fab1a0',
    'Consulta registros DNS de cualquier tipo (A, AAAA, CNAME, TXT, NS, MX) para un dominio específico.',
    '<li>Soporta 6 tipos de registros</li><li>Consultas rápidas</li><li>Resultados detallados</li><li>Interfaz intuitiva</li>',
    '''<div class="input-card">
<div class="mb-3"><div class="btn-group" role="group" style="display:flex;gap:0.5rem;flex-wrap:wrap">
<button class="btn btn-primary active" data-type="A" onclick="selectType('A',this)" style="flex:1;min-width:60px">A</button>
<button class="btn btn-outline-secondary" data-type="AAAA" onclick="selectType('AAAA',this)" style="flex:1;min-width:60px">AAAA</button>
<button class="btn btn-outline-secondary" data-type="CNAME" onclick="selectType('CNAME',this)" style="flex:1;min-width:80px">CNAME</button>
<button class="btn btn-outline-secondary" data-type="TXT" onclick="selectType('TXT',this)" style="flex:1;min-width:60px">TXT</button>
<button class="btn btn-outline-secondary" data-type="NS" onclick="selectType('NS',this)" style="flex:1;min-width:60px">NS</button>
<button class="btn btn-outline-secondary" data-type="MX" onclick="selectType('MX',this)" style="flex:1;min-width:60px">MX</button>
</div></div>
<div class="input-group-modern">
<input type="text" id="domainInput" placeholder="ejemplo.com" onkeypress="if(event.key==='Enter')check()">
<button class="btn-main" onclick="check()">Consultar</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div></div>
<div id="error" class="alert alert-danger" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5>📋 Registros DNS</h5><div id="resultsContent"></div></div></div>''',
    '''{%block scripts %}
<script>
let type='A';
function selectType(t,btn){type=t;document.querySelectorAll('.btn-group button').forEach(b=>{b.className='btn btn-outline-secondary'});btn.className='btn btn-primary active'}
async function check(){const d=document.getElementById('domainInput').value.trim();if(!d){document.getElementById('error').textContent='Ingresa dominio';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('domain',d);fd.append('type',type);const r=await fetch('/api/dns-lookup',{method:'POST',body:fd});const data=await r.json();if(data.success){let h='<div class="alert alert-success"><strong>✓ Tipo:</strong> '+data.type+' | <strong>Total:</strong> '+data.total+'</div><div class="list-group">';data.records.forEach(x=>h+='<div class="list-group-item"><code>'+x.value+'</code></div>');h+='</div>';document.getElementById('resultsContent').innerHTML=h;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{%endblock %}'''
)

# ===== REVERSE DNS =====
create_tool(
    'reverse-dns.html',
    'Reverse DNS',
    '🔁',
    '#fd79a8',
    'Realiza búsquedas DNS inversas (PTR) para obtener el hostname asociado a una dirección IP.',
    '<li>Consulta registros PTR</li><li>De IP a hostname</li><li>Verifica configuración</li><li>Soporta IPv4 e IPv6</li>',
    '''<div class="input-card">
<div class="input-group-modern">
<input type="text" id="ipInput" placeholder="8.8.8.8" onkeypress="if(event.key==='Enter')check()">
<button class="btn-main" onclick="check()">Consultar PTR</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div></div>
<div id="error" class="alert alert-danger" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5>📋 Hostnames</h5><div id="resultsContent"></div></div></div>''',
    '''{%block scripts %}
<script>
async function check(){const ip=document.getElementById('ipInput').value.trim();if(!ip){document.getElementById('error').textContent='Ingresa una IP';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('ip',ip);const r=await fetch('/api/reverse-dns',{method:'POST',body:fd});const data=await r.json();if(data.success){let h='<div class="alert alert-success"><strong>✓ IP:</strong> '+data.ip+' | <strong>Total:</strong> '+data.total+'</div><div class="list-group">';data.hosts.forEach(x=>h+='<div class="list-group-item"><code>'+x+'</code></div>');h+='</div>';document.getElementById('resultsContent').innerHTML=h;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{%endblock %}'''
)

# ===== WHOIS LOOKUP =====
create_tool(
    'whois-lookup.html',
    'WHOIS Lookup',
    '📇',
    '#fdcb6e',
    'Consulta información WHOIS completa de dominios: registrante, fechas, servidores DNS y contactos.',
    '<li>Info del registrante</li><li>Fechas de registro</li><li>Servidores DNS</li><li>Contactos técnicos</li>',
    '''<div class="input-card">
<div class="input-group-modern">
<input type="text" id="domainInput" placeholder="ejemplo.com" onkeypress="if(event.key==='Enter')check()">
<button class="btn-main" onclick="check()">Consultar WHOIS</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div></div>
<div id="error" class="alert alert-danger" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5>📋 Información WHOIS</h5><div id="resultsContent"></div></div></div>''',
    '''{%block scripts %}
<script>
async function check(){const d=document.getElementById('domainInput').value.trim();if(!d){document.getElementById('error').textContent='Ingresa dominio';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('domain',d);const r=await fetch('/api/whois-lookup',{method:'POST',body:fd});const data=await r.json();if(data.success){const p=JSON.stringify(data.whois,null,2).replace(/</g,'&lt;');document.getElementById('resultsContent').innerHTML='<div class="alert alert-success"><strong>✓ Dominio:</strong> '+data.domain+'</div><pre class="p-3 bg-light rounded" style="white-space:pre-wrap;font-size:0.85rem">'+p+'</pre>';document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{%endblock %}'''
)

# ===== EMAIL HEADER =====
create_tool(
    'email-header.html',
    'Email Header Analyzer',
    '✉️',
    '#74b9ff',
    'Analiza los headers completos de emails para rastrear origen, verificar autenticación SPF/DKIM y detectar anomalías.',
    '<li>Extrae IP de origen</li><li>Verifica SPF y DKIM</li><li>Muestra ruta completa</li><li>Detecta anomalías</li>',
    '''<div class="input-card">
<label class="form-label fw-bold">Pega los headers completos del email:</label>
<textarea id="headers" rows="12" placeholder="Received: from..." style="width:100%;padding:1rem;border:2px solid #e9ecef;border-radius:8px;font-family:monospace;font-size:0.85rem"></textarea>
<button class="btn-main w-100 mt-3" onclick="check()">Analizar Headers</button>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div></div>
<div id="error" class="alert alert-danger mt-3" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5>📋 Análisis</h5><div id="resultsContent"></div></div></div>''',
    '''{%block scripts %}
<script>
async function check(){const h=document.getElementById('headers').value.trim();if(!h){document.getElementById('error').textContent='Pega los headers';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('headers',h);const r=await fetch('/api/email-header',{method:'POST',body:fd});const data=await r.json();if(data.success){let html='<div class="row g-3 mb-3"><div class="col-md-6"><div class="card"><div class="card-body"><h6>IP Origen:</h6><code>'+(data.origin_ip_guess||'-')+'</code></div></div></div><div class="col-md-6"><div class="card"><div class="card-body"><h6>SPF:</h6><span class="badge '+(data.spf_result==='pass'?'bg-success':'bg-danger')+'">'+(data.spf_result||'-')+'</span></div></div></div></div>';if(data.received?.length)html+='<h6 class="mt-3">Received Headers:</h6><pre class="p-3 bg-light rounded small">'+data.received.map(x=>x.replace(/</g,'&lt;')).join('\\n')+'</pre>';document.getElementById('resultsContent').innerHTML=html;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{%endblock %}'''
)

print("\n" + "=" * 70)
print("✨ ¡Herramientas DNS/Email completadas!")
print("\nAhora ejecuta: python app.py")