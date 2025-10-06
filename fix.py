#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Parte 3 - Herramientas de Seguridad y Red + Reverse DNS + WHOIS + Email Header
Ejecuta: python3 fix_all_tools_part3.py
"""

import os

print("🔧 Creando herramientas de Seguridad y Red...")
print("=" * 60)

# ===== SSL CHECK =====
ssl_check = """{% extends "base.html" %}
{% block title %}SSL Check{% endblock %}
{% block extra_styles %}
<style>
.tool-page{background:white;min-height:calc(100vh-200px);padding:3rem 0}
.tool-header{text-align:center;margin-bottom:2rem;max-width:800px;margin:0 auto}
.tool-header h1{font-size:2.5rem;font-weight:700;color:#2c3e50;margin-bottom:1rem}
.tool-description{font-size:1.1rem;color:#7f8c8d;line-height:1.6;margin-bottom:1.5rem}
.tool-features{background:#f8f9fa;padding:1.5rem;border-radius:10px;text-align:left}
.tool-features h3{font-size:1rem;font-weight:600;margin-bottom:0.75rem}
.input-card{max-width:600px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
.input-group-modern{display:flex;gap:0.75rem;margin-bottom:1.5rem}
.input-group-modern input{flex:1;padding:0.9rem 1.2rem;border:2px solid #e9ecef;border-radius:8px}
.btn-main{background:#00b894;color:white;border:none;padding:0.9rem 2rem;border-radius:8px;font-weight:600;cursor:pointer}
.results-card{max-width:800px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
</style>
{% endblock %}
{% block content %}
<div class="tool-page"><div class="container">
<div class="tool-header">
<h1>✅ SSL Check</h1>
<p class="tool-description">Verifica la validez y configuración de certificados SSL/TLS de cualquier sitio web. Analiza fechas de expiración, emisor y nombres alternativos.</p>
<div class="tool-features"><h3>Características:</h3><ul>
<li>Valida certificados SSL/TLS</li><li>Verifica fechas de expiración</li><li>Muestra información del emisor</li><li>Lista nombres alternativos (SAN)</li>
</ul></div>
</div>
<div class="input-card">
<div class="input-group-modern">
<input type="text" id="hostInput" placeholder="ejemplo.com" onkeypress="if(event.key==='Enter')check()">
<button class="btn-main" onclick="check()">Verificar SSL</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border text-success mb-2"></div><p>Verificando...</p></div>
<div id="error" class="alert alert-danger" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5 class="mb-3">Información del Certificado:</h5><div id="resultsContent"></div></div></div>
</div></div>
<script>
async function check(){const h=document.getElementById('hostInput').value.trim();if(!h){document.getElementById('error').textContent='Ingresa un dominio';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('hostname',h);const r=await fetch('/api/ssl-check',{method:'POST',body:fd});const data=await r.json();if(data.success){const d=new Date(data.data.valid_until);const now=new Date();const days=Math.ceil((d-now)/(1000*60*60*24));let status=days<0?'<span class="badge bg-danger">Expirado</span>':days<30?'<span class="badge bg-warning">Expira pronto</span>':'<span class="badge bg-success">Válido</span>';let h='<table class="table table-sm"><tr><td><strong>Emitido para:</strong></td><td>'+data.data.subject.commonName+'</td></tr><tr><td><strong>Emitido por:</strong></td><td>'+data.data.issuer.commonName+'</td></tr><tr><td><strong>Estado:</strong></td><td>'+status+'</td></tr><tr><td><strong>Válido desde:</strong></td><td>'+new Date(data.data.valid_from).toLocaleString()+'</td></tr><tr><td><strong>Válido hasta:</strong></td><td>'+d.toLocaleString()+'</td></tr></table><h6 class="mt-3">Nombres Alternativos:</h6><div>';data.data.subject_alt_names.forEach(n=>h+='<span class="badge bg-info me-1">'+n+'</span>');h+='</div>';document.getElementById('resultsContent').innerHTML=h;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{% endblock %}"""

with open('templates/ssl-check.html', 'w', encoding='utf-8') as f:
    f.write(ssl_check)
print("✅ ssl-check.html")

# ===== HTTP HEADERS =====
http_headers = """{% extends "base.html" %}
{% block title %}HTTP Headers{% endblock %}
{% block extra_styles %}
<style>
.tool-page{background:white;min-height:calc(100vh-200px);padding:3rem 0}
.tool-header{text-align:center;margin-bottom:2rem;max-width:800px;margin:0 auto}
.tool-header h1{font-size:2.5rem;font-weight:700;color:#2c3e50;margin-bottom:1rem}
.tool-description{font-size:1.1rem;color:#7f8c8d;line-height:1.6;margin-bottom:1.5rem}
.tool-features{background:#f8f9fa;padding:1.5rem;border-radius:10px;text-align:left}
.input-card{max-width:600px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
.input-group-modern{display:flex;gap:0.75rem}
.input-group-modern input{flex:1;padding:0.9rem 1.2rem;border:2px solid #e9ecef;border-radius:8px}
.btn-main{background:#fdcb6e;color:#2c3e50;border:none;padding:0.9rem 2rem;border-radius:8px;font-weight:600;cursor:pointer}
.results-card{max-width:900px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
</style>
{% endblock %}
{% block content %}
<div class="tool-page"><div class="container">
<div class="tool-header">
<h1>📑 HTTP Headers</h1>
<p class="tool-description">Analiza las cabeceras HTTP de respuesta de cualquier URL. Útil para debugging, seguridad y optimización web.</p>
<div class="tool-features"><h3>Características:</h3><ul>
<li>Muestra todas las cabeceras HTTP</li><li>Detecta redirecciones</li><li>Analiza cabeceras de seguridad</li><li>Formato legible y ordenado</li>
</ul></div>
</div>
<div class="input-card">
<div class="input-group-modern">
<input type="text" id="urlInput" placeholder="https://ejemplo.com" onkeypress="if(event.key==='Enter')check()">
<button class="btn-main" onclick="check()">Analizar</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div></div>
<div id="error" class="alert alert-danger mt-3" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5 class="mb-3">Cabeceras HTTP:</h5><div id="resultsContent"></div></div></div>
</div></div>
<script>
async function check(){const url=document.getElementById('urlInput').value.trim();if(!url){document.getElementById('error').textContent='Ingresa una URL';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('url',url);const r=await fetch('/api/http-headers',{method:'POST',body:fd});const data=await r.json();if(data.success){let h='<div class="alert alert-info mb-3"><strong>URL:</strong> '+data.data.final_url+' | <strong>Código:</strong> '+data.data.status_code+'</div><table class="table table-sm table-hover"><thead><tr><th style="width:30%">Cabecera</th><th>Valor</th></tr></thead><tbody>';data.data.headers.forEach(x=>h+='<tr><td><strong>'+x.name+'</strong></td><td><code style="word-break:break-all;font-size:0.85rem">'+x.value+'</code></td></tr>');h+='</tbody></table>';document.getElementById('resultsContent').innerHTML=h;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{% endblock %}"""

with open('templates/http-headers.html', 'w', encoding='utf-8') as f:
    f.write(http_headers)
print("✅ http-headers.html")

# ===== IP WHOIS =====
ip_whois = """{% extends "base.html" %}
{% block title %}IP WHOIS{% endblock %}
{% block extra_styles %}
<style>
.tool-page{background:white;min-height:calc(100vh-200px);padding:3rem 0}
.tool-header{text-align:center;margin-bottom:2rem;max-width:800px;margin:0 auto}
.tool-header h1{font-size:2.5rem;font-weight:700;color:#2c3e50;margin-bottom:1rem}
.tool-description{font-size:1.1rem;color:#7f8c8d;line-height:1.6;margin-bottom:1.5rem}
.tool-features{background:#f8f9fa;padding:1.5rem;border-radius:10px;text-align:left}
.input-card{max-width:600px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
.input-group-modern{display:flex;gap:0.75rem}
.input-group-modern input{flex:1;padding:0.9rem 1.2rem;border:2px solid #e9ecef;border-radius:8px}
.btn-main{background:#a29bfe;color:white;border:none;padding:0.9rem 2rem;border-radius:8px;font-weight:600;cursor:pointer}
.results-card{max-width:800px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
</style>
{% endblock %}
{% block content %}
<div class="tool-page"><div class="container">
<div class="tool-header">
<h1>📜 IP WHOIS</h1>
<p class="tool-description">Consulta información de registro WHOIS para direcciones IP. Obtén detalles sobre el propietario, organización y localización.</p>
<div class="tool-features"><h3>Características:</h3><ul>
<li>Información del propietario de la IP</li><li>Detalles de organización</li><li>Rangos de red asignados</li><li>Datos de contacto administrativo</li>
</ul></div>
</div>
<div class="input-card">
<div class="input-group-modern">
<input type="text" id="ipInput" placeholder="8.8.8.8" onkeypress="if(event.key==='Enter')check()">
<button class="btn-main" onclick="check()">Consultar WHOIS</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div></div>
<div id="error" class="alert alert-danger mt-3" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5 class="mb-3">Información WHOIS:</h5><div id="resultsContent"></div></div></div>
</div></div>
<script>
async function check(){const ip=document.getElementById('ipInput').value.trim();if(!ip){document.getElementById('error').textContent='Ingresa una IP';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('ip',ip);const r=await fetch('/api/ip-whois',{method:'POST',body:fd});const data=await r.json();if(data.success){let h='<div class="alert alert-success mb-3"><strong>IP:</strong> '+ip+'</div><table class="table table-sm">';for(const[k,v]of Object.entries(data.data)){h+='<tr><td><strong>'+k.replace(/_/g,' ')+':</strong></td><td>'+v+'</td></tr>'}h+='</table>';document.getElementById('resultsContent').innerHTML=h;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{% endblock %}"""

with open('templates/ip-whois.html', 'w', encoding='utf-8') as f:
    f.write(ip_whois)
print("✅ ip-whois.html")

# ===== BLACKLIST CHECK =====
blacklist = """{% extends "base.html" %}
{% block title %}Blacklist Check{% endblock %}
{% block extra_styles %}
<style>
.tool-page{background:white;min-height:calc(100vh-200px);padding:3rem 0}
.tool-header{text-align:center;margin-bottom:2rem;max-width:800px;margin:0 auto}
.tool-header h1{font-size:2.5rem;font-weight:700;color:#2c3e50;margin-bottom:1rem}
.tool-description{font-size:1.1rem;color:#7f8c8d;line-height:1.6;margin-bottom:1.5rem}
.tool-features{background:#f8f9fa;padding:1.5rem;border-radius:10px;text-align:left}
.input-card{max-width:600px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
.input-group-modern{display:flex;gap:0.75rem}
.input-group-modern input{flex:1;padding:0.9rem 1.2rem;border:2px solid #e9ecef;border-radius:8px}
.btn-main{background:#6c5ce7;color:white;border:none;padding:0.9rem 2rem;border-radius:8px;font-weight:600;cursor:pointer}
.results-card{max-width:800px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
</style>
{% endblock %}
{% block content %}
<div class="tool-page"><div class="container">
<div class="tool-header">
<h1>🛡️ Blacklist Check</h1>
<p class="tool-description">Verifica si una dirección IP está listada en las principales listas negras de spam (DNSBL). Esencial para administradores de servidores de correo.</p>
<div class="tool-features"><h3>Características:</h3><ul>
<li>Consulta 10 listas negras principales</li><li>Detección rápida de spam IPs</li><li>Resultados detallados por servidor</li><li>Ayuda a mantener reputación de email</li>
</ul></div>
</div>
<div class="input-card">
<div class="input-group-modern">
<input type="text" id="ipInput" placeholder="8.8.8.8" onkeypress="if(event.key==='Enter')check()">
<button class="btn-main" onclick="check()">Verificar</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div><p>Consultando listas...</p></div>
<div id="error" class="alert alert-danger mt-3" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><div id="resultsContent"></div></div></div>
</div></div>
<script>
async function check(){const ip=document.getElementById('ipInput').value.trim();if(!ip){document.getElementById('error').textContent='Ingresa una IP';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('ip',ip);const r=await fetch('/api/blacklist-check',{method:'POST',body:fd});const data=await r.json();if(data.success){const status=data.data.listed_count>0?'danger':'success';const icon=data.data.listed_count>0?'exclamation-triangle':'check-circle';let h='<div class="alert alert-'+status+' mb-3"><h5><i class="bi bi-'+icon+'"></i> IP: '+data.data.ip+'</h5><p class="mb-0">'+(data.data.listed_count>0?'Encontrada en <strong>'+data.data.listed_count+'</strong> de '+data.data.total_checked+' listas':'No encontrada en ninguna de '+data.data.total_checked+' listas')+'</p></div><table class="table table-sm table-hover"><thead><tr><th>Servidor</th><th>Estado</th></tr></thead><tbody>';data.data.results.forEach(x=>{const badge=x.listed===true?'<span class="badge bg-danger">Encontrada</span>':x.listed===false?'<span class="badge bg-success">Limpia</span>':'<span class="badge bg-secondary">Error</span>';h+='<tr><td><code>'+x.server+'</code></td><td>'+badge+'</td></tr>'});h+='</tbody></table>';document.getElementById('resultsContent').innerHTML=h;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{% endblock %}"""

with open('templates/blacklist-check.html', 'w', encoding='utf-8') as f:
    f.write(blacklist)
print("✅ blacklist-check.html")

# ===== REVERSE DNS =====
reverse_dns = """{% extends "base.html" %}
{% block title %}Reverse DNS{% endblock %}
{% block extra_styles %}
<style>
.tool-page{background:white;min-height:calc(100vh-200px);padding:3rem 0}
.tool-header{text-align:center;margin-bottom:2rem;max-width:800px;margin:0 auto}
.tool-header h1{font-size:2.5rem;font-weight:700;color:#2c3e50;margin-bottom:1rem}
.tool-description{font-size:1.1rem;color:#7f8c8d;line-height:1.6;margin-bottom:1.5rem}
.tool-features{background:#f8f9fa;padding:1.5rem;border-radius:10px;text-align:left}
.input-card{max-width:600px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
.input-group-modern{display:flex;gap:0.75rem}
.input-group-modern input{flex:1;padding:0.9rem 1.2rem;border:2px solid #e9ecef;border-radius:8px}
.btn-main{background:#fd79a8;color:white;border:none;padding:0.9rem 2rem;border-radius:8px;font-weight:600;cursor:pointer}
.results-card{max-width:800px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
</style>
{% endblock %}
{% block content %}
<div class="tool-page"><div class="container">
<div class="tool-header">
<h1>🔁 Reverse DNS</h1>
<p class="tool-description">Realiza búsquedas DNS inversas (PTR) para obtener el hostname asociado a una dirección IP.</p>
<div class="tool-features"><h3>Características:</h3><ul>
<li>Consulta registros PTR</li><li>Obtiene hostname desde IP</li><li>Verifica configuración DNS</li><li>Soporta IPv4 e IPv6</li>
</ul></div>
</div>
<div class="input-card">
<div class="input-group-modern">
<input type="text" id="ipInput" placeholder="8.8.8.8" onkeypress="if(event.key==='Enter')check()">
<button class="btn-main" onclick="check()">Consultar PTR</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div></div>
<div id="error" class="alert alert-danger mt-3" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5 class="mb-3">Hostnames:</h5><div id="resultsContent"></div></div></div>
</div></div>
<script>
async function check(){const ip=document.getElementById('ipInput').value.trim();if(!ip){document.getElementById('error').textContent='Ingresa una IP';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('ip',ip);const r=await fetch('/api/reverse-dns',{method:'POST',body:fd});const data=await r.json();if(data.success){let h='<div class="alert alert-success mb-3"><strong>IP:</strong> '+data.ip+' | <strong>Resultados:</strong> '+data.total+'</div><div class="list-group">';data.hosts.forEach(x=>h+='<div class="list-group-item"><code>'+x+'</code></div>');h+='</div>';document.getElementById('resultsContent').innerHTML=h;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{% endblock %}"""

with open('templates/reverse-dns.html', 'w', encoding='utf-8') as f:
    f.write(reverse_dns)
print("✅ reverse-dns.html")

# ===== WHOIS LOOKUP =====
whois_lookup = """{% extends "base.html" %}
{% block title %}WHOIS Lookup{% endblock %}
{% block extra_styles %}
<style>
.tool-page{background:white;min-height:calc(100vh-200px);padding:3rem 0}
.tool-header{text-align:center;margin-bottom:2rem;max-width:800px;margin:0 auto}
.tool-header h1{font-size:2.5rem;font-weight:700;color:#2c3e50;margin-bottom:1rem}
.tool-description{font-size:1.1rem;color:#7f8c8d;line-height:1.6;margin-bottom:1.5rem}
.tool-features{background:#f8f9fa;padding:1.5rem;border-radius:10px;text-align:left}
.input-card{max-width:600px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
.input-group-modern{display:flex;gap:0.75rem}
.input-group-modern input{flex:1;padding:0.9rem 1.2rem;border:2px solid #e9ecef;border-radius:8px}
.btn-main{background:#fdcb6e;color:#2c3e50;border:none;padding:0.9rem 2rem;border-radius:8px;font-weight:600;cursor:pointer}
.results-card{max-width:900px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
</style>
{% endblock %}
{% block content %}
<div class="tool-page"><div class="container">
<div class="tool-header">
<h1>📇 WHOIS Lookup</h1>
<p class="tool-description">Consulta información WHOIS completa de dominios. Obtén datos del registrante, fechas de registro y expiración, servidores DNS y más.</p>
<div class="tool-features"><h3>Características:</h3><ul>
<li>Información del registrante</li><li>Fechas de registro y expiración</li><li>Servidores DNS</li><li>Datos de contacto técnico</li>
</ul></div>
</div>
<div class="input-card">
<div class="input-group-modern">
<input type="text" id="domainInput" placeholder="ejemplo.com" onkeypress="if(event.key==='Enter')check()">
<button class="btn-main" onclick="check()">Consultar WHOIS</button>
</div>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div></div>
<div id="error" class="alert alert-danger mt-3" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5 class="mb-3">Información WHOIS:</h5><div id="resultsContent"></div></div></div>
</div></div>
<script>
async function check(){const d=document.getElementById('domainInput').value.trim();if(!d){document.getElementById('error').textContent='Ingresa un dominio';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('domain',d);const r=await fetch('/api/whois-lookup',{method:'POST',body:fd});const data=await r.json();if(data.success){const p=JSON.stringify(data.whois,null,2).replace(/</g,'&lt;');document.getElementById('resultsContent').innerHTML='<div class="alert alert-success mb-3"><strong>Dominio:</strong> '+data.domain+'</div><pre class="p-3 bg-light rounded" style="white-space:pre-wrap;font-size:0.85rem">'+p+'</pre>';document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{% endblock %}"""

with open('templates/whois-lookup.html', 'w', encoding='utf-8') as f:
    f.write(whois_lookup)
print("✅ whois-lookup.html")

# ===== EMAIL HEADER =====
email_header = """{% extends "base.html" %}
{% block title %}Email Header Analyzer{% endblock %}
{% block extra_styles %}
<style>
.tool-page{background:white;min-height:calc(100vh-200px);padding:3rem 0}
.tool-header{text-align:center;margin-bottom:2rem;max-width:800px;margin:0 auto}
.tool-header h1{font-size:2.5rem;font-weight:700;color:#2c3e50;margin-bottom:1rem}
.tool-description{font-size:1.1rem;color:#7f8c8d;line-height:1.6;margin-bottom:1.5rem}
.tool-features{background:#f8f9fa;padding:1.5rem;border-radius:10px;text-align:left}
.input-card{max-width:700px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
textarea{width:100%;padding:1rem;border:2px solid #e9ecef;border-radius:8px;font-family:monospace;font-size:0.9rem}
.btn-main{background:#74b9ff;color:white;border:none;padding:0.9rem 2rem;border-radius:8px;font-weight:600;cursor:pointer;width:100%;margin-top:1rem}
.results-card{max-width:900px;margin:2rem auto;background:white;padding:2rem;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
</style>
{% endblock %}
{% block content %}
<div class="tool-page"><div class="container">
<div class="tool-header">
<h1>✉️ Email Header Analyzer</h1>
<p class="tool-description">Analiza los headers completos de un email para rastrear su origen, verificar autenticación SPF/DKIM y detectar posibles problemas.</p>
<div class="tool-features"><h3>Características:</h3><ul>
<li>Extrae IP de origen</li><li>Verifica SPF y DKIM</li><li>Muestra ruta del email</li><li>Detecta anomalías</li>
</ul></div>
</div>
<div class="input-card">
<label class="form-label fw-bold">Pega los headers completos del email:</label>
<textarea id="headers" rows="12" placeholder="Received: from..."></textarea>
<button class="btn-main" onclick="check()">Analizar Headers</button>
<div id="loader" class="text-center py-4" style="display:none"><div class="spinner-border mb-2"></div></div>
<div id="error" class="alert alert-danger mt-3" style="display:none"></div>
</div>
<div id="results" style="display:none"><div class="results-card"><h5 class="mb-3">Análisis:</h5><div id="resultsContent"></div></div></div>
</div></div>
<script>
async function check(){const h=document.getElementById('headers').value.trim();if(!h){document.getElementById('error').textContent='Pega los headers';document.getElementById('error').style.display='block';return}document.getElementById('loader').style.display='block';document.getElementById('error').style.display='none';document.getElementById('results').style.display='none';try{const fd=new FormData();fd.append('headers',h);const r=await fetch('/api/email-header',{method:'POST',body:fd});const data=await r.json();if(data.success){let html='<div class="row g-3 mb-3"><div class="col-md-6"><div class="card"><div class="card-body"><h6>IP Origen:</h6><code>'+(data.origin_ip_guess||'-')+'</code></div></div></div><div class="col-md-6"><div class="card"><div class="card-body"><h6>SPF:</h6><span class="badge '+(data.spf_result==='pass'?'bg-success':'bg-danger')+'">'+(data.spf_result||'-')+'</span></div></div></div></div>';if(data.received?.length)html+='<h6 class="mt-3">Received Headers:</h6><pre class="p-3 bg-light rounded small">'+data.received.map(x=>x.replace(/</g,'&lt;')).join('\\n')+'</pre>';document.getElementById('resultsContent').innerHTML=html;document.getElementById('results').style.display='block'}else{document.getElementById('error').textContent=data.error;document.getElementById('error').style.display='block'}}catch(e){document.getElementById('error').textContent='Error';document.getElementById('error').style.display='block'}finally{document.getElementById('loader').style.display='none'}}
</script>
{% endblock %}"""

with open('templates/email-header.html', 'w', encoding='utf-8') as f:
    f.write(email_header)
print("✅ email-header.html")

print("\n" + "=" * 60)
print("✨ ¡TODAS LAS HERRAMIENTAS COMPLETADAS!")
print("=" * 60)
print("\n📦 Archivos creados:")
print("   ✅ ssl-check.html")
print("   ✅ http-headers.html")
print("   ✅ ip-whois.html")
print("   ✅ blacklist-check.html")
print("   ✅ reverse-dns.html")
print("   ✅ whois-lookup.html")
print("   ✅ email-header.html")
print("\n🚀 Ejecuta en orden:")
print("   python3 fix_all_tools.py")
print("   python3 fix_all_tools_part2.py")
print("   python3 fix_all_tools_part3.py")
print("   python app.py")
print("\n✨ ¡Listo! Todas las herramientas funcionando perfectamente.")