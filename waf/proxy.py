"""Forwards the cached request unchanged after inspection, preserving cookies."""
import requests
from flask import Response, request

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}

def backend_available(base_url):
    try:
        with requests.Session() as client:
            client.trust_env = False
            return client.get(base_url, timeout=2, allow_redirects=False).status_code < 500
    except requests.RequestException:
        return False

def forward(base_url, path):
    target = base_url.rstrip("/") + request.path
    if request.query_string:
        target += "?" + request.query_string.decode("latin-1")
    connection_fields = {v.strip().lower() for v in request.headers.get("Connection", "").split(",")}
    excluded = HOP_BY_HOP | connection_fields | {"host", "content-length", "x-forwarded-for", "x-real-ip", "x-lab-auth-result"}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in excluded}
    # Cookies share a host across ports. Never send dashboard credentials to the lab target.
    if "Cookie" in headers:
        headers["Cookie"] = "; ".join(part.strip() for part in headers["Cookie"].split(";")
                                      if not part.strip().startswith("waf_admin_session="))
    headers["X-Forwarded-For"] = request.remote_addr or "unknown"
    try:
        with requests.Session() as client:
            client.trust_env = False
            upstream = client.request(request.method, target, data=request.get_data(cache=True),
                                      headers=headers, allow_redirects=False, timeout=15)
    except requests.RequestException:
        return Response("Backend service is unavailable.", status=502, content_type="text/plain")
    excluded_response = HOP_BY_HOP | {"content-encoding", "content-length"}
    excluded_response |= {v.strip().lower() for v in upstream.headers.get("Connection", "").split(",")}
    headers = []
    for key in upstream.raw.headers.keys():
        if key.lower() in excluded_response:
            continue
        for value in upstream.raw.headers.getlist(key):
            if key.lower() == "location" and value.startswith(base_url.rstrip("/") + "/"):
                value = value[len(base_url.rstrip("/")):]
            headers.append((key, value))
    return Response(upstream.content, status=upstream.status_code, headers=headers)
