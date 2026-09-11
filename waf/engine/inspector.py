"""Bounded request parsing. The original bytes are cached before multipart parsing."""
from dataclasses import dataclass, field
import json

@dataclass(frozen=True)
class FileInfo:
    filename: str
    content_type: str
    size: int
    content: bytes = b""
    field: str = "file"

@dataclass
class RequestContext:
    client_ip: str
    method: str
    url: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    cookies: dict[str, str]
    user_agent: str
    content_type: str
    body: bytes
    files: list[FileInfo]
    content_length: int
    form: dict[str, list[str]] = field(default_factory=dict)
    json_data: object = None

    def text_fields(self):
        yield "path", self.path
        for source, values in (("query", self.query), ("form", self.form)):
            for key, entries in values.items():
                for index, value in enumerate(entries):
                    yield f"{source}.{key}[{index}]", value
        for key, value in self.cookies.items():
            yield f"cookies.{key}", value
        for key, value in self.headers.items():
            if key.lower() not in {"cookie", "user-agent", "content-type", "content-length"}:
                yield f"headers.{key}", value
        yield "user_agent", self.user_agent
        for index, upload in enumerate(self.files):
            yield f"files.{index}.filename", upload.filename
        if self.json_data is not None:
            # Iterative and bounded; deep malformed JSON is rejected by inspector.
            pending = [("body.json", self.json_data)]
            count = 0
            while pending and count < 10000:
                name, value = pending.pop()
                count += 1
                if isinstance(value, dict):
                    pending.extend((f"{name}.{k}", v) for k, v in value.items())
                elif isinstance(value, list):
                    pending.extend((f"{name}[{i}]", v) for i, v in enumerate(value))
                else:
                    yield name, str(value)
            if pending:
                raise ValueError("Too many JSON fields")
        elif not self.content_type.startswith(("multipart/", "application/x-www-form-urlencoded")):
            yield "body.raw", self.body.decode("utf-8", errors="replace")

    def text_components(self):
        components = {}
        for field_name, value in self.text_fields():
            components.setdefault(field_name.split(".")[0], []).append(value)
        return components

def client_ip(request, trust_proxy_headers):
    if trust_proxy_headers:
        forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        return forwarded or request.headers.get("X-Real-IP") or request.remote_addr or "unknown"
    return request.remote_addr or "unknown"

def inspect_request(request, trust_proxy_headers=False, inspection_max_bytes=65536, metadata_only=False):
    context = RequestContext(
        client_ip(request, trust_proxy_headers), request.method, request.base_url,
        request.path, {k: request.args.getlist(k) for k in request.args},
        dict(request.headers), request.cookies.to_dict(), request.user_agent.string,
        request.content_type or "", b"", [], request.content_length or 0,
    )
    if metadata_only:
        return context
    context.body = request.get_data(cache=True)  # BEFORE request.form/files consume stream.
    context.content_length = len(context.body)
    context.form = {k: request.form.getlist(k) for k in request.form}
    if request.is_json:
        context.json_data = json.loads(context.body)
    for key, uploaded in request.files.items(multi=True):
        stream = uploaded.stream
        position = stream.tell()
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(0)
        prefix = stream.read(inspection_max_bytes)
        stream.seek(position)
        context.files.append(FileInfo(uploaded.filename or "", uploaded.mimetype or "", size, prefix, key))
    return context
