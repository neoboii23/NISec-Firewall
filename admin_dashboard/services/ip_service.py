import ipaddress

class IPService:
    def __init__(self,store):
        self.store=store

    def list(self,search="",kind=""):
        return [p for p in self.store.policies() if search in p["ip"] and (not kind or p["kind"]==kind)]

    def change(self,data,actor):
        for field in ("ip", "kind", "operation", "reason", "trust_mode"):
            if field in data and not isinstance(data[field], str):
                raise ValueError(f"{field} must be text")
        if "duration" in data and (isinstance(data["duration"], bool) or not isinstance(data["duration"], (int, str))):
            raise ValueError("duration must be an integer number of seconds")
        ip=str(ipaddress.ip_address(data.get("ip","")))
        kind=data.get("kind","")
        if data.get("operation")=="remove":
            self.store.remove_ip(ip,kind,actor)
        elif data.get("operation")=="add":
            mode=data.get("trust_mode","NORMAL")
            if mode=="FULL_BYPASS" and data.get("confirm_full_bypass") is not True:
                raise ValueError("FULL_BYPASS requires explicit confirmation")
            self.store.set_ip(ip,kind,data.get("reason","Administrator policy").strip(),actor,
                              data.get("duration",600 if kind=="temporary" else None),trust_mode=mode)
        else:
            raise ValueError("Unknown IP action")
