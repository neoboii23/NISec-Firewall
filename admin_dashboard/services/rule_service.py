import json
from waf.management.store import DETECTORS

class RuleService:
    def __init__(self, store, rules_dir, settings_path):
        self.store,self.rules_dir,self.settings_path=store,rules_dir,settings_path

    def inventory(self):
        overrides,detectors=self.store.states()
        configurations=self.store.rule_configurations()
        rules=[]
        for file in sorted(self.rules_dir.glob("*.json")):
            for rule in json.loads(file.read_text(encoding="utf-8"))["rules"]:
                rules.append({key:rule.get(key) for key in ("id","name","category","severity","score","action")} |
                             {"enabled":overrides.get(rule["id"],rule.get("enabled",True)),
                              "literal_patterns":[],"pattern_editable":bool(rule.get('patterns'))} | configurations.get(rule['id'],{}))
        settings=json.loads(self.settings_path.read_text())
        return {"rules":rules,"detectors":[{"id":key,"enabled":detectors.get(key,settings[key]["enabled"])} for key in DETECTORS]}

    def update(self, kind, identifier, enabled, actor):
        inventory=self.inventory()
        valid={r["id"] for r in inventory["rules" if kind=="rule" else "detectors"]}
        if identifier not in valid:
            raise ValueError("Unknown rule or detector")
        previous=next(r['enabled'] for r in inventory['rules' if kind=='rule' else 'detectors'] if r['id']==identifier)
        self.store.set_enabled(kind,identifier,enabled,actor,previous)

    def configure(self,identifier,changes,actor):
        rule=next((r for r in self.inventory()['rules'] if r['id']==identifier),None)
        if not rule:raise ValueError('Unknown rule')
        if not changes or set(changes)-{'score','action','severity','literal_patterns'}:raise ValueError('Unsupported rule fields')
        if 'score' in changes and (type(changes['score']) is not int or not 0<=changes['score']<=100):raise ValueError('Score must be 0–100')
        if 'action' in changes and changes['action'] not in ('BLOCK','LOG','ALERT','TEMPORARY_BLOCK','RATE_LIMIT'):raise ValueError('Unsupported rule action')
        if 'severity' in changes and changes['severity'] not in ('INFO','LOW','MEDIUM','HIGH','CRITICAL'):raise ValueError('Unsupported severity')
        if 'literal_patterns' in changes:
            values=changes['literal_patterns']
            if not rule['pattern_editable'] or not isinstance(values,list) or len(values)>5 or any(not isinstance(v,str) or not 3<=len(v)<=120 for v in values):
                raise ValueError('Only up to five 3–120 character literal signatures are supported on signature rules')
        previous={k:rule[k] for k in ('score','action','severity','literal_patterns')}
        self.store.configure_rule(identifier,previous | changes,actor,previous)
