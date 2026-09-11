from sqlalchemy import create_engine,select
from sqlalchemy.orm import Session
from database.models import SecurityEventStore
from engine.decision import DetectionResult
from conftest import make_context
from management.orm_models import SecurityEvent,RequestLog,BlockedIP,RateLimitRecord

def test_orm_views_single_store_and_idempotent_migration(tmp_path):
    path=tmp_path/'security.db'
    store=SecurityEventStore(path)
    store.record(make_context(),DetectionResult(decision='RATE_LIMIT',metadata={'retry_after':15}),429)
    store.management.set_ip('::1','blacklist','lab','admin')
    SecurityEventStore(path)
    engine=create_engine('sqlite:///'+str(path))
    try:
        with Session(engine) as session:
            event=session.scalars(select(SecurityEvent)).one()
            assert session.scalars(select(RequestLog)).one().id==event.id
            assert session.scalars(select(RateLimitRecord)).one().retry_after==15
            assert session.scalars(select(BlockedIP)).one().ip=='::1'
    finally:engine.dispose()
