"""Seed demo users and ORIGINE bag catalog."""
from werkzeug.security import generate_password_hash
from app import app
from models import Item, User, db

ITEMS = [
    ("The City Tote", "A generous, softly structured carryall for the in-between moments.", "Everyday", 148, "https://images.unsplash.com/photo-1584917865442-de89df76afd3?auto=format&fit=crop&w=900&q=85"),
    ("Mila Mini", "A compact crossbody with an unmistakable after-dark character.", "Evening", 98, "https://images.unsplash.com/photo-1594223274512-ad4803739b7c?auto=format&fit=crop&w=900&q=85"),
    ("The Weekender", "Room for a spontaneous escape in a clean silhouette.", "Travel", 188, "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?auto=format&fit=crop&w=900&q=85"),
    ("Luna Shoulder Bag", "Curved lines and a close-to-body fit for life on the move.", "Everyday", 132, "https://images.unsplash.com/photo-1566150905458-1bf1fc113f0d?auto=format&fit=crop&w=900&q=85"),
    ("Studio Pouch", "An elegant home for essentials, made to tuck into every bag.", "Small Goods", 56, "https://images.unsplash.com/photo-1590874103328-eac38a683ce7?auto=format&fit=crop&w=900&q=85"),
    ("The Market Basket", "A hand-finished statement piece for sun-warmed days.", "Summer", 118, "https://images.unsplash.com/photo-1585488434455-1a5d51362fef?auto=format&fit=crop&w=900&q=85"),
]


def seed_database():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            db.session.add(User(username="admin", email="admin@origine.lab", password=generate_password_hash("admin123"), full_name="ORIGINE Administrator", bio="Laboratory administrator", is_admin=True))
        if not User.query.filter_by(username="student").first():
            db.session.add(User(username="student", email="student@origine.lab", password=generate_password_hash("student123"), full_name="Lab Student", bio="Cybersecurity student"))
        if not Item.query.first():
            db.session.add_all(Item(name=n, description=d, category=c, price=p, image_url=i) for n, d, c, p, i in ITEMS)
        db.session.commit()


if __name__ == "__main__":
    seed_database()
    print("Database seeded. Accounts: admin/admin123 and student/student123")
