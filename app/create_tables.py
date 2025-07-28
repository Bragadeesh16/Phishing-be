from models import Base
from database import engine


# Create tables in the SQLite database
Base.metadata.create_all(bind=engine)

print("Tables created successfully in SQLite.")
