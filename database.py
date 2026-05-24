import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = "sqlite:///phishing_detector.db"

Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class URLModel(Base):
    __tablename__ = "urls"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True, nullable=False)
    hostname = Column(String, nullable=False)
    tld = Column(String, nullable=True)
    domain_age_days = Column(Integer, nullable=False)
    scanned_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    features = relationship("FeatureModel", back_populates="url", uselist=False, cascade="all, delete-orphan")
    prediction = relationship("PredictionModel", back_populates="url", uselist=False, cascade="all, delete-orphan")
    risk_flags = relationship("RiskFlagModel", back_populates="url", cascade="all, delete-orphan")

class FeatureModel(Base):
    __tablename__ = "features"
    
    id = Column(Integer, primary_key=True, index=True)
    url_id = Column(Integer, ForeignKey("urls.id", ondelete="CASCADE"), nullable=False, unique=True)
    
    # The 33 numerical features
    url_len = Column(Float, nullable=False)
    host_len = Column(Float, nullable=False)
    path_len = Column(Float, nullable=False)
    query_len = Column(Float, nullable=False)
    num_subdomains = Column(Float, nullable=False)
    num_digits = Column(Float, nullable=False)
    digit_ratio = Column(Float, nullable=False)
    digit_ratio_host = Column(Float, nullable=False)
    num_special_chars = Column(Float, nullable=False)
    dash_count_host = Column(Float, nullable=False)
    dot_count_host = Column(Float, nullable=False)
    slash_count = Column(Float, nullable=False)
    has_ip = Column(Float, nullable=False)
    has_http_in_path = Column(Float, nullable=False)
    has_at_symbol = Column(Float, nullable=False)
    has_double_slash = Column(Float, nullable=False)
    entropy = Column(Float, nullable=False)
    has_brand_keyword = Column(Float, nullable=False)
    is_shortened = Column(Float, nullable=False)
    tld_length = Column(Float, nullable=False)
    tld_is_risky = Column(Float, nullable=False)
    subdomain_depth = Column(Float, nullable=False)
    has_login_keywords = Column(Float, nullable=False)
    vowel_consonant_ratio = Column(Float, nullable=False)
    longest_word_len = Column(Float, nullable=False)
    num_params = Column(Float, nullable=False)
    suspicious_tld = Column(Float, nullable=False)
    domain_age_days = Column(Float, nullable=False)
    www_in_hostname = Column(Float, nullable=False)
    subdomain_len = Column(Float, nullable=False)
    path_digit_ratio = Column(Float, nullable=False)
    query_digit_ratio = Column(Float, nullable=False)
    non_alphanumeric_ratio = Column(Float, nullable=False)
    
    url = relationship("URLModel", back_populates="features")

class PredictionModel(Base):
    __tablename__ = "predictions"
    
    id = Column(Integer, primary_key=True, index=True)
    url_id = Column(Integer, ForeignKey("urls.id", ondelete="CASCADE"), nullable=False, unique=True)
    prediction = Column(String, nullable=False) # 'Phishing' or 'Legitimate'
    phishing_probability = Column(Float, nullable=False) # Probability (0.0 to 1.0)
    risk_score = Column(Float, nullable=False) # Computed as probability * 100
    matched_brand = Column(String, nullable=True) # Spoofed brand keyword if any
    scanned_at = Column(DateTime, default=datetime.utcnow)
    
    url = relationship("URLModel", back_populates="prediction")

class RiskFlagModel(Base):
    __tablename__ = "risk_flags"
    
    id = Column(Integer, primary_key=True, index=True)
    url_id = Column(Integer, ForeignKey("urls.id", ondelete="CASCADE"), nullable=False)
    flag_name = Column(String, nullable=False)
    flag_severity = Column(String, nullable=False) # 'Low', 'Medium', 'High'
    description = Column(String, nullable=False)
    
    url = relationship("URLModel", back_populates="risk_flags")

# Database initialization
def init_db():
    Base.metadata.create_all(bind=engine)
    print("Database tables initialized successfully.")

# Get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Analytics API querying scan logs using raw SQL
def run_sql_query(query_str, params=None):
    """Executes a raw SQL query and returns results as list of dicts."""
    db = SessionLocal()
    try:
        result = db.execute(text(query_str), params or {})
        # Map columns to values
        cols = result.keys()
        rows = [dict(zip(cols, row)) for row in result.fetchall()]
        return rows
    except Exception as e:
        print(f"SQL execution error: {e}")
        return []
    finally:
        db.close()

# --- Pre-packaged Analytics Queries using raw SQL ---

def get_most_phished_brands():
    """Query to find most targeted brands based on phishing predictions."""
    sql = """
        SELECT matched_brand, COUNT(*) as count
        FROM predictions
        WHERE prediction = 'Phishing' AND matched_brand IS NOT NULL AND matched_brand != ''
        GROUP BY matched_brand
        ORDER BY count DESC
        LIMIT 10
    """
    return run_sql_query(sql)

def get_attack_frequency_by_hour():
    """Query to get attack volume grouped by hour of the day."""
    sql = """
        SELECT strftime('%H', scanned_at) as hour, COUNT(*) as count
        FROM predictions
        GROUP BY hour
        ORDER BY hour ASC
    """
    return run_sql_query(sql)

def get_attack_frequency_by_day():
    """Query to get attack volume grouped by day of the week (0=Sunday, 6=Saturday)."""
    # SQLite strftime %w returns 0-6
    sql = """
        SELECT strftime('%w', scanned_at) as day_of_week, COUNT(*) as count
        FROM predictions
        GROUP BY day_of_week
        ORDER BY day_of_week ASC
    """
    days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
    raw_results = run_sql_query(sql)
    # Map numerical day to string day
    result_map = {item['day_of_week']: item['count'] for item in raw_results}
    formatted = []
    for idx, day_name in enumerate(days):
        count = result_map.get(str(idx), 0)
        formatted.append({'day': day_name, 'count': count})
    return formatted

def get_top_risky_tlds():
    """Query to identify the top TLDs seen in phishing predictions."""
    sql = """
        SELECT u.tld, COUNT(*) as count
        FROM urls u
        JOIN predictions p ON u.id = p.url_id
        WHERE p.prediction = 'Phishing' AND u.tld IS NOT NULL AND u.tld != ''
        GROUP BY u.tld
        ORDER BY count DESC
        LIMIT 10
    """
    return run_sql_query(sql)

def get_top_risk_factors():
    """Query to find the most frequent risk flags triggered across scanned URLs."""
    sql = """
        SELECT flag_name, flag_severity, COUNT(*) as count
        FROM risk_flags
        GROUP BY flag_name, flag_severity
        ORDER BY count DESC
        LIMIT 10
    """
    return run_sql_query(sql)

def get_historical_metrics():
    """Query to get basic scanner aggregates (scans over time, phishing rates)."""
    sql_total = "SELECT COUNT(*) as total FROM predictions"
    sql_phishing = "SELECT COUNT(*) as phishing FROM predictions WHERE prediction = 'Phishing'"
    
    total_res = run_sql_query(sql_total)
    phish_res = run_sql_query(sql_phishing)
    
    total = total_res[0]['total'] if total_res else 0
    phishing = phish_res[0]['phishing'] if phish_res else 0
    safe = total - phishing
    
    phishing_rate = (phishing / total * 100) if total > 0 else 0.0
    
    # Get scans over time (grouped by date)
    sql_timeline = """
        SELECT strftime('%Y-%m-%d', scanned_at) as date,
               SUM(CASE WHEN prediction = 'Phishing' THEN 1 ELSE 0 END) as phishing,
               SUM(CASE WHEN prediction = 'Legitimate' THEN 1 ELSE 0 END) as safe,
               COUNT(*) as total
        FROM predictions
        GROUP BY date
        ORDER BY date ASC
        LIMIT 30
    """
    timeline = run_sql_query(sql_timeline)
    
    return {
        'total_scanned': total,
        'phishing_count': phishing,
        'safe_count': safe,
        'phishing_rate': round(phishing_rate, 2),
        'timeline': timeline
    }

if __name__ == '__main__':
    # Initialize DB
    init_db()
