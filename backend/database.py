import os
import logging

def ensure_mysql_database(host, port, user, password, db_name):
    """Auto-create MySQL database if it does not exist."""
    try:
        import pymysql
        conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            autocommit=True
        )
        cur = conn.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
        cur.close()
        conn.close()
        logging.info(f"Ensured MySQL database '{db_name}' exists.")
    except Exception as e:
        logging.warning(f"Could not auto-create MySQL database '{db_name}': {e}")

def ensure_postgres_database(host, port, user, password, db_name):
    """Auto-create PostgreSQL database if it does not exist."""
    try:
        import psycopg2
        from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            dbname="postgres"
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (db_name,))
        if not cur.fetchone():
            cur.execute(f'CREATE DATABASE "{db_name}"')
            logging.info(f"Created PostgreSQL database '{db_name}'.")
        cur.close()
        conn.close()
    except Exception as e:
        logging.warning(f"Could not auto-create PostgreSQL database '{db_name}': {e}")

def connect_db():
    db_url = os.getenv("DATABASE_URL")
    db_engine = os.getenv("DB_ENGINE", "").lower()
    
    if db_url:
        if db_url.startswith("postgresql://") or db_url.startswith("postgres://"):
            import psycopg2
            return psycopg2.connect(db_url)
        elif db_url.startswith("mysql://") or db_url.startswith("mysql+pymysql://"):
            try:
                import pymysql
                import urllib.parse as urlparse
                url = urlparse.urlparse(db_url)
                db_name = url.path.lstrip("/")
                try:
                    return pymysql.connect(
                        host=url.hostname or "localhost",
                        port=url.port or 3306,
                        user=url.username or "root",
                        password=url.password or "",
                        database=db_name,
                        autocommit=True
                    )
                except Exception:
                    ensure_mysql_database(
                        url.hostname or "localhost",
                        url.port or 3306,
                        url.username or "root",
                        url.password or "",
                        db_name
                    )
                    return pymysql.connect(
                        host=url.hostname or "localhost",
                        port=url.port or 3306,
                        user=url.username or "root",
                        password=url.password or "",
                        database=db_name,
                        autocommit=True
                    )
            except Exception as e:
                logging.error(f"Failed to connect via PyMySQL URL: {e}")
                raise

    if db_engine == "mysql" or os.getenv("DB_PORT") == "3306":
        host = os.getenv("DB_HOST", "localhost")
        port = int(os.getenv("DB_PORT", 3306))
        user = os.getenv("DB_USER", "root")
        password = os.getenv("DB_PASS", "")
        db_name = os.getenv("DB_NAME", "auth_db")
        
        try:
            import pymysql
            try:
                return pymysql.connect(
                    host=host, port=port, user=user, password=password, database=db_name, autocommit=True
                )
            except pymysql.err.OperationalError as oe:
                if oe.args[0] == 1049:  # Unknown database
                    ensure_mysql_database(host, port, user, password, db_name)
                    return pymysql.connect(
                        host=host, port=port, user=user, password=password, database=db_name, autocommit=True
                    )
                raise
        except ImportError:
            import mysql.connector
            try:
                return mysql.connector.connect(
                    host=host, port=port, user=user, password=password, database=db_name, autocommit=True
                )
            except mysql.connector.Error as err:
                if err.errno == 1049:
                    ensure_mysql_database(host, port, user, password, db_name)
                    return mysql.connector.connect(
                        host=host, port=port, user=user, password=password, database=db_name, autocommit=True
                    )
                raise

    # Default to PostgreSQL
    import psycopg2
    required_vars = ["DB_HOST", "DB_USER", "DB_PASS", "DB_NAME"]
    missing = [v for v in required_vars if not os.getenv(v)]
    if missing:
        raise RuntimeError(f"Missing required DB env vars: {', '.join(missing)}")
    
    host = os.getenv("DB_HOST")
    port = int(os.getenv("DB_PORT", 5432))
    user = os.getenv("DB_USER")
    password = os.getenv("DB_PASS")
    db_name = os.getenv("DB_NAME")

    try:
        return psycopg2.connect(host=host, port=port, user=user, password=password, dbname=db_name)
    except psycopg2.OperationalError:
        ensure_postgres_database(host, port, user, password, db_name)
        return psycopg2.connect(host=host, port=port, user=user, password=password, dbname=db_name)

def is_mysql(conn):
    module = type(conn).__module__
    return "pymysql" in module or "mysql" in module

def get_dict_cursor(conn):
    module = type(conn).__module__
    if "psycopg2" in module:
        import psycopg2.extras
        return conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    elif "pymysql" in module:
        import pymysql.cursors
        return conn.cursor(pymysql.cursors.DictCursor)
    elif "mysql" in module:
        return conn.cursor(dictionary=True)
    else:
        return conn.cursor()

def count_admins(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    row = cursor.fetchone()
    cursor.close()
    if isinstance(row, dict):
        return list(row.values())[0]
    return row[0] if row else 0

MYSQL_TABLES_SQL = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255),
        emp_id VARCHAR(50) UNIQUE,
        email VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(20) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        department VARCHAR(100) DEFAULT 'Unassigned',
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS otp_codes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        identifier VARCHAR(100) UNIQUE NOT NULL,
        otp VARCHAR(255) NOT NULL,
        expiry_time TIMESTAMP NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS reset_links (
        id INT AUTO_INCREMENT PRIMARY KEY,
        identifier VARCHAR(100) UNIQUE NOT NULL,
        token VARCHAR(255) NOT NULL,
        expiry_time TIMESTAMP NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS token_blocklist (
        id INT AUTO_INCREMENT PRIMARY KEY,
        jti VARCHAR(255) UNIQUE NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS pending_profile_updates (
        user_id INT PRIMARY KEY,
        otp_hash VARCHAR(255) NOT NULL,
        pending_data TEXT NOT NULL,
        expiry TIMESTAMP NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS categories (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL UNIQUE,
        slug VARCHAR(120) NOT NULL UNIQUE,
        description TEXT,
        image_url TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        category_id INT,
        name VARCHAR(255) NOT NULL,
        slug VARCHAR(280) NOT NULL UNIQUE,
        description TEXT,
        price DECIMAL(10, 2) NOT NULL,
        discount_price DECIMAL(10, 2),
        stock INT NOT NULL DEFAULT 0,
        sku VARCHAR(100) UNIQUE,
        brand VARCHAR(100),
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS product_images (
        id INT AUTO_INCREMENT PRIMARY KEY,
        product_id INT NOT NULL,
        image_url TEXT NOT NULL,
        is_primary BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS addresses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        full_name VARCHAR(150) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        street_address TEXT NOT NULL,
        city VARCHAR(100) NOT NULL,
        state VARCHAR(100),
        postal_code VARCHAR(20) NOT NULL,
        country VARCHAR(100) DEFAULT 'USA',
        is_default BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS cart (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS cart_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        cart_id INT NOT NULL,
        product_id INT NOT NULL,
        quantity INT NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (cart_id, product_id),
        FOREIGN KEY (cart_id) REFERENCES cart(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS wishlist (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS wishlist_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        wishlist_id INT NOT NULL,
        product_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (wishlist_id, product_id),
        FOREIGN KEY (wishlist_id) REFERENCES wishlist(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_number VARCHAR(50) NOT NULL UNIQUE,
        user_id INT NOT NULL,
        address_id INT,
        shipping_address_snapshot TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'PLACED',
        subtotal DECIMAL(10, 2) NOT NULL,
        discount DECIMAL(10, 2) DEFAULT 0.00,
        shipping_fee DECIMAL(10, 2) DEFAULT 0.00,
        total_amount DECIMAL(10, 2) NOT NULL,
        payment_method VARCHAR(50) NOT NULL DEFAULT 'COD',
        payment_status VARCHAR(30) NOT NULL DEFAULT 'PENDING',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
        FOREIGN KEY (address_id) REFERENCES addresses(id) ON DELETE SET NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS order_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT NOT NULL,
        product_id INT,
        product_name VARCHAR(255) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        quantity INT NOT NULL,
        total DECIMAL(10, 2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS payments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT NOT NULL,
        user_id INT NOT NULL,
        payment_method VARCHAR(50) NOT NULL,
        transaction_id VARCHAR(100),
        amount DECIMAL(10, 2) NOT NULL,
        status VARCHAR(30) NOT NULL DEFAULT 'PENDING',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS coupons (
        id INT AUTO_INCREMENT PRIMARY KEY,
        code VARCHAR(50) NOT NULL UNIQUE,
        discount_type VARCHAR(20) NOT NULL DEFAULT 'percentage',
        discount_value DECIMAL(10, 2) NOT NULL,
        min_order_value DECIMAL(10, 2) DEFAULT 0.00,
        max_discount_amount DECIMAL(10, 2),
        start_date TIMESTAMP NULL,
        expiry_date TIMESTAMP NULL,
        usage_limit INT DEFAULT 100,
        times_used INT DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS coupon_usage (
        id INT AUTO_INCREMENT PRIMARY KEY,
        coupon_id INT NOT NULL,
        user_id INT NOT NULL,
        order_id INT,
        discount_amount DECIMAL(10, 2) NOT NULL,
        used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (coupon_id) REFERENCES coupons(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS reviews (
        id INT AUTO_INCREMENT PRIMARY KEY,
        product_id INT NOT NULL,
        user_id INT NOT NULL,
        rating INT NOT NULL,
        review_text TEXT,
        is_verified_purchase BOOLEAN DEFAULT FALSE,
        status VARCHAR(20) DEFAULT 'approved',
        admin_reply TEXT DEFAULT NULL,
        admin_reply_at TIMESTAMP NULL DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS returns (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT NOT NULL,
        user_id INT NOT NULL,
        return_number VARCHAR(60) UNIQUE,
        reason TEXT NOT NULL,
        refund_amount DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
        refund_method VARCHAR(50) DEFAULT 'ORIGINAL_PAYMENT',
        customer_notes TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'REQUESTED',
        resolution_action VARCHAR(50) DEFAULT 'REFUND',
        admin_notes TEXT,
        processed_at TIMESTAMP NULL DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        title VARCHAR(200) NOT NULL,
        message TEXT NOT NULL,
        type VARCHAR(50) DEFAULT 'ORDER_UPDATE',
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS inventory_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        product_id INT NOT NULL,
        change_type VARCHAR(50) NOT NULL,
        quantity_changed INT NOT NULL,
        remaining_stock INT NOT NULL,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS store_settings (
        setting_key VARCHAR(100) PRIMARY KEY,
        setting_value TEXT NOT NULL,
        setting_group VARCHAR(50) NOT NULL DEFAULT 'general',
        description VARCHAR(255) NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );
    """
]

POSTGRES_TABLES_SQL = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        emp_id VARCHAR(50) UNIQUE,
        email VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(20) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        department VARCHAR(100) DEFAULT 'Unassigned',
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS otp_codes (
        id SERIAL PRIMARY KEY,
        identifier VARCHAR(100) UNIQUE NOT NULL,
        otp VARCHAR(255) NOT NULL,
        expiry_time TIMESTAMP NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS reset_links (
        id SERIAL PRIMARY KEY,
        identifier VARCHAR(100) UNIQUE NOT NULL,
        token VARCHAR(255) NOT NULL,
        expiry_time TIMESTAMP NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS token_blocklist (
        id SERIAL PRIMARY KEY,
        jti VARCHAR(255) UNIQUE NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS pending_profile_updates (
        user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        otp_hash VARCHAR(255) NOT NULL,
        pending_data TEXT NOT NULL,
        expiry TIMESTAMP NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL UNIQUE,
        slug VARCHAR(120) NOT NULL UNIQUE,
        description TEXT,
        image_url TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        category_id INT REFERENCES categories(id) ON DELETE SET NULL,
        name VARCHAR(255) NOT NULL,
        slug VARCHAR(280) NOT NULL UNIQUE,
        description TEXT,
        price NUMERIC(10, 2) NOT NULL,
        discount_price NUMERIC(10, 2),
        stock INT NOT NULL DEFAULT 0,
        sku VARCHAR(100) UNIQUE,
        brand VARCHAR(100),
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS product_images (
        id SERIAL PRIMARY KEY,
        product_id INT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
        image_url TEXT NOT NULL,
        is_primary BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS addresses (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        full_name VARCHAR(150) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        street_address TEXT NOT NULL,
        city VARCHAR(100) NOT NULL,
        state VARCHAR(100),
        postal_code VARCHAR(20) NOT NULL,
        country VARCHAR(100) DEFAULT 'USA',
        is_default BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS cart (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS cart_items (
        id SERIAL PRIMARY KEY,
        cart_id INT NOT NULL REFERENCES cart(id) ON DELETE CASCADE,
        product_id INT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
        quantity INT NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (cart_id, product_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS wishlist (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS wishlist_items (
        id SERIAL PRIMARY KEY,
        wishlist_id INT NOT NULL REFERENCES wishlist(id) ON DELETE CASCADE,
        product_id INT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (wishlist_id, product_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        order_number VARCHAR(50) NOT NULL UNIQUE,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
        address_id INT REFERENCES addresses(id) ON DELETE SET NULL,
        shipping_address_snapshot TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'PLACED',
        subtotal NUMERIC(10, 2) NOT NULL,
        discount NUMERIC(10, 2) DEFAULT 0.00,
        shipping_fee NUMERIC(10, 2) DEFAULT 0.00,
        total_amount NUMERIC(10, 2) NOT NULL,
        payment_method VARCHAR(50) NOT NULL DEFAULT 'COD',
        payment_status VARCHAR(30) NOT NULL DEFAULT 'PENDING',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS order_items (
        id SERIAL PRIMARY KEY,
        order_id INT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
        product_id INT REFERENCES products(id) ON DELETE SET NULL,
        product_name VARCHAR(255) NOT NULL,
        price NUMERIC(10, 2) NOT NULL,
        quantity INT NOT NULL,
        total NUMERIC(10, 2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        order_id INT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        payment_method VARCHAR(50) NOT NULL,
        transaction_id VARCHAR(100),
        amount NUMERIC(10, 2) NOT NULL,
        status VARCHAR(30) NOT NULL DEFAULT 'PENDING',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS coupons (
        id SERIAL PRIMARY KEY,
        code VARCHAR(50) NOT NULL UNIQUE,
        discount_type VARCHAR(20) NOT NULL DEFAULT 'percentage',
        discount_value NUMERIC(10, 2) NOT NULL,
        min_order_value NUMERIC(10, 2) DEFAULT 0.00,
        max_discount_amount NUMERIC(10, 2),
        start_date TIMESTAMP,
        expiry_date TIMESTAMP,
        usage_limit INT DEFAULT 100,
        times_used INT DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS coupon_usage (
        id SERIAL PRIMARY KEY,
        coupon_id INT NOT NULL REFERENCES coupons(id) ON DELETE CASCADE,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        order_id INT REFERENCES orders(id) ON DELETE CASCADE,
        discount_amount NUMERIC(10, 2) NOT NULL,
        used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS reviews (
        id SERIAL PRIMARY KEY,
        product_id INT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
        review_text TEXT,
        is_verified_purchase BOOLEAN DEFAULT FALSE,
        status VARCHAR(20) DEFAULT 'approved',
        admin_reply TEXT DEFAULT NULL,
        admin_reply_at TIMESTAMP NULL DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS returns (
        id SERIAL PRIMARY KEY,
        order_id INT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        return_number VARCHAR(60) UNIQUE,
        reason TEXT NOT NULL,
        refund_amount NUMERIC(10, 2) NOT NULL DEFAULT 0.00,
        refund_method VARCHAR(50) DEFAULT 'ORIGINAL_PAYMENT',
        customer_notes TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'REQUESTED',
        resolution_action VARCHAR(50) DEFAULT 'REFUND',
        admin_notes TEXT,
        processed_at TIMESTAMP NULL DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(200) NOT NULL,
        message TEXT NOT NULL,
        type VARCHAR(50) DEFAULT 'ORDER_UPDATE',
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS inventory_logs (
        id SERIAL PRIMARY KEY,
        product_id INT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
        change_type VARCHAR(50) NOT NULL,
        quantity_changed INT NOT NULL,
        remaining_stock INT NOT NULL,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS store_settings (
        setting_key VARCHAR(100) PRIMARY KEY,
        setting_value TEXT NOT NULL,
        setting_group VARCHAR(50) NOT NULL DEFAULT 'general',
        description VARCHAR(255) NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
]

def init_db(conn=None):
    """Ensure database and all required tables exist for both MySQL and PostgreSQL."""
    close_at_end = False
    if conn is None:
        conn = connect_db()
        close_at_end = True
        
    try:
        cursor = conn.cursor()
        queries = MYSQL_TABLES_SQL if is_mysql(conn) else POSTGRES_TABLES_SQL
        for q in queries:
            cursor.execute(q)
        if hasattr(conn, 'commit'):
            conn.commit()
        cursor.close()
        logging.info("Database tables verified/created successfully.")
    except Exception as e:
        logging.error(f"Error initializing database tables: {e}")
        raise
    finally:
        if close_at_end:
            conn.close()
