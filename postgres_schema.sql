-- PostgreSQL Schema for Render

CREATE TABLE users (
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

CREATE TABLE otp_codes (
    id SERIAL PRIMARY KEY,
    identifier VARCHAR(100) UNIQUE NOT NULL,
    otp VARCHAR(255) NOT NULL,
    expiry_time TIMESTAMP NOT NULL
);

CREATE TABLE reset_links (
    id SERIAL PRIMARY KEY,
    identifier VARCHAR(100) UNIQUE NOT NULL,
    token VARCHAR(255) NOT NULL,
    expiry_time TIMESTAMP NOT NULL
);

CREATE TABLE token_blocklist (
    id SERIAL PRIMARY KEY,
    jti VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE pending_profile_updates (
    user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    otp_hash VARCHAR(255) NOT NULL,
    pending_data TEXT NOT NULL,
    expiry TIMESTAMP NOT NULL
);
