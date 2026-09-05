import logging
from functools import wraps
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, get_dict_cursor

settings_bp = Blueprint('settings', __name__)

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity() or {}
        if identity.get("role") != "admin":
            return jsonify({"success": False, "error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return wrapper

DEFAULT_STORE_SETTINGS = [
    ('store_name', 'Apex Commerce', 'general', 'Public commercial brand name'),
    ('store_tagline', 'Engineered for Performance & Everyday Luxury', 'general', 'Brand slogan and subtitle'),
    ('support_email', 'support@apexstore.com', 'general', 'Customer care email address'),
    ('support_phone', '+1 (800) 555-APEX', 'general', 'Customer support hotline phone'),
    ('store_address', '742 Market Street, Financial District, San Francisco, CA 94103', 'general', 'Corporate physical headquarters'),
    ('currency_code', 'USD', 'general', 'Standard financial currency code'),
    ('currency_symbol', '$', 'general', 'Currency display symbol'),
    ('announcement_banner', '✨ FLASH SALE: Enjoy 10% OFF your first order with code APEX10 • Free shipping over $100!', 'general', 'Storefront header announcement marquee'),
    ('maintenance_mode', 'false', 'general', 'Block storefront access for site maintenance'),
    
    ('standard_shipping_fee', '15.00', 'shipping', 'Default shipping rate for orders under threshold'),
    ('free_shipping_threshold', '100.00', 'shipping', 'Minimum subtotal to unlock free complimentary delivery'),
    ('estimated_delivery_days', '3-5 business days', 'shipping', 'Customer-facing transit delivery time estimate'),
    ('shipping_carrier_name', 'Apex Express Priority Logistics', 'shipping', 'Primary delivery logistics partner'),
    
    ('tax_enabled', 'true', 'tax', 'Calculate sales tax during order checkout'),
    ('default_tax_rate', '8.5', 'tax', 'Standard sales tax percentage rate'),
    ('tax_included_in_price', 'false', 'tax', 'Whether product shelf prices already include tax'),
    
    ('low_stock_threshold', '5', 'inventory', 'Stock level that triggers amber low inventory warning'),
    ('allow_backorders', 'false', 'inventory', 'Allow customers to purchase items when stock is 0'),
    ('auto_hide_out_of_stock', 'false', 'inventory', 'Automatically hide products from catalog when inventory reaches 0'),
    
    ('enable_cod', 'true', 'orders_policies', 'Enable Cash on Delivery payment option'),
    ('enable_cards', 'true', 'orders_policies', 'Enable Credit/Debit card checkout'),
    ('enable_upi', 'true', 'orders_policies', 'Enable UPI and Digital Wallet checkout'),
    ('min_order_amount', '10.00', 'orders_policies', 'Minimum cart subtotal required to proceed to checkout'),
    ('return_window_days', '30', 'orders_policies', 'Number of days customer can initiate a return after delivery'),
    ('enable_reviews', 'true', 'orders_policies', 'Allow verified buyers to leave product reviews'),
    ('auto_approve_reviews', 'true', 'orders_policies', 'Automatically publish new reviews without manual moderation')
]

PUBLIC_KEYS = {
    'store_name', 'store_tagline', 'support_email', 'support_phone',
    'store_address', 'currency_code', 'currency_symbol', 'announcement_banner',
    'maintenance_mode', 'standard_shipping_fee', 'free_shipping_threshold',
    'estimated_delivery_days', 'enable_cod', 'enable_cards', 'enable_upi',
    'return_window_days', 'enable_reviews'
}

# ==========================================================
# PUBLIC STORE SETTINGS
# ==========================================================

@settings_bp.route("/settings/public", methods=["GET"])
def get_public_settings():
    """Retrieve public configuration values for storefront UI."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT setting_key, setting_value FROM store_settings")
        rows = cursor.fetchall()
        
        settings = {}
        for r in rows:
            k = r["setting_key"]
            if k in PUBLIC_KEYS:
                val = r["setting_value"]
                # Convert boolean strings
                if val.lower() == "true":
                    val = True
                elif val.lower() == "false":
                    val = False
                settings[k] = val

        return jsonify({"success": True, "settings": settings}), 200
    except Exception as e:
        logging.error(f"Error loading public settings: {e}")
        return jsonify({"success": False, "error": "Failed to load store settings"}), 500
    finally:
        cursor.close()
        conn.close()

# ==========================================================
# ADMIN STORE SETTINGS MANAGEMENT
# ==========================================================

@settings_bp.route("/admin/settings", methods=["GET"])
@admin_required
def admin_get_settings():
    """Admin: Fetch all store operational settings grouped by operational category."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT setting_key, setting_value, setting_group, description, updated_at FROM store_settings ORDER BY setting_group, setting_key")
        rows = cursor.fetchall()

        grouped = {
            "general": [],
            "shipping": [],
            "tax": [],
            "inventory": [],
            "orders_policies": []
        }
        settings_dict = {}

        for r in rows:
            grp = r["setting_group"]
            item = {
                "key": r["setting_key"],
                "value": r["setting_value"],
                "group": grp,
                "description": r.get("description") or "",
                "updated_at": r["updated_at"].isoformat() if r.get("updated_at") else None
            }
            if grp in grouped:
                grouped[grp].append(item)
            else:
                grouped[grp] = [item]

            settings_dict[r["setting_key"]] = r["setting_value"]

        return jsonify({
            "success": True,
            "grouped": grouped,
            "settings": settings_dict
        }), 200
    except Exception as e:
        logging.error(f"Error fetching admin settings: {e}")
        return jsonify({"success": False, "error": "Failed to fetch settings"}), 500
    finally:
        cursor.close()
        conn.close()

@settings_bp.route("/admin/settings", methods=["PUT"])
@admin_required
def admin_update_settings():
    """Admin: Update store settings in batch."""
    data = request.get_json(silent=True) or {}
    updates = data.get("settings") if isinstance(data.get("settings"), dict) else data

    if not updates or not isinstance(updates, dict):
        return jsonify({"success": False, "error": "No settings provided for update"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        updated_count = 0
        for key, val in updates.items():
            if val is None:
                continue
            
            # Stringify booleans and numbers
            val_str = str(val).strip() if not isinstance(val, bool) else ("true" if val else "false")

            # Validation
            if key in ('standard_shipping_fee', 'free_shipping_threshold', 'min_order_amount', 'default_tax_rate'):
                try:
                    num = float(val_str)
                    if num < 0:
                        return jsonify({"success": False, "error": f"Setting '{key}' cannot be negative"}), 400
                except ValueError:
                    return jsonify({"success": False, "error": f"Setting '{key}' must be a valid number"}), 400

            if key in ('low_stock_threshold', 'return_window_days'):
                try:
                    num = int(val_str)
                    if num < 0:
                        return jsonify({"success": False, "error": f"Setting '{key}' cannot be negative"}), 400
                except ValueError:
                    return jsonify({"success": False, "error": f"Setting '{key}' must be a valid integer"}), 400

            cursor.execute("""
                UPDATE store_settings 
                SET setting_value = %s, updated_at = NOW() 
                WHERE setting_key = %s
            """, (val_str, key))
            updated_count += 1

        conn.commit()

        return jsonify({
            "success": True,
            "message": f"Successfully saved {updated_count} store operational settings.",
            "updated_count": updated_count
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error updating settings: {e}")
        return jsonify({"success": False, "error": "Failed to update settings"}), 500
    finally:
        cursor.close()
        conn.close()

@settings_bp.route("/admin/settings/reset", methods=["POST"])
@admin_required
def admin_reset_settings():
    """Admin: Reset all store settings to recommended defaults."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        for k, val, grp, desc in DEFAULT_STORE_SETTINGS:
            cursor.execute("""
                UPDATE store_settings 
                SET setting_value = %s, updated_at = NOW() 
                WHERE setting_key = %s
            """, (val, k))
        conn.commit()

        return jsonify({
            "success": True,
            "message": "All store configuration settings have been reset to factory defaults."
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error resetting settings: {e}")
        return jsonify({"success": False, "error": "Failed to reset settings"}), 500
    finally:
        cursor.close()
        conn.close()
