import logging
import re
import datetime
from functools import wraps
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, get_dict_cursor, is_mysql

coupons_bp = Blueprint('coupons', __name__)

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity() or {}
        if identity.get("role") != "admin":
            return jsonify({"success": False, "error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return wrapper

def format_coupon(c):
    """Serialize coupon database row into a standardized JSON response object."""
    if not c:
        return None
    
    disc_val = float(c.get("discount_value") or 0.0)
    disc_type = str(c.get("discount_type") or "percentage").lower()
    min_val = float(c.get("min_order_value") or 0.0)
    max_disc = float(c["max_discount_amount"]) if c.get("max_discount_amount") is not None else None
    
    if disc_type == "percentage":
        badge = f"{int(disc_val) if disc_val.is_integer() else disc_val}% OFF"
    else:
        badge = f"${disc_val:.2f} OFF"
        
    terms = []
    if min_val > 0:
        terms.append(f"Min order ${min_val:.2f}")
    if max_disc is not None and disc_type == "percentage":
        terms.append(f"Max discount ${max_disc:.2f}")
    terms_text = " • ".join(terms) if terms else "No minimum spend"

    expiry = c.get("expiry_date")
    expiry_iso = expiry.isoformat() if isinstance(expiry, (datetime.date, datetime.datetime)) else (str(expiry) if expiry else None)
    
    created = c.get("created_at")
    created_iso = created.isoformat() if isinstance(created, (datetime.date, datetime.datetime)) else (str(created) if created else None)

    # Determine status
    now = datetime.datetime.utcnow()
    is_active = bool(c.get("is_active", True))
    usage_limit = c.get("usage_limit")
    times_used = c.get("times_used") or 0
    
    is_expired = False
    if expiry and isinstance(expiry, datetime.datetime) and expiry < now:
        is_expired = True
    
    is_limit_reached = False
    if usage_limit is not None and times_used >= usage_limit:
        is_limit_reached = True

    status_label = "ACTIVE"
    if not is_active:
        status_label = "INACTIVE"
    elif is_expired:
        status_label = "EXPIRED"
    elif is_limit_reached:
        status_label = "DEPLETED"

    return {
        "id": c["id"],
        "code": c["code"],
        "description": c.get("description") or f"Save with code {c['code']}",
        "discount_type": disc_type,
        "discount_value": disc_val,
        "min_order_value": min_val,
        "max_discount_amount": max_disc,
        "usage_limit": usage_limit,
        "times_used": times_used,
        "is_active": is_active,
        "status_label": status_label,
        "badge": badge,
        "terms": terms_text,
        "expiry_date": expiry_iso,
        "created_at": created_iso,
        "total_savings_distributed": float(c.get("total_savings_distributed") or 0.0),
        "actual_redemptions": int(c.get("actual_redemptions") or times_used)
    }

# ==========================================================
# STOREFRONT CUSTOMER API
# ==========================================================

@coupons_bp.route("/coupons/available", methods=["GET"])
def get_available_coupons():
    """Returns active, unexpired, and available promotional coupons for storefront display."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("""
            SELECT id, code, description, discount_type, discount_value, min_order_value, 
                   max_discount_amount, expiry_date, usage_limit, times_used, is_active, created_at
            FROM coupons
            WHERE is_active = TRUE
              AND (usage_limit IS NULL OR times_used < usage_limit)
              AND (expiry_date IS NULL OR expiry_date >= NOW())
            ORDER BY discount_value DESC, min_order_value ASC
        """)
        rows = cursor.fetchall()
        coupons = [format_coupon(dict(r)) for r in rows]
        return jsonify({"success": True, "coupons": coupons}), 200
    except Exception as e:
        logging.error(f"Error fetching available coupons: {e}")
        return jsonify({"success": False, "error": "Failed to fetch coupons"}), 500
    finally:
        cursor.close()
        conn.close()

# Keep backward-compatible route under /checkout/coupons
@coupons_bp.route("/checkout/available-coupons", methods=["GET"])
def get_checkout_available_coupons():
    return get_available_coupons()

# ==========================================================
# ADMIN MANAGEMENT API
# ==========================================================

@coupons_bp.route("/admin/coupons", methods=["GET"])
@admin_required
def admin_get_coupons():
    """List all coupons with filtering, search, and usage analytics."""
    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "all").strip().lower()
    discount_type = request.args.get("discount_type", "all").strip().lower()

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Base query joining coupon_usage aggregates
        query = """
            SELECT c.*,
                   COALESCE(SUM(cu.discount_amount), 0) as total_savings_distributed,
                   COUNT(cu.id) as actual_redemptions
            FROM coupons c
            LEFT JOIN coupon_usage cu ON c.id = cu.coupon_id
            WHERE 1=1
        """
        params = []

        if search:
            query += " AND (UPPER(c.code) LIKE %s OR LOWER(c.description) LIKE %s)"
            s_param = f"%{search.upper()}%"
            d_param = f"%{search.lower()}%"
            params.extend([s_param, d_param])

        if discount_type in ["percentage", "fixed"]:
            query += " AND LOWER(c.discount_type) = %s"
            params.append(discount_type)

        if status_filter == "active":
            query += " AND c.is_active = TRUE AND (c.expiry_date IS NULL OR c.expiry_date >= NOW()) AND (c.usage_limit IS NULL OR c.times_used < c.usage_limit)"
        elif status_filter == "inactive":
            query += " AND c.is_active = FALSE"
        elif status_filter == "expired":
            query += " AND (c.expiry_date < NOW() OR (c.usage_limit IS NOT NULL AND c.times_used >= c.usage_limit))"

        query += " GROUP BY c.id ORDER BY c.id DESC"

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        coupons = [format_coupon(dict(r)) for r in rows]

        # Overall summary stats
        cursor.execute("""
            SELECT 
                COUNT(*) as total_coupons,
                SUM(CASE WHEN is_active = TRUE AND (expiry_date IS NULL OR expiry_date >= NOW()) AND (usage_limit IS NULL OR times_used < usage_limit) THEN 1 ELSE 0 END) as active_coupons,
                SUM(times_used) as total_redemptions
            FROM coupons
        """)
        stats_row = cursor.fetchone() or {}

        cursor.execute("SELECT COALESCE(SUM(discount_amount), 0) as total_savings FROM coupon_usage")
        savings_row = cursor.fetchone() or {}

        stats = {
            "total_coupons": int(stats_row.get("total_coupons") or 0),
            "active_coupons": int(stats_row.get("active_coupons") or 0),
            "total_redemptions": int(stats_row.get("total_redemptions") or 0),
            "total_savings_distributed": float(savings_row.get("total_savings") or 0.0)
        }

        return jsonify({
            "success": True,
            "coupons": coupons,
            "stats": stats
        }), 200
    except Exception as e:
        logging.error(f"Error fetching admin coupons: {e}")
        return jsonify({"success": False, "error": "Failed to fetch coupons"}), 500
    finally:
        cursor.close()
        conn.close()

@coupons_bp.route("/admin/coupons", methods=["POST"])
@admin_required
def admin_create_coupon():
    """Create a new promotional voucher code."""
    data = request.get_json(silent=True) or {}

    raw_code = data.get("code", "").strip().upper()
    if not raw_code:
        return jsonify({"success": False, "error": "Coupon code is required"}), 400

    # Validate code format
    if not re.match(r'^[A-Z0-9_-]{3,30}$', raw_code):
        return jsonify({"success": False, "error": "Coupon code must be 3-30 uppercase alphanumeric characters or hyphens"}), 400

    disc_type = str(data.get("discount_type") or "percentage").lower()
    if disc_type not in ["percentage", "fixed"]:
        return jsonify({"success": False, "error": "Discount type must be 'percentage' or 'fixed'"}), 400

    try:
        disc_val = float(data.get("discount_value") or 0.0)
        if disc_val <= 0:
            return jsonify({"success": False, "error": "Discount value must be greater than 0"}), 400
        if disc_type == "percentage" and disc_val > 100:
            return jsonify({"success": False, "error": "Percentage discount cannot exceed 100%"}), 400
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid discount value provided"}), 400

    min_val = 0.0
    if data.get("min_order_value") is not None and str(data.get("min_order_value")).strip() != "":
        try:
            min_val = max(0.0, float(data.get("min_order_value")))
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid minimum order value"}), 400

    max_disc = None
    if data.get("max_discount_amount") is not None and str(data.get("max_discount_amount")).strip() != "":
        try:
            max_disc = max(0.0, float(data.get("max_discount_amount")))
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid maximum discount amount"}), 400

    usage_limit = 100
    if data.get("usage_limit") is not None and str(data.get("usage_limit")).strip() != "":
        try:
            usage_limit = max(1, int(data.get("usage_limit")))
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid usage limit"}), 400

    expiry_date = None
    if data.get("expiry_date") and str(data.get("expiry_date")).strip():
        exp_str = str(data.get("expiry_date")).strip().replace("Z", "")
        try:
            expiry_date = datetime.datetime.fromisoformat(exp_str)
        except Exception:
            return jsonify({"success": False, "error": "Invalid expiry date format. Use YYYY-MM-DD or ISO string"}), 400

    description = (data.get("description") or "").strip()
    if not description:
        if disc_type == "percentage":
            description = f"Get {disc_val:.0f}% off orders"
            if min_val > 0:
                description += f" over ${min_val:.2f}"
            if max_disc:
                description += f" (Max savings ${max_disc:.2f})"
        else:
            description = f"Get ${disc_val:.2f} off orders"
            if min_val > 0:
                description += f" over ${min_val:.2f}"

    is_active = bool(data.get("is_active", True))

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Check uniqueness
        cursor.execute("SELECT id FROM coupons WHERE UPPER(code) = %s", (raw_code,))
        if cursor.fetchone():
            return jsonify({"success": False, "error": f"Coupon code '{raw_code}' already exists"}), 409

        cursor.execute("""
            INSERT INTO coupons (
                code, description, discount_type, discount_value, min_order_value,
                max_discount_amount, usage_limit, times_used, expiry_date, is_active
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 0, %s, %s)
        """, (
            raw_code, description, disc_type, disc_val, min_val,
            max_disc, usage_limit, expiry_date, is_active
        ))
        conn.commit()

        new_id = cursor.lastrowid if is_mysql(conn) else None
        if not new_id:
            cursor.execute("SELECT id FROM coupons WHERE code = %s", (raw_code,))
            new_id = cursor.fetchone()["id"]

        cursor.execute("SELECT * FROM coupons WHERE id = %s", (new_id,))
        created = cursor.fetchone()

        return jsonify({
            "success": True,
            "message": f"Coupon '{raw_code}' created successfully!",
            "coupon": format_coupon(dict(created))
        }), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Error creating coupon: {e}")
        return jsonify({"success": False, "error": "Failed to create coupon"}), 500
    finally:
        cursor.close()
        conn.close()

@coupons_bp.route("/admin/coupons/<int:coupon_id>", methods=["PUT"])
@admin_required
def admin_update_coupon(coupon_id):
    """Update an existing coupon's settings and parameters."""
    data = request.get_json(silent=True) or {}

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT * FROM coupons WHERE id = %s", (coupon_id,))
        existing = cursor.fetchone()
        if not existing:
            return jsonify({"success": False, "error": "Coupon not found"}), 404

        raw_code = data.get("code", existing["code"]).strip().upper()
        if not raw_code:
            return jsonify({"success": False, "error": "Coupon code cannot be blank"}), 400

        if not re.match(r'^[A-Z0-9_-]{3,30}$', raw_code):
            return jsonify({"success": False, "error": "Coupon code must be 3-30 uppercase alphanumeric characters"}), 400

        # Check uniqueness if code is changed
        if raw_code != existing["code"]:
            cursor.execute("SELECT id FROM coupons WHERE UPPER(code) = %s AND id != %s", (raw_code, coupon_id))
            if cursor.fetchone():
                return jsonify({"success": False, "error": f"Coupon code '{raw_code}' already exists"}), 409

        disc_type = str(data.get("discount_type", existing["discount_type"])).lower()
        if disc_type not in ["percentage", "fixed"]:
            return jsonify({"success": False, "error": "Invalid discount type"}), 400

        disc_val = float(data.get("discount_value", existing["discount_value"]))
        if disc_val <= 0:
            return jsonify({"success": False, "error": "Discount value must be greater than 0"}), 400
        if disc_type == "percentage" and disc_val > 100:
            return jsonify({"success": False, "error": "Percentage discount cannot exceed 100%"}), 400

        min_val = float(data.get("min_order_value", existing["min_order_value"] or 0.0))
        
        max_disc = data.get("max_discount_amount")
        if max_disc is not None and str(max_disc).strip() != "":
            max_disc = float(max_disc)
        else:
            max_disc = None

        usage_limit = int(data.get("usage_limit", existing["usage_limit"] or 100))
        
        expiry_date = existing["expiry_date"]
        if "expiry_date" in data:
            val = data["expiry_date"]
            if val and str(val).strip():
                exp_str = str(val).strip().replace("Z", "")
                expiry_date = datetime.datetime.fromisoformat(exp_str)
            else:
                expiry_date = None

        description = data.get("description", existing["description"])
        is_active = bool(data.get("is_active", existing["is_active"]))

        cursor.execute("""
            UPDATE coupons
            SET code = %s, description = %s, discount_type = %s, discount_value = %s,
                min_order_value = %s, max_discount_amount = %s, usage_limit = %s,
                expiry_date = %s, is_active = %s
            WHERE id = %s
        """, (
            raw_code, description, disc_type, disc_val, min_val,
            max_disc, usage_limit, expiry_date, is_active, coupon_id
        ))
        conn.commit()

        cursor.execute("SELECT * FROM coupons WHERE id = %s", (coupon_id,))
        updated = cursor.fetchone()

        return jsonify({
            "success": True,
            "message": f"Coupon '{raw_code}' updated successfully!",
            "coupon": format_coupon(dict(updated))
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error updating coupon: {e}")
        return jsonify({"success": False, "error": "Failed to update coupon"}), 500
    finally:
        cursor.close()
        conn.close()

@coupons_bp.route("/admin/coupons/<int:coupon_id>/toggle-status", methods=["PATCH"])
@admin_required
def admin_toggle_coupon_status(coupon_id):
    """Toggle coupon active status."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, code, is_active FROM coupons WHERE id = %s", (coupon_id,))
        coupon = cursor.fetchone()
        if not coupon:
            return jsonify({"success": False, "error": "Coupon not found"}), 404

        new_status = not bool(coupon["is_active"])
        cursor.execute("UPDATE coupons SET is_active = %s WHERE id = %s", (new_status, coupon_id))
        conn.commit()

        return jsonify({
            "success": True,
            "message": f"Coupon '{coupon['code']}' is now {'active' if new_status else 'inactive'}.",
            "is_active": new_status
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error toggling coupon status: {e}")
        return jsonify({"success": False, "error": "Failed to update status"}), 500
    finally:
        cursor.close()
        conn.close()

@coupons_bp.route("/admin/coupons/<int:coupon_id>", methods=["DELETE"])
@admin_required
def admin_delete_coupon(coupon_id):
    """Delete coupon or deactivate if orders are linked."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, code FROM coupons WHERE id = %s", (coupon_id,))
        coupon = cursor.fetchone()
        if not coupon:
            return jsonify({"success": False, "error": "Coupon not found"}), 404

        # Check if coupon has usage records
        cursor.execute("SELECT COUNT(*) as count FROM coupon_usage WHERE coupon_id = %s", (coupon_id,))
        usage_res = cursor.fetchone()
        usage_count = usage_res["count"] if isinstance(usage_res, dict) else usage_res[0]

        if usage_count > 0:
            # Soft-deactivate to prevent breaking historical records
            cursor.execute("UPDATE coupons SET is_active = FALSE WHERE id = %s", (coupon_id,))
            conn.commit()
            return jsonify({
                "success": True,
                "message": f"Coupon '{coupon['code']}' has {usage_count} customer orders linked. It has been deactivated to preserve order history.",
                "action": "deactivated"
            }), 200

        cursor.execute("DELETE FROM coupons WHERE id = %s", (coupon_id,))
        conn.commit()

        return jsonify({
            "success": True,
            "message": f"Coupon '{coupon['code']}' deleted successfully.",
            "action": "deleted"
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error deleting coupon: {e}")
        return jsonify({"success": False, "error": "Failed to delete coupon"}), 500
    finally:
        cursor.close()
        conn.close()

@coupons_bp.route("/admin/coupons/<int:coupon_id>/usages", methods=["GET"])
@admin_required
def admin_get_coupon_usages(coupon_id):
    """List recent customer orders and savings with this coupon."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("""
            SELECT cu.id, cu.discount_amount, cu.used_at,
                   u.name as user_name, u.email as user_email,
                   o.order_number, o.total_amount, o.status as order_status
            FROM coupon_usage cu
            JOIN users u ON cu.user_id = u.id
            LEFT JOIN orders o ON cu.order_id = o.id
            WHERE cu.coupon_id = %s
            ORDER BY cu.used_at DESC
            LIMIT 50
        """, (coupon_id,))
        usages = cursor.fetchall()
        
        return jsonify({
            "success": True,
            "usages": [
                {
                    "id": u["id"],
                    "user_name": u["user_name"],
                    "user_email": u["user_email"],
                    "order_number": u.get("order_number") or "N/A",
                    "order_status": u.get("order_status") or "N/A",
                    "discount_amount": float(u["discount_amount"]),
                    "used_at": u["used_at"].isoformat() if isinstance(u["used_at"], (datetime.date, datetime.datetime)) else str(u["used_at"])
                }
                for u in usages
            ]
        }), 200
    except Exception as e:
        logging.error(f"Error fetching coupon usages: {e}")
        return jsonify({"success": False, "error": "Failed to fetch coupon usages"}), 500
    finally:
        cursor.close()
        conn.close()
