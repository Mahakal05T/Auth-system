import logging
import re
from functools import wraps
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, count_admins, get_dict_cursor
from utils import is_valid_email, generate_random_password, hash_password
from email_service import send_credentials_email

ALLOWED_ROLES = {"user", "admin"}

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity() or {}
        if identity.get("role") != "admin":
            return jsonify({"success": False, "error": "Unauthorized access"}), 403
        return f(*args, **kwargs)
    return wrapper

@admin_bp.route("/dashboard", methods=["GET"])
@admin_required
def admin_dashboard():
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, name, email, phone, role, created_at, status FROM users")
        users_records = cursor.fetchall()

        users = [dict(u) for u in users_records]
        total_users = len(users)
        active_users = len([u for u in users if u.get("status") == "active"])
        
        return jsonify({
            "success": True,
            "data": {
                "users": users,
                "total_users": total_users,
                "active_users": active_users
            }
        }), 200
    finally:
        cursor.close()
        conn.close()

@admin_bp.route("/add_user", methods=["POST"])
@admin_required
def add_user():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Missing JSON data"}), 400

    name = data.get("name")
    email = data.get("email")
    phone = data.get("phone")
    role = data.get("role", "user").lower()

    if not name or not email or not phone:
        return jsonify({"success": False, "error": "Missing required fields"}), 400
    if not is_valid_email(email):
        return jsonify({"success": False, "error": "Invalid email format"}), 400
    if phone and not re.match(r'^\+?\d{7,15}$', phone):
        return jsonify({"success": False, "error": "Invalid phone number format"}), 400
    if role not in ALLOWED_ROLES:
        return jsonify({"success": False, "error": "Invalid role"}), 400

    temp_password = generate_random_password()
    hashed_password = hash_password(temp_password)

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id FROM users WHERE email=%s OR phone=%s", (email, phone))
        if cursor.fetchone():
            return jsonify({"success": False, "error": "User with this email or phone already exists"}), 409

        cursor.execute(
            "INSERT INTO users (name, email, phone, password_hash, role, status) "
            "VALUES (%s, %s, %s, %s, %s, 'active')",
            (name, email, phone, hashed_password, role)
        )
        conn.commit()

        email_sent = send_credentials_email(email, temp_password)
        return jsonify({"success": True, "message": "User added successfully", "email_sent": email_sent}), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Error adding user: {e}")
        return jsonify({"success": False, "error": "Database error while adding user"}), 500
    finally:
        cursor.close()
        conn.close()

@admin_bp.route("/delete_user/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    current_identity = get_jwt_identity() or {}
    if user_id == current_identity.get("id"):
        return jsonify({"success": False, "error": "You cannot delete your own account"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, role FROM users WHERE id=%s", (user_id,))
        target = cursor.fetchone()
        if not target:
            return jsonify({"success": False, "error": "User not found"}), 404

        if target["role"] == "admin" and count_admins(conn) <= 1:
            return jsonify({"success": False, "error": "Cannot delete the last admin"}), 400

        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn.commit()
        return jsonify({"success": True, "message": "User deleted successfully."}), 200
    finally:
        cursor.close()
        conn.close()

@admin_bp.route("/set_role", methods=["PATCH"])
@admin_required
def admin_set_role():
    data = request.get_json(force=True, silent=True) or {}
    user_id = data.get("user_id")
    new_role = data.get("role")

    if not user_id or not new_role:
        return jsonify({"success": False, "error": "user_id and role are required"}), 400
    if new_role not in ALLOWED_ROLES:
        return jsonify({"success": False, "error": f"Invalid role. Must be one of {list(ALLOWED_ROLES)}"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, role FROM users WHERE id=%s", (user_id,))
        target = cursor.fetchone()
        if not target:
            return jsonify({"success": False, "error": "User not found"}), 404

        current_identity = get_jwt_identity() or {}
        if target["role"] == "admin" and new_role != "admin":
            if count_admins(conn) <= 1:
                return jsonify({"success": False, "error": "Cannot remove the last admin"}), 400
            if target["id"] == current_identity.get("id"):
                return jsonify({"success": False, "error": "Admins cannot remove their own admin role"}), 400

        cursor.execute("UPDATE users SET role=%s WHERE id=%s", (new_role, user_id))
        conn.commit()
        return jsonify({"success": True, "message": "Role updated successfully", "user_id": user_id, "role": new_role}), 200
    finally:
        cursor.close()
        conn.close()

# ==========================================================
# ADMIN ORDERS MANAGEMENT
# ==========================================================

@admin_bp.route("/orders", methods=["GET"])
@admin_required
def admin_get_orders():
    """Retrieve all platform orders with search, status filters, and metrics."""
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "all").strip().upper()
    page = max(1, int(request.args.get("page", 1)))
    limit = max(1, min(50, int(request.args.get("limit", 15))))
    offset = (page - 1) * limit

    conditions = []
    params = []

    if q:
        conditions.append("(LOWER(o.order_number) LIKE %s OR LOWER(u.name) LIKE %s OR LOWER(u.email) LIKE %s)")
        q_wild = f"%{q.lower()}%"
        params.extend([q_wild, q_wild, q_wild])

    if status and status != "ALL":
        conditions.append("UPPER(o.status) = %s")
        params.append(status)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # 1. Metric counts
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN UPPER(status) IN ('PLACED', 'PROCESSING', 'PENDING') THEN 1 ELSE 0 END) as processing,
                SUM(CASE WHEN UPPER(status) = 'SHIPPED' THEN 1 ELSE 0 END) as shipped,
                SUM(CASE WHEN UPPER(status) = 'DELIVERED' THEN 1 ELSE 0 END) as delivered,
                SUM(CASE WHEN UPPER(status) = 'CANCELLED' THEN 1 ELSE 0 END) as cancelled
            FROM orders
        """)
        counts_row = cursor.fetchone() or {}
        counts = {
            "total": int(counts_row.get("total") or 0),
            "processing": int(counts_row.get("processing") or 0),
            "shipped": int(counts_row.get("shipped") or 0),
            "delivered": int(counts_row.get("delivered") or 0),
            "cancelled": int(counts_row.get("cancelled") or 0)
        }

        # 2. Filtered count
        cursor.execute(f"""
            SELECT COUNT(*) as filtered_total
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            {where_clause}
        """, tuple(params))
        total_filtered = cursor.fetchone()["filtered_total"]

        # 3. Query orders page
        query = f"""
            SELECT o.id, o.order_number, o.status, o.subtotal, o.discount, 
                   o.shipping_fee, o.total_amount, o.payment_method, o.payment_status,
                   o.created_at, o.updated_at,
                   u.name as customer_name, u.email as customer_email, u.phone as customer_phone,
                   (SELECT COUNT(*) FROM order_items oi WHERE oi.order_id = o.id) as total_items_count,
                   (
                       SELECT pi.image_url FROM order_items oi2
                       LEFT JOIN product_images pi ON oi2.product_id = pi.product_id
                       WHERE oi2.order_id = o.id
                       ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
                   ) as primary_image
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            {where_clause}
            ORDER BY o.created_at DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        orders = []
        for r in rows:
            orders.append({
                "id": r["id"],
                "order_number": r["order_number"],
                "customer": r["customer_name"] or "Guest User",
                "email": r["customer_email"] or "N/A",
                "phone": r["customer_phone"] or "N/A",
                "status": r["status"].upper(),
                "total": float(r["total_amount"]),
                "subtotal": float(r["subtotal"]),
                "discount": float(r["discount"] or 0.0),
                "shipping_fee": float(r["shipping_fee"] or 0.0),
                "items_count": int(r.get("total_items_count") or 0),
                "payment_method": r["payment_method"],
                "payment_status": r["payment_status"],
                "primary_image": r.get("primary_image") or "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=300&q=80",
                "date": str(r["created_at"])[:10] if r.get("created_at") else "Recent",
                "created_at": str(r["created_at"]) if r.get("created_at") else None
            })

        total_pages = max(1, (total_filtered + limit - 1) // limit)
        return jsonify({
            "success": True,
            "orders": orders,
            "total": total_filtered,
            "page": page,
            "total_pages": total_pages,
            "counts": counts
        }), 200
    finally:
        cursor.close()
        conn.close()

@admin_bp.route("/orders/<identifier>", methods=["GET"])
@admin_required
def admin_get_order_detail(identifier):
    """Retrieve complete order details for admin inspection."""
    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("""
            SELECT o.*, u.name as customer_name, u.email as customer_email, u.phone as customer_phone
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            WHERE o.id = %s OR o.order_number = %s
            LIMIT 1
        """, (identifier, identifier))
        order = cursor.fetchone()

        if not order:
            return jsonify({"success": False, "error": "Order not found"}), 404

        order_id = order["id"]

        # Fetch items
        cursor.execute("""
            SELECT oi.id, oi.product_id, oi.product_name, oi.price, oi.quantity, oi.total,
                   (
                       SELECT pi.image_url FROM product_images pi 
                       WHERE pi.product_id = oi.product_id 
                       ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
                   ) as image
            FROM order_items oi
            WHERE oi.order_id = %s
            ORDER BY oi.id ASC
        """, (order_id,))
        items = cursor.fetchall()

        import json
        shipping_snapshot = {}
        if order.get("shipping_address_snapshot"):
            try:
                shipping_snapshot = json.loads(order["shipping_address_snapshot"])
            except Exception:
                shipping_snapshot = {}

        return jsonify({
            "success": True,
            "order": {
                "id": order["id"],
                "order_number": order["order_number"],
                "customer": {
                    "name": order["customer_name"],
                    "email": order["customer_email"],
                    "phone": order["customer_phone"]
                },
                "status": order["status"].upper(),
                "subtotal": float(order["subtotal"]),
                "discount": float(order["discount"] or 0.0),
                "shipping_fee": float(order["shipping_fee"] or 0.0),
                "total_amount": float(order["total_amount"]),
                "payment_method": order["payment_method"],
                "payment_status": order["payment_status"],
                "shipping_address": shipping_snapshot,
                "created_at": str(order["created_at"]) if order.get("created_at") else None,
                "updated_at": str(order["updated_at"]) if order.get("updated_at") else None,
                "items": [{
                    "id": it["id"],
                    "product_id": it["product_id"],
                    "product_name": it["product_name"],
                    "price": float(it["price"]),
                    "quantity": int(it["quantity"]),
                    "total": float(it["total"]),
                    "image": it.get("image") or "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=300&q=80"
                } for it in items]
            }
        }), 200
    finally:
        cursor.close()
        conn.close()

@admin_bp.route("/orders/<identifier>/status", methods=["PATCH"])
@admin_required
def admin_update_order_status(identifier):
    """Admin updates fulfillment status with inventory restocking on cancellation."""
    data = request.get_json(silent=True) or {}
    new_status = (data.get("status") or "").strip().upper()

    valid_statuses = ["PLACED", "CONFIRMED", "PROCESSING", "SHIPPED", "DELIVERED", "CANCELLED"]
    if new_status not in valid_statuses:
        return jsonify({"success": False, "error": f"Invalid status. Must be one of {valid_statuses}"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id, order_number, user_id, status, payment_status FROM orders WHERE id=%s OR order_number=%s", (identifier, identifier))
        order = cursor.fetchone()
        if not order:
            return jsonify({"success": False, "error": "Order not found"}), 404

        current_status = order["status"].upper()
        order_id = order["id"]
        user_id = order["user_id"]

        new_payment_status = order["payment_status"]

        # If transitioning to CANCELLED from non-cancelled status, restore inventory
        if new_status == "CANCELLED" and current_status != "CANCELLED":
            cursor.execute("SELECT product_id, quantity FROM order_items WHERE order_id = %s", (order_id,))
            items = cursor.fetchall()
            for it in items:
                p_id = it["product_id"]
                qty = int(it["quantity"])
                if p_id:
                    cursor.execute("UPDATE products SET stock = stock + %s WHERE id = %s", (qty, p_id))
                    cursor.execute("SELECT stock FROM products WHERE id = %s", (p_id,))
                    prod = cursor.fetchone()
                    rem_stock = prod["stock"] if prod else 0
                    cursor.execute("""
                        INSERT INTO inventory_logs (product_id, change_type, quantity_changed, remaining_stock, notes)
                        VALUES (%s, 'ADMIN_CANCEL_RESTOCK', %s, %s, %s)
                    """, (p_id, qty, rem_stock, f"Admin cancelled Order #{order['order_number']}"))

            if order["payment_status"] == "PAID":
                new_payment_status = "REFUNDED"
            else:
                new_payment_status = "CANCELLED"

        elif new_status == "DELIVERED" and order["payment_status"] == "PENDING":
            # COD payment collected upon delivery
            new_payment_status = "PAID"

        # Update order record
        cursor.execute("""
            UPDATE orders 
            SET status = %s, payment_status = %s 
            WHERE id = %s
        """, (new_status, new_payment_status, order_id))

        # Update payment record if exists
        cursor.execute("UPDATE payments SET status = %s WHERE order_id = %s", (
            "COMPLETED" if new_payment_status == "PAID" else ("REFUNDED" if new_payment_status == "REFUNDED" else "CANCELLED"),
            order_id
        ))

        # Send customer notification
        cursor.execute("""
            INSERT INTO notifications (user_id, title, message, type)
            VALUES (%s, %s, %s, 'ORDER_STATUS_UPDATED')
        """, (
            user_id,
            f"Order #{order['order_number']} Update",
            f"Your order status has been updated to {new_status}."
        ))

        conn.commit()

        return jsonify({
            "success": True, 
            "message": f"Order #{order['order_number']} updated to {new_status}.",
            "status": new_status,
            "payment_status": new_payment_status
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error updating order status: {e}")
        return jsonify({"success": False, "error": "Failed to update order status"}), 500
    finally:
        cursor.close()
        conn.close()

