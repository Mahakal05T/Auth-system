import logging
import secrets
from datetime import datetime
from functools import wraps
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, get_dict_cursor

returns_bp = Blueprint('returns', __name__)

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity() or {}
        if identity.get("role") != "admin":
            return jsonify({"success": False, "error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return wrapper

def generate_return_number():
    rand = secrets.token_hex(3).upper()
    return f"RET-{datetime.utcnow().strftime('%Y%m%d')}-{rand}"

# ==========================================================
# CUSTOMER RETURNS API
# ==========================================================

@returns_bp.route("/returns/request", methods=["POST"])
@jwt_required()
def customer_request_return():
    """Customer initiates a return or dispute request for an order."""
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    data = request.get_json(silent=True) or {}
    order_identifier = data.get("order_id") or data.get("order_number")
    reason = (data.get("reason") or "").strip()
    customer_notes = (data.get("customer_notes") or data.get("details") or "").strip()
    refund_method = data.get("refund_method") or "ORIGINAL_PAYMENT"

    if not order_identifier:
        return jsonify({"success": False, "error": "Order identifier is required"}), 400
    if not reason:
        return jsonify({"success": False, "error": "Please select a reason for the return"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Check order exists and belongs to user
        cursor.execute("""
            SELECT id, order_number, status, total_amount, payment_status, created_at 
            FROM orders 
            WHERE (id = %s OR order_number = %s) AND user_id = %s
            LIMIT 1
        """, (order_identifier, order_identifier, user_id))
        order = cursor.fetchone()
        if not order:
            return jsonify({"success": False, "error": "Order not found or unauthorized"}), 404

        order_status = order["status"].upper()
        if order_status in ("CANCELLED", "REFUNDED"):
            return jsonify({"success": False, "error": f"Cannot return an order with status '{order_status}'"}), 400

        # Check if return already requested
        cursor.execute("""
            SELECT id, return_number, status FROM returns 
            WHERE order_id = %s AND status NOT IN ('REJECTED', 'REFUNDED')
            LIMIT 1
        """, (order["id"],))
        existing = cursor.fetchone()
        if existing:
            return jsonify({
                "success": False, 
                "error": f"A return request ({existing['return_number']}) is already open for this order with status '{existing['status']}'."
            }), 409

        return_number = generate_return_number()
        refund_amount = float(order["total_amount"])

        # Insert return record
        cursor.execute("""
            INSERT INTO returns (
                order_id, user_id, return_number, reason, refund_amount, 
                refund_method, customer_notes, status, resolution_action
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'REQUESTED', 'REFUND')
        """, (
            order["id"], user_id, return_number, reason, 
            refund_amount, refund_method, customer_notes
        ))

        # Update order status
        cursor.execute("UPDATE orders SET status = 'RETURN_REQUESTED' WHERE id = %s", (order["id"],))

        # Add customer notification
        cursor.execute("""
            INSERT INTO notifications (user_id, title, message, type)
            VALUES (%s, %s, %s, 'RETURN_UPDATE')
        """, (
            user_id,
            f"Return Request Received: {return_number}",
            f"Your return request for Order #{order['order_number']} has been received and is under review by our operations team."
        ))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Return request submitted successfully. Our team will review your request within 24 hours.",
            "return_number": return_number,
            "order_number": order["order_number"],
            "refund_amount": refund_amount,
            "status": "REQUESTED"
        }), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Error creating return request: {e}")
        return jsonify({"success": False, "error": "Failed to submit return request"}), 500
    finally:
        cursor.close()
        conn.close()

@returns_bp.route("/returns/my-returns", methods=["GET"])
@jwt_required()
def customer_get_returns():
    """Retrieve all return requests for authenticated customer."""
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("""
            SELECT 
                r.id, r.return_number, r.order_id, r.reason, r.refund_amount,
                r.refund_method, r.customer_notes, r.status, r.resolution_action,
                r.admin_notes, r.processed_at, r.created_at,
                o.order_number, o.total_amount as order_total,
                (
                    SELECT pi.image_url FROM order_items oi
                    LEFT JOIN product_images pi ON oi.product_id = pi.product_id
                    WHERE oi.order_id = o.id
                    ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
                ) as order_image,
                (SELECT COUNT(*) FROM order_items oi2 WHERE oi2.order_id = o.id) as items_count
            FROM returns r
            LEFT JOIN orders o ON r.order_id = o.id
            WHERE r.user_id = %s
            ORDER BY r.created_at DESC
        """, (user_id,))
        rows = cursor.fetchall()

        results = []
        for r in rows:
            results.append({
                "id": r["id"],
                "return_number": r["return_number"],
                "order_id": r["order_id"],
                "order_number": r["order_number"],
                "order_image": r.get("order_image") or "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=300&q=80",
                "items_count": int(r.get("items_count") or 1),
                "reason": r["reason"],
                "customer_notes": r.get("customer_notes") or "",
                "refund_amount": float(r["refund_amount"]),
                "refund_method": r["refund_method"],
                "status": r["status"],
                "resolution_action": r["resolution_action"],
                "admin_notes": r.get("admin_notes") or "",
                "processed_at": r["processed_at"].isoformat() if r.get("processed_at") else None,
                "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
            })

        return jsonify({"success": True, "returns": results}), 200
    finally:
        cursor.close()
        conn.close()

# ==========================================================
# ADMIN RETURNS & REFUNDS MODERATION API
# ==========================================================

@returns_bp.route("/admin/returns", methods=["GET"])
@admin_required
def admin_get_returns():
    """Admin: Fetch all return requests with KPI statistics and filters."""
    search = request.args.get("search", "").strip()
    status = request.args.get("status", "all").upper()
    page = max(1, request.args.get("page", 1, type=int))
    limit = min(50, max(5, request.args.get("limit", 15, type=int)))
    offset = (page - 1) * limit

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # 1. Statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_returns,
                SUM(CASE WHEN status = 'REQUESTED' THEN 1 ELSE 0 END) as pending_requests,
                SUM(CASE WHEN status IN ('APPROVED', 'ITEM_RECEIVED') THEN 1 ELSE 0 END) as active_returns,
                SUM(CASE WHEN status = 'REFUNDED' THEN 1 ELSE 0 END) as refunded_count,
                COALESCE(SUM(CASE WHEN status = 'REFUNDED' THEN refund_amount ELSE 0 END), 0) as total_refunded_amount,
                SUM(CASE WHEN status = 'REJECTED' THEN 1 ELSE 0 END) as rejected_count
            FROM returns
        """)
        stats_row = cursor.fetchone() or {}
        stats = {
            "total_returns": int(stats_row.get("total_returns") or 0),
            "pending_requests": int(stats_row.get("pending_requests") or 0),
            "active_returns": int(stats_row.get("active_returns") or 0),
            "refunded_count": int(stats_row.get("refunded_count") or 0),
            "total_refunded_amount": round(float(stats_row.get("total_refunded_amount") or 0.0), 2),
            "rejected_count": int(stats_row.get("rejected_count") or 0)
        }

        # 2. Filter conditions
        conditions = []
        params = []

        if search:
            conditions.append("(r.return_number LIKE %s OR o.order_number LIKE %s OR u.name LIKE %s OR u.email LIKE %s OR r.reason LIKE %s)")
            wildcard = f"%{search}%"
            params.extend([wildcard, wildcard, wildcard, wildcard, wildcard])

        if status != "ALL":
            conditions.append("r.status = %s")
            params.append(status)

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        # Count total matching
        count_sql = f"""
            SELECT COUNT(*) as count 
            FROM returns r
            LEFT JOIN orders o ON r.order_id = o.id
            LEFT JOIN users u ON r.user_id = u.id
            {where_clause}
        """
        cursor.execute(count_sql, tuple(params))
        total_matching = cursor.fetchone()["count"]

        # Fetch matching
        fetch_sql = f"""
            SELECT 
                r.id, r.return_number, r.order_id, r.user_id, r.reason,
                r.refund_amount, r.refund_method, r.customer_notes, r.status,
                r.resolution_action, r.admin_notes, r.processed_at, r.created_at,
                o.order_number, o.status as order_status, o.total_amount as order_total,
                o.payment_method, o.payment_status,
                u.name as customer_name, u.email as customer_email, u.phone as customer_phone,
                (
                    SELECT pi.image_url FROM order_items oi
                    LEFT JOIN product_images pi ON oi.product_id = pi.product_id
                    WHERE oi.order_id = o.id
                    ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
                ) as order_image,
                (SELECT COUNT(*) FROM order_items oi2 WHERE oi2.order_id = o.id) as items_count
            FROM returns r
            LEFT JOIN orders o ON r.order_id = o.id
            LEFT JOIN users u ON r.user_id = u.id
            {where_clause}
            ORDER BY r.created_at DESC, r.id DESC
            LIMIT %s OFFSET %s
        """
        fetch_params = params + [limit, offset]
        cursor.execute(fetch_sql, tuple(fetch_params))
        rows = cursor.fetchall()

        returns_list = []
        for r in rows:
            returns_list.append({
                "id": r["id"],
                "return_number": r["return_number"],
                "order_id": r["order_id"],
                "order_number": r["order_number"],
                "order_status": r.get("order_status") or "DELIVERED",
                "order_total": float(r["order_total"] or 0),
                "order_image": r.get("order_image") or "",
                "items_count": int(r.get("items_count") or 1),
                "payment_method": r.get("payment_method") or "cod",
                "payment_status": r.get("payment_status") or "PAID",
                "customer_name": r.get("customer_name") or "Valued Customer",
                "customer_email": r.get("customer_email") or "",
                "customer_phone": r.get("customer_phone") or "",
                "reason": r["reason"],
                "customer_notes": r.get("customer_notes") or "",
                "refund_amount": float(r["refund_amount"] or 0),
                "refund_method": r["refund_method"] or "ORIGINAL_PAYMENT",
                "status": r["status"],
                "resolution_action": r.get("resolution_action") or "REFUND",
                "admin_notes": r.get("admin_notes") or "",
                "processed_at": r["processed_at"].isoformat() if r.get("processed_at") else None,
                "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
            })

        total_pages = max(1, (total_matching + limit - 1) // limit)

        return jsonify({
            "success": True,
            "returns": returns_list,
            "total": total_matching,
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
            "stats": stats
        }), 200
    except Exception as e:
        logging.error(f"Error fetching admin returns: {e}")
        return jsonify({"success": False, "error": "Failed to fetch returns"}), 500
    finally:
        cursor.close()
        conn.close()

@returns_bp.route("/admin/returns/<int:return_id>/status", methods=["PATCH"])
@admin_required
def admin_update_return_status(return_id):
    """Admin updates return status (APPROVED, ITEM_RECEIVED, REFUNDED, REJECTED)."""
    data = request.get_json(silent=True) or {}
    new_status = (data.get("status") or "").strip().upper()
    admin_notes = (data.get("admin_notes") or "").strip()
    refund_amount = data.get("refund_amount")
    restock_inventory = data.get("restock_inventory", True)

    valid_statuses = ("APPROVED", "ITEM_RECEIVED", "REFUNDED", "REJECTED")
    if new_status not in valid_statuses:
        return jsonify({
            "success": False, 
            "error": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        }), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("""
            SELECT r.*, o.order_number, o.id as order_db_id, o.user_id as order_user_id, o.total_amount
            FROM returns r
            LEFT JOIN orders o ON r.order_id = o.id
            WHERE r.id = %s
        """, (return_id,))
        ret = cursor.fetchone()
        if not ret:
            return jsonify({"success": False, "error": "Return record not found"}), 404

        order_id = ret["order_db_id"]
        user_id = ret["order_user_id"]
        order_num = ret["order_number"]
        amount = float(refund_amount) if refund_amount is not None else float(ret["refund_amount"])

        now = datetime.utcnow()

        if new_status == "APPROVED":
            # Update return status and notes
            cursor.execute("""
                UPDATE returns 
                SET status = 'APPROVED', admin_notes = %s, updated_at = %s 
                WHERE id = %s
            """, (admin_notes or ret["admin_notes"], now, return_id))
            # Update order
            cursor.execute("UPDATE orders SET status = 'RETURN_APPROVED' WHERE id = %s", (order_id,))
            # Notification
            cursor.execute("""
                INSERT INTO notifications (user_id, title, message, type)
                VALUES (%s, %s, %s, 'RETURN_UPDATE')
            """, (
                user_id,
                f"Return Authorized: {ret['return_number']}",
                f"Your return request for Order #{order_num} has been authorized. {admin_notes if admin_notes else 'Please prepare package for return shipping.'}"
            ))

        elif new_status == "ITEM_RECEIVED":
            cursor.execute("""
                UPDATE returns 
                SET status = 'ITEM_RECEIVED', admin_notes = %s, updated_at = %s 
                WHERE id = %s
            """, (admin_notes or ret["admin_notes"], now, return_id))
            cursor.execute("UPDATE orders SET status = 'RETURN_RECEIVED' WHERE id = %s", (order_id,))
            cursor.execute("""
                INSERT INTO notifications (user_id, title, message, type)
                VALUES (%s, %s, %s, 'RETURN_UPDATE')
            """, (
                user_id,
                f"Package Received: {ret['return_number']}",
                f"Our warehouse has safely received your returned package for Order #{order_num}. Quality verification and refund processing are underway."
            ))

        elif new_status == "REFUNDED":
            # 1. Update return
            cursor.execute("""
                UPDATE returns 
                SET status = 'REFUNDED', refund_amount = %s, admin_notes = %s, 
                    processed_at = %s, updated_at = %s 
                WHERE id = %s
            """, (amount, admin_notes or ret["admin_notes"], now, now, return_id))

            # 2. Update order
            cursor.execute("""
                UPDATE orders 
                SET status = 'REFUNDED', payment_status = 'REFUNDED' 
                WHERE id = %s
            """, (order_id,))

            # 3. Restock inventory if requested
            if restock_inventory:
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
                            VALUES (%s, 'RETURN_RESTOCK', %s, %s, %s)
                        """, (p_id, qty, rem_stock, f"Return {ret['return_number']} processed"))

            # 4. Notification
            cursor.execute("""
                INSERT INTO notifications (user_id, title, message, type)
                VALUES (%s, %s, %s, 'REFUND_ISSUED')
            """, (
                user_id,
                f"Refund Processed: ${amount:.2f}",
                f"A refund of ${amount:.2f} has been completed for Order #{order_num} ({ret['return_number']}). Funds will reflect per your financial provider's schedule."
            ))

        elif new_status == "REJECTED":
            cursor.execute("""
                UPDATE returns 
                SET status = 'REJECTED', resolution_action = 'REJECTED', 
                    admin_notes = %s, processed_at = %s, updated_at = %s 
                WHERE id = %s
            """, (admin_notes or ret["admin_notes"], now, now, return_id))
            # Restore order to DELIVERED
            cursor.execute("UPDATE orders SET status = 'DELIVERED' WHERE id = %s", (order_id,))
            # Notification
            cursor.execute("""
                INSERT INTO notifications (user_id, title, message, type)
                VALUES (%s, %s, %s, 'RETURN_REJECTED')
            """, (
                user_id,
                f"Return Request Rejected: {ret['return_number']}",
                f"Your return request for Order #{order_num} could not be approved. Reason: {admin_notes if admin_notes else 'Does not meet return criteria'}. Please contact support for questions."
            ))

        conn.commit()

        return jsonify({
            "success": True,
            "message": f"Return {ret['return_number']} updated to {new_status}.",
            "status": new_status,
            "refund_amount": amount,
            "processed_at": now.isoformat()
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error updating return status: {e}")
        return jsonify({"success": False, "error": "Failed to update return status"}), 500
    finally:
        cursor.close()
        conn.close()

@returns_bp.route("/admin/returns/<int:return_id>/notes", methods=["POST"])
@admin_required
def admin_add_return_notes(return_id):
    """Admin adds internal comments / notes to a return record."""
    data = request.get_json(silent=True) or {}
    notes = (data.get("notes") or "").strip()

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("SELECT id FROM returns WHERE id = %s", (return_id,))
        if not cursor.fetchone():
            return jsonify({"success": False, "error": "Return record not found"}), 404

        cursor.execute("UPDATE returns SET admin_notes = %s WHERE id = %s", (notes, return_id))
        conn.commit()

        return jsonify({"success": True, "message": "Notes saved successfully", "admin_notes": notes}), 200
    finally:
        cursor.close()
        conn.close()
