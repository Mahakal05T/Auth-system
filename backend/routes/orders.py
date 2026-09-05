import logging
import json
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, get_dict_cursor

orders_bp = Blueprint('orders', __name__, url_prefix='/orders')

def format_order_item(r):
    """Format single order line item."""
    return {
        "id": r["id"],
        "product_id": r["product_id"],
        "product_name": r["product_name"],
        "price": float(r["price"]),
        "quantity": int(r["quantity"]),
        "total": float(r["total"]),
        "image": r.get("image") or "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=300&q=80"
    }

# ==========================================================
# CUSTOMER ORDERS ENDPOINTS
# ==========================================================

@orders_bp.route("", methods=["GET"])
@jwt_required()
def get_customer_orders():
    """Retrieve all orders placed by authenticated customer."""
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user identity"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cursor.execute("""
            SELECT o.id, o.order_number, o.status, o.subtotal, o.discount, 
                   o.shipping_fee, o.total_amount, o.payment_method, o.payment_status,
                   o.created_at, o.updated_at,
                   (
                       SELECT COUNT(*) FROM order_items oi WHERE oi.order_id = o.id
                   ) as total_items_count,
                   (
                       SELECT pi.image_url FROM order_items oi2
                       LEFT JOIN product_images pi ON oi2.product_id = pi.product_id
                       WHERE oi2.order_id = o.id
                       ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
                   ) as primary_image
            FROM orders o
            WHERE o.user_id = %s
            ORDER BY o.created_at DESC
        """, (user_id,))
        order_rows = cursor.fetchall()

        orders = []
        for o in order_rows:
            # Fetch item names snippet for preview
            cursor.execute("""
                SELECT product_name, quantity FROM order_items 
                WHERE order_id = %s LIMIT 3
            """, (o["id"],))
            items_preview = cursor.fetchall()

            status = o["status"].upper()
            can_cancel = status in ["PLACED", "PROCESSING", "PENDING"]

            orders.append({
                "id": o["id"],
                "order_number": o["order_number"],
                "status": status,
                "can_cancel": can_cancel,
                "subtotal": float(o["subtotal"]),
                "discount": float(o["discount"] or 0.0),
                "shipping_fee": float(o["shipping_fee"] or 0.0),
                "total_amount": float(o["total_amount"]),
                "payment_method": o["payment_method"],
                "payment_status": o["payment_status"],
                "created_at": str(o["created_at"]) if o.get("created_at") else None,
                "total_items_count": int(o.get("total_items_count") or 0),
                "primary_image": o.get("primary_image") or "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=300&q=80",
                "items_preview": [f"{it['quantity']}x {it['product_name']}" for it in items_preview]
            })

        return jsonify({"success": True, "orders": orders}), 200
    except Exception as e:
        logging.error(f"Error fetching orders: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve orders"}), 500
    finally:
        cursor.close()
        conn.close()

@orders_bp.route("/<identifier>", methods=["GET"])
@jwt_required()
def get_order_details(identifier):
    """Retrieve full details of a customer's specific order by ID or order number."""
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user identity"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # IDOR check: only fetch if order belongs to authenticated user
        cursor.execute("""
            SELECT * FROM orders 
            WHERE (id = %s OR order_number = %s) AND user_id = %s
            LIMIT 1
        """, (identifier, identifier, user_id))
        order = cursor.fetchone()

        if not order:
            return jsonify({"success": False, "error": "Order not found or unauthorized"}), 404

        order_id = order["id"]

        # Fetch line items with images
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
        items = [format_order_item(r) for r in cursor.fetchall()]

        # Parse shipping address snapshot
        shipping_address = {}
        if order.get("shipping_address_snapshot"):
            try:
                shipping_address = json.loads(order["shipping_address_snapshot"])
            except Exception:
                shipping_address = {}

        if not shipping_address and order.get("address_id"):
            cursor.execute("SELECT * FROM addresses WHERE id = %s", (order["address_id"],))
            addr = cursor.fetchone()
            if addr:
                shipping_address = {
                    "full_name": addr["full_name"],
                    "phone": addr["phone"],
                    "street_address": addr["street_address"],
                    "city": addr["city"],
                    "state": addr.get("state", ""),
                    "postal_code": addr["postal_code"],
                    "country": addr.get("country", "USA")
                }

        # Fetch payment record
        cursor.execute("SELECT * FROM payments WHERE order_id = %s ORDER BY id DESC LIMIT 1", (order_id,))
        payment = cursor.fetchone()

        status = order["status"].upper()
        can_cancel = status in ["PLACED", "PROCESSING", "PENDING"]

        return jsonify({
            "success": True,
            "order": {
                "id": order["id"],
                "order_number": order["order_number"],
                "status": status,
                "can_cancel": can_cancel,
                "subtotal": float(order["subtotal"]),
                "discount": float(order["discount"] or 0.0),
                "shipping_fee": float(order["shipping_fee"] or 0.0),
                "total_amount": float(order["total_amount"]),
                "payment_method": order["payment_method"],
                "payment_status": order["payment_status"],
                "shipping_address": shipping_address,
                "created_at": str(order["created_at"]) if order.get("created_at") else None,
                "updated_at": str(order["updated_at"]) if order.get("updated_at") else None,
                "items": items,
                "payment": {
                    "transaction_id": payment["transaction_id"] if payment else None,
                    "status": payment["status"] if payment else order["payment_status"],
                    "amount": float(payment["amount"]) if payment else float(order["total_amount"])
                } if payment else None
            }
        }), 200
    except Exception as e:
        logging.error(f"Error fetching order detail: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve order details"}), 500
    finally:
        cursor.close()
        conn.close()

@orders_bp.route("/<identifier>/cancel", methods=["POST"])
@jwt_required()
def cancel_customer_order(identifier):
    """Customer self-service cancellation with automatic inventory restock."""
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user identity"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # IDOR check
        cursor.execute("""
            SELECT id, order_number, status, payment_status, total_amount
            FROM orders 
            WHERE (id = %s OR order_number = %s) AND user_id = %s
            LIMIT 1
        """, (identifier, identifier, user_id))
        order = cursor.fetchone()

        if not order:
            return jsonify({"success": False, "error": "Order not found or unauthorized"}), 404

        status = order["status"].upper()
        if status in ["SHIPPED", "DELIVERED"]:
            return jsonify({
                "success": False, 
                "error": f"Order #{order['order_number']} has already been {status.lower()} and cannot be cancelled directly. Please initiate a return instead."
            }), 400

        if status == "CANCELLED":
            return jsonify({"success": False, "error": "This order has already been cancelled"}), 400

        order_id = order["id"]

        # 1. Update order status
        new_payment_status = "REFUNDED" if order["payment_status"] == "PAID" else "CANCELLED"
        cursor.execute("""
            UPDATE orders 
            SET status = 'CANCELLED', payment_status = %s 
            WHERE id = %s
        """, (new_payment_status, order_id))

        # 2. Fetch order items to restore inventory
        cursor.execute("SELECT product_id, quantity FROM order_items WHERE order_id = %s", (order_id,))
        items = cursor.fetchall()

        for it in items:
            p_id = it["product_id"]
            qty = int(it["quantity"])
            if p_id:
                # Restock product
                cursor.execute("UPDATE products SET stock = stock + %s WHERE id = %s", (qty, p_id))

                # Query new stock
                cursor.execute("SELECT stock FROM products WHERE id = %s", (p_id,))
                prod = cursor.fetchone()
                rem_stock = prod["stock"] if prod else 0

                # Log restock
                cursor.execute("""
                    INSERT INTO inventory_logs (product_id, change_type, quantity_changed, remaining_stock, notes)
                    VALUES (%s, 'ORDER_CANCELLED_RESTOCK', %s, %s, %s)
                """, (p_id, qty, rem_stock, f"Order #{order['order_number']} cancelled"))

        # 3. Update payment status if exists
        cursor.execute("""
            UPDATE payments 
            SET status = %s 
            WHERE order_id = %s
        """, (new_payment_status, order_id))

        # 4. Create customer notification
        cursor.execute("""
            INSERT INTO notifications (user_id, title, message, type)
            VALUES (%s, %s, %s, 'ORDER_CANCELLED')
        """, (
            user_id,
            f"Order Cancelled: #{order['order_number']}",
            f"Your order #{order['order_number']} was successfully cancelled. {('Refund has been processed to your original payment method.') if new_payment_status == 'REFUNDED' else ''}"
        ))

        conn.commit()

        return jsonify({
            "success": True,
            "message": f"Order #{order['order_number']} has been cancelled successfully and items returned to stock.",
            "order_number": order["order_number"],
            "status": "CANCELLED",
            "payment_status": new_payment_status
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error cancelling order: {e}")
        return jsonify({"success": False, "error": "Failed to cancel order"}), 500
    finally:
        cursor.close()
        conn.close()

@orders_bp.route("/<identifier>/track", methods=["GET"])
@jwt_required()
def track_customer_order(identifier):
    """Retrieve detailed shipment and delivery timeline for an order."""
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    role = identity.get("role")

    if not user_id:
        return jsonify({"success": False, "error": "Invalid user identity"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # IDOR check: customer can only track their own order unless admin
        if role == "admin":
            cursor.execute("""
                SELECT * FROM orders WHERE id = %s OR order_number = %s LIMIT 1
            """, (identifier, identifier))
        else:
            cursor.execute("""
                SELECT * FROM orders WHERE (id = %s OR order_number = %s) AND user_id = %s LIMIT 1
            """, (identifier, identifier, user_id))

        order = cursor.fetchone()
        if not order:
            return jsonify({"success": False, "error": "Order not found or unauthorized"}), 404

        order_id = order["id"]
        status = order["status"].upper()

        # Parse shipping address snapshot
        shipping_address = {}
        if order.get("shipping_address_snapshot"):
            try:
                shipping_address = json.loads(order["shipping_address_snapshot"])
            except Exception:
                shipping_address = {}

        if not shipping_address and order.get("address_id"):
            cursor.execute("SELECT * FROM addresses WHERE id = %s", (order["address_id"],))
            addr = cursor.fetchone()
            if addr:
                shipping_address = {
                    "full_name": addr["full_name"],
                    "phone": addr["phone"],
                    "street_address": addr["street_address"],
                    "city": addr["city"],
                    "state": addr.get("state", ""),
                    "postal_code": addr["postal_code"],
                    "country": addr.get("country", "USA")
                }

        # Fetch line items
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
        items = [format_order_item(r) for r in cursor.fetchall()]

        # Generate timeline steps
        created_dt = order.get("created_at")
        created_str = str(created_dt)[:16] if created_dt else "Recent"

        if status == "CANCELLED":
            timeline = [
                {"title": "Order Placed", "description": "Order submitted by customer", "time": created_str, "status": "completed"},
                {"title": "Order Cancelled", "description": "Order cancelled and items returned to stock", "time": str(order.get("updated_at"))[:16] if order.get("updated_at") else "Done", "status": "cancelled"}
            ]
        elif status == "DELIVERED":
            timeline = [
                {"title": "Order Placed", "description": "Order details and payment verified", "time": created_str, "status": "completed"},
                {"title": "Processing & Packed", "description": "Packaged at fulfillment center", "time": "Completed", "status": "completed"},
                {"title": "Shipped & In Transit", "description": "Departed sorting facility with Express Courier", "time": "Completed", "status": "completed"},
                {"title": "Out for Delivery", "description": "Courier out for final delivery", "time": "Completed", "status": "completed"},
                {"title": "Delivered", "description": "Package safely handed to recipient", "time": str(order.get("updated_at"))[:16] if order.get("updated_at") else "Done", "status": "completed"}
            ]
        elif status == "SHIPPED":
            timeline = [
                {"title": "Order Placed", "description": "Order details and payment verified", "time": created_str, "status": "completed"},
                {"title": "Processing & Packed", "description": "Packaged at fulfillment center", "time": "Completed", "status": "completed"},
                {"title": "Shipped & In Transit", "description": "Departed regional distribution hub", "time": "In Transit", "status": "current"},
                {"title": "Out for Delivery", "description": "Expected delivery soon", "time": "Pending", "status": "pending"},
                {"title": "Delivered", "description": "Final delivery confirmation", "time": "Pending", "status": "pending"}
            ]
        else:
            # PLACED / PROCESSING
            timeline = [
                {"title": "Order Placed", "description": "Order details and payment verified", "time": created_str, "status": "completed"},
                {"title": "Processing & Packed", "description": "Items being verified and packed", "time": "In Progress", "status": "current"},
                {"title": "Shipped & In Transit", "description": "Waiting for carrier pickup", "time": "Pending", "status": "pending"},
                {"title": "Out for Delivery", "description": "Local route delivery", "time": "Pending", "status": "pending"},
                {"title": "Delivered", "description": "Package arrival", "time": "Pending", "status": "pending"}
            ]

        tracking_number = f"TRK-{order['order_number']}"
        carrier = "Apex Express Courier"

        return jsonify({
            "success": True,
            "tracking": {
                "order_number": order["order_number"],
                "status": status,
                "carrier": carrier,
                "tracking_number": tracking_number,
                "created_at": str(order.get("created_at")),
                "estimated_delivery": "Within 3-5 business days",
                "timeline": timeline,
                "shipping_address": shipping_address,
                "items": items,
                "subtotal": float(order["subtotal"]),
                "shipping_fee": float(order["shipping_fee"] or 0.0),
                "discount": float(order["discount"] or 0.0),
                "total_amount": float(order["total_amount"]),
                "payment_method": order["payment_method"],
                "payment_status": order["payment_status"]
            }
        }), 200
    except Exception as e:
        logging.error(f"Error tracking order: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve order tracking information"}), 500
    finally:
        cursor.close()
        conn.close()

