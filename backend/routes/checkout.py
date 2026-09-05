import logging
import json
import uuid
import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, get_dict_cursor, is_mysql

checkout_bp = Blueprint('checkout', __name__, url_prefix='/checkout')

def seed_initial_coupons(cursor, conn):
    """Seed standard promotional coupons if coupons table is empty."""
    cursor.execute("SELECT COUNT(*) as count FROM coupons")
    res = cursor.fetchone()
    count = res["count"] if isinstance(res, dict) else res[0]
    if count == 0:
        coupons = [
            ("SAVE10", "Get 10% off on orders above $30 (Max $50 savings)", "percentage", 10.00, 30.00, 50.00, 500),
            ("WELCOME10", "Welcome offer: 10% off orders of $20 or more", "percentage", 10.00, 20.00, 30.00, 1000),
            ("APEX20", "VIP savings: 20% off orders above $75 (Max $100)", "percentage", 20.00, 75.00, 100.00, 250),
            ("FREESHIP", "Standard shipping discount ($9.99 off) on orders $25+", "fixed", 9.99, 25.00, 9.99, 500)
        ]
        for c in coupons:
            cursor.execute("""
                INSERT INTO coupons (code, description, discount_type, discount_value, min_order_value, max_discount_amount, usage_limit, times_used, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 0, TRUE)
            """, c)
        conn.commit()

def calculate_coupon_discount(cursor, coupon_code, subtotal):
    """Validate a coupon code and calculate the discount."""
    if not coupon_code:
        return 0.0, None, None

    code = coupon_code.strip().upper()
    cursor.execute("SELECT * FROM coupons WHERE UPPER(code) = %s AND is_active = TRUE", (code,))
    coupon = cursor.fetchone()

    if not coupon:
        return 0.0, None, "Invalid or inactive promotional coupon code"

    # Check expiration if set
    now = datetime.datetime.utcnow()
    if coupon.get("expiry_date") and coupon["expiry_date"] < now:
        return 0.0, None, "Coupon code has expired"

    # Check usage limit
    usage_limit = coupon.get("usage_limit", 100)
    times_used = coupon.get("times_used", 0)
    if times_used >= usage_limit:
        return 0.0, None, "Coupon code usage limit reached"

    # Check minimum order value
    min_val = float(coupon.get("min_order_value") or 0.0)
    if subtotal < min_val:
        return 0.0, None, f"Coupon requires a minimum order subtotal of ${min_val:.2f}"

    disc_val = float(coupon.get("discount_value") or 0.0)
    disc_type = str(coupon.get("discount_type", "percentage")).lower()
    max_disc = float(coupon["max_discount_amount"]) if coupon.get("max_discount_amount") else None

    if disc_type == "percentage":
        discount = (subtotal * disc_val) / 100.0
    else:
        discount = disc_val

    if max_disc is not None and discount > max_disc:
        discount = max_disc

    discount = round(discount, 2)
    return discount, coupon, None

# ==========================================================
# CHECKOUT ENDPOINTS
# ==========================================================

@checkout_bp.route("/validate-coupon", methods=["POST"])
@jwt_required()
def validate_coupon():
    data = request.get_json(silent=True) or {}
    code = data.get("code")
    subtotal = float(data.get("subtotal") or 0.0)

    if not code:
        return jsonify({"success": False, "error": "Coupon code is required"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        seed_initial_coupons(cursor, conn)
        discount, coupon, err = calculate_coupon_discount(cursor, code, subtotal)
        if err:
            return jsonify({"success": False, "valid": False, "error": err}), 400

        return jsonify({
            "success": True,
            "valid": True,
            "code": coupon["code"],
            "discount_type": coupon["discount_type"],
            "discount_value": float(coupon["discount_value"]),
            "discount_amount": discount,
            "message": f"Coupon {coupon['code']} applied successfully!"
        }), 200
    finally:
        cursor.close()
        conn.close()

@checkout_bp.route("/preview", methods=["POST"])
@jwt_required()
def checkout_preview():
    """Recalculate entire cart server-side and validate stocks."""
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user identity"}), 401

    data = request.get_json(silent=True) or {}
    coupon_code = data.get("coupon_code")

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        seed_initial_coupons(cursor, conn)

        # Get user cart
        cursor.execute("SELECT id FROM cart WHERE user_id = %s", (user_id,))
        cart_row = cursor.fetchone()
        if not cart_row:
            return jsonify({"success": False, "error": "Shopping cart is empty"}), 400

        cart_id = cart_row["id"]
        cursor.execute("""
            SELECT ci.id as item_id, ci.quantity, ci.product_id,
                   p.name, p.price, p.discount_price, p.stock, p.is_active
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            WHERE ci.cart_id = %s
        """, (cart_id,))
        items = cursor.fetchall()

        if not items:
            return jsonify({"success": False, "error": "Shopping cart has no items"}), 400

        subtotal = 0.0
        stock_warnings = []
        preview_items = []

        for item in items:
            qty = int(item["quantity"])
            stock = int(item["stock"])
            is_active = bool(item["is_active"])

            price = float(item["price"])
            disc_price = float(item["discount_price"]) if item.get("discount_price") else None
            unit_price = disc_price if (disc_price and 0 < disc_price < price) else price
            line_total = round(unit_price * qty, 2)
            subtotal += line_total

            if not is_active:
                stock_warnings.append(f"'{item['name']}' is no longer available.")
            elif qty > stock:
                stock_warnings.append(f"'{item['name']}' only has {stock} items available (requested {qty}).")

            preview_items.append({
                "product_id": item["product_id"],
                "name": item["name"],
                "unit_price": unit_price,
                "quantity": qty,
                "total_price": line_total,
                "in_stock": is_active and qty <= stock
            })

        subtotal = round(subtotal, 2)
        shipping_fee = 0.0 if subtotal >= 49.00 else 9.99
        discount_amount = 0.0
        applied_coupon = None

        if coupon_code:
            disc, cp, err = calculate_coupon_discount(cursor, coupon_code, subtotal)
            if not err:
                discount_amount = disc
                applied_coupon = cp["code"]

        total = round(max(0.0, subtotal - discount_amount) + shipping_fee, 2)

        return jsonify({
            "success": True,
            "preview": {
                "items": preview_items,
                "total_items": sum(i["quantity"] for i in preview_items),
                "subtotal": subtotal,
                "shipping_fee": shipping_fee,
                "discount_amount": discount_amount,
                "coupon_code": applied_coupon,
                "total_amount": total,
                "can_checkout": len(stock_warnings) == 0,
                "stock_warnings": stock_warnings
            }
        }), 200
    finally:
        cursor.close()
        conn.close()

@checkout_bp.route("/place-order", methods=["POST"])
@jwt_required()
def place_order():
    """Place customer order with strict atomic server-side recalculation and inventory locking."""
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user identity"}), 401

    data = request.get_json(silent=True) or {}
    address_id = data.get("address_id")
    address_data = data.get("address_data")
    payment_method = (data.get("payment_method") or "COD").strip().upper()
    coupon_code = data.get("coupon_code")

    if payment_method not in ["COD", "CARD", "UPI", "MOCK_CARD"]:
        payment_method = "COD"
    if payment_method == "MOCK_CARD":
        payment_method = "CARD"

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        seed_initial_coupons(cursor, conn)

        # 1. Fetch and validate delivery address
        final_address_id = None
        shipping_snapshot = {}

        if address_id and str(address_id) != "new":
            cursor.execute("SELECT * FROM addresses WHERE id = %s AND user_id = %s", (address_id, user_id))
            addr = cursor.fetchone()
            if not addr:
                return jsonify({"success": False, "error": "Selected address not found or unauthorized"}), 404
            final_address_id = addr["id"]
            shipping_snapshot = {
                "full_name": addr["full_name"],
                "phone": addr["phone"],
                "street_address": addr["street_address"],
                "city": addr["city"],
                "state": addr.get("state", ""),
                "postal_code": addr["postal_code"],
                "country": addr.get("country", "USA")
            }
        elif address_data:
            full_name = address_data.get("full_name", "").strip()
            phone = address_data.get("phone", "").strip()
            street = address_data.get("street_address", "").strip()
            city = address_data.get("city", "").strip()
            state = address_data.get("state", "").strip()
            postal = address_data.get("postal_code", "").strip()
            country = address_data.get("country", "USA").strip() or "USA"

            if not full_name or not phone or not street or not city or not postal:
                return jsonify({"success": False, "error": "All shipping address fields are required"}), 400

            cursor.execute("""
                INSERT INTO addresses (user_id, full_name, phone, street_address, city, state, postal_code, country, is_default)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, FALSE)
            """, (user_id, full_name, phone, street, city, state, postal, country))

            final_address_id = cursor.lastrowid if is_mysql(conn) else None
            if not final_address_id:
                cursor.execute("SELECT id FROM addresses WHERE user_id = %s ORDER BY id DESC LIMIT 1", (user_id,))
                final_address_id = cursor.fetchone()["id"]

            shipping_snapshot = {
                "full_name": full_name,
                "phone": phone,
                "street_address": street,
                "city": city,
                "state": state,
                "postal_code": postal,
                "country": country
            }
        else:
            return jsonify({"success": False, "error": "Shipping address is required"}), 400

        # 2. Fetch customer cart items
        cursor.execute("SELECT id FROM cart WHERE user_id = %s", (user_id,))
        cart_row = cursor.fetchone()
        if not cart_row:
            return jsonify({"success": False, "error": "Your shopping cart is empty"}), 400

        cart_id = cart_row["id"]
        cursor.execute("""
            SELECT ci.id as item_id, ci.quantity, ci.product_id,
                   p.name, p.price, p.discount_price, p.stock, p.is_active
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            WHERE ci.cart_id = %s
        """, (cart_id,))
        cart_items = cursor.fetchall()

        if not cart_items:
            return jsonify({"success": False, "error": "Your shopping cart contains no items"}), 400

        # 3. Strictly validate stock and compute totals on the server
        subtotal = 0.0
        validated_items = []

        for item in cart_items:
            qty = int(item["quantity"])
            stock = int(item["stock"])
            is_active = bool(item["is_active"])

            if not is_active:
                conn.rollback()
                return jsonify({
                    "success": False, 
                    "error": f"Product '{item['name']}' is no longer available. Please remove it from your cart."
                }), 400

            if qty > stock:
                conn.rollback()
                return jsonify({
                    "success": False, 
                    "error": f"Insufficient stock for '{item['name']}'. Only {stock} units available."
                }), 400

            price = float(item["price"])
            disc_price = float(item["discount_price"]) if item.get("discount_price") else None
            unit_price = disc_price if (disc_price and 0 < disc_price < price) else price
            line_total = round(unit_price * qty, 2)
            subtotal += line_total

            validated_items.append({
                "product_id": item["product_id"],
                "name": item["name"],
                "unit_price": unit_price,
                "quantity": qty,
                "line_total": line_total,
                "new_stock": stock - qty
            })

        subtotal = round(subtotal, 2)
        shipping_fee = 0.0 if subtotal >= 49.00 else 9.99

        # 4. Coupon discount
        discount_amount = 0.0
        coupon_obj = None
        if coupon_code:
            disc, coupon_obj, err = calculate_coupon_discount(cursor, coupon_code, subtotal)
            if not err:
                discount_amount = disc

        total_amount = round(max(0.0, subtotal - discount_amount) + shipping_fee, 2)

        # 5. Generate unique order number
        today_str = datetime.datetime.utcnow().strftime("%Y%m%d")
        rand_suffix = uuid.uuid4().hex[:6].upper()
        order_number = f"APX-{today_str}-{rand_suffix}"

        # 6. Determine initial payment status
        payment_status = "PAID" if payment_method in ["CARD", "UPI"] else "PENDING"
        order_status = "PROCESSING"

        # 7. Insert Order
        snapshot_json = json.dumps(shipping_snapshot)
        cursor.execute("""
            INSERT INTO orders (
                order_number, user_id, address_id, shipping_address_snapshot,
                status, subtotal, discount, shipping_fee, total_amount,
                payment_method, payment_status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            order_number, user_id, final_address_id, snapshot_json,
            order_status, subtotal, discount_amount, shipping_fee, total_amount,
            payment_method, payment_status
        ))

        order_id = cursor.lastrowid if is_mysql(conn) else None
        if not order_id:
            cursor.execute("SELECT id FROM orders WHERE order_number = %s", (order_number,))
            order_id = cursor.fetchone()["id"]

        # 8. Insert Order Items & Deduct Inventory
        for vi in validated_items:
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, price, quantity, total)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (order_id, vi["product_id"], vi["name"], vi["unit_price"], vi["quantity"], vi["line_total"]))

            # Decrement product stock
            cursor.execute("UPDATE products SET stock = %s WHERE id = %s", (vi["new_stock"], vi["product_id"]))

            # Log inventory change
            cursor.execute("""
                INSERT INTO inventory_logs (product_id, change_type, quantity_changed, remaining_stock, notes)
                VALUES (%s, 'ORDER_SALE', %s, %s, %s)
            """, (vi["product_id"], -vi["quantity"], vi["new_stock"], f"Order #{order_number}"))

        # 9. Insert Payment Record
        txn_id = f"TXN-{uuid.uuid4().hex[:12].upper()}"
        cursor.execute("""
            INSERT INTO payments (order_id, user_id, payment_method, transaction_id, amount, status)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (order_id, user_id, payment_method, txn_id, total_amount, "COMPLETED" if payment_status == "PAID" else "PENDING"))

        # 10. Record Coupon Usage
        if coupon_obj:
            cursor.execute("""
                INSERT INTO coupon_usage (coupon_id, user_id, order_id, discount_amount)
                VALUES (%s, %s, %s, %s)
            """, (coupon_obj["id"], user_id, order_id, discount_amount))
            cursor.execute("UPDATE coupons SET times_used = times_used + 1 WHERE id = %s", (coupon_obj["id"],))

        # 11. Empty Customer's Cart
        cursor.execute("DELETE FROM cart_items WHERE cart_id = %s", (cart_id,))

        # 12. Create notification for user
        cursor.execute("""
            INSERT INTO notifications (user_id, title, message, type)
            VALUES (%s, %s, %s, 'ORDER_PLACED')
        """, (
            user_id,
            f"Order Confirmed: #{order_number}",
            f"Your order #{order_number} for ${total_amount:.2f} has been placed successfully."
        ))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Order placed successfully!",
            "order": {
                "id": order_id,
                "order_number": order_number,
                "subtotal": subtotal,
                "shipping_fee": shipping_fee,
                "discount": discount_amount,
                "total_amount": total_amount,
                "payment_method": payment_method,
                "payment_status": payment_status,
                "status": order_status,
                "created_at": datetime.datetime.utcnow().isoformat()
            }
        }), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Order placement failure: {e}", exc_info=True)
        return jsonify({"success": False, "error": f"Failed to place order: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()
