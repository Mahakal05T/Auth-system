
import logging
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, get_dict_cursor, is_mysql

cart_bp = Blueprint('cart', __name__, url_prefix='/cart')

def get_or_create_user_cart(cursor, conn, user_id):
    """Retrieve or insert a customer cart."""
    cursor.execute("SELECT id FROM cart WHERE user_id = %s LIMIT 1", (user_id,))
    row = cursor.fetchone()
    if row:
        return row["id"]

    cursor.execute("INSERT INTO cart (user_id) VALUES (%s)", (user_id,))
    cart_id = cursor.lastrowid if is_mysql(conn) else None
    if not cart_id:
        cursor.execute("SELECT id FROM cart WHERE user_id = %s", (user_id,))
        r = cursor.fetchone()
        cart_id = r["id"] if r else None
    conn.commit()
    return cart_id

def calculate_cart_summary(cursor, cart_id):
    """Calculate cart items, strictly computing prices server-side."""
    cursor.execute("""
        SELECT ci.id as item_id, ci.product_id, ci.quantity,
               p.name, p.price, p.discount_price, p.stock, p.sku, p.brand, p.is_active,
               (
                   SELECT image_url FROM product_images pi 
                   WHERE pi.product_id = p.id 
                   ORDER BY pi.is_primary DESC, pi.id ASC LIMIT 1
               ) as image
        FROM cart_items ci
        JOIN products p ON ci.product_id = p.id
        WHERE ci.cart_id = %s
        ORDER BY ci.id ASC
    """, (cart_id,))
    rows = cursor.fetchall()

    items = []
    subtotal = 0.0
    total_items = 0

    for r in rows:
        price = float(r["price"]) if r.get("price") is not None else 0.0
        disc_price = float(r["discount_price"]) if r.get("discount_price") is not None else None
        
        # Determine actual unit price
        unit_price = disc_price if (disc_price is not None and 0 < disc_price < price) else price
        qty = int(r["quantity"])
        item_total = unit_price * qty
        subtotal += item_total
        total_items += qty

        stock = int(r.get("stock", 0))
        is_active = bool(r.get("is_active", True))

        items.append({
            "id": r["item_id"],
            "product_id": r["product_id"],
            "name": r["name"],
            "sku": r["sku"],
            "brand": r["brand"],
            "image": r["image"] or "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=300&q=80",
            "quantity": qty,
            "unit_price": round(unit_price, 2),
            "regular_price": round(price, 2),
            "total_price": round(item_total, 2),
            "stock": stock,
            "is_out_of_stock": (stock < qty) or (not is_active),
            "is_active": is_active
        })

    shipping_fee = 0.0 if (subtotal >= 49.0 or len(items) == 0) else 9.99
    total_amount = subtotal + shipping_fee

    return {
        "items": items,
        "total_items": total_items,
        "subtotal": round(subtotal, 2),
        "shipping_fee": round(shipping_fee, 2),
        "total": round(total_amount, 2),
        "free_shipping_threshold": 49.0,
        "amount_for_free_shipping": max(0.0, round(49.0 - subtotal, 2))
    }

# ==========================================================
# CART ENDPOINTS
# ==========================================================

@cart_bp.route("", methods=["GET"])
@jwt_required()
def get_cart():
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user token"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cart_id = get_or_create_user_cart(cursor, conn, user_id)
        summary = calculate_cart_summary(cursor, cart_id)
        summary["cart_id"] = cart_id
        return jsonify({"success": True, "cart": summary}), 200
    except Exception as e:
        logging.error(f"Error getting cart: {e}")
        return jsonify({"success": False, "error": "Failed to retrieve shopping cart"}), 500
    finally:
        cursor.close()
        conn.close()

@cart_bp.route("/items", methods=["POST"])
@jwt_required()
def add_to_cart():
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user token"}), 401

    data = request.get_json(silent=True) or {}
    product_id = data.get("product_id")
    quantity = data.get("quantity", 1)

    if not product_id:
        return jsonify({"success": False, "error": "Product ID is required"}), 400

    try:
        quantity = max(1, int(quantity))
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid quantity"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        # Check product existence & stock
        cursor.execute("SELECT id, name, stock, is_active FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()
        if not product or not product["is_active"]:
            return jsonify({"success": False, "error": "Product is not available"}), 404

        current_stock = product["stock"]
        if current_stock <= 0:
            return jsonify({"success": False, "error": "Product is currently out of stock"}), 400

        cart_id = get_or_create_user_cart(cursor, conn, user_id)

        # Check if already in cart
        cursor.execute("SELECT id, quantity FROM cart_items WHERE cart_id = %s AND product_id = %s", (cart_id, product_id))
        existing_item = cursor.fetchone()

        if existing_item:
            new_quantity = existing_item["quantity"] + quantity
            if new_quantity > current_stock:
                return jsonify({
                    "success": False, 
                    "error": f"Cannot add more than available stock ({current_stock} available, {existing_item['quantity']} already in cart)"
                }), 400

            cursor.execute("UPDATE cart_items SET quantity = %s WHERE id = %s", (new_quantity, existing_item["id"]))
        else:
            if quantity > current_stock:
                return jsonify({
                    "success": False, 
                    "error": f"Requested quantity ({quantity}) exceeds available stock ({current_stock})"
                }), 400

            cursor.execute("INSERT INTO cart_items (cart_id, product_id, quantity) VALUES (%s, %s, %s)", 
                           (cart_id, product_id, quantity))

        conn.commit()
        summary = calculate_cart_summary(cursor, cart_id)
        summary["cart_id"] = cart_id
        return jsonify({
            "success": True, 
            "message": f"Added {product['name']} to cart",
            "cart": summary
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error adding to cart: {e}")
        return jsonify({"success": False, "error": "Failed to add product to cart"}), 500
    finally:
        cursor.close()
        conn.close()

@cart_bp.route("/items/<int:item_id>", methods=["PUT"])
@jwt_required()
def update_cart_item(item_id):
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user token"}), 401

    data = request.get_json(silent=True) or {}
    try:
        new_quantity = int(data.get("quantity", 1))
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "Invalid quantity"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cart_id = get_or_create_user_cart(cursor, conn, user_id)

        # Verify item ownership
        cursor.execute("""
            SELECT ci.id, ci.product_id, p.stock, p.name 
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            WHERE ci.id = %s AND ci.cart_id = %s
        """, (item_id, cart_id))
        item = cursor.fetchone()
        if not item:
            return jsonify({"success": False, "error": "Cart item not found"}), 404

        if new_quantity <= 0:
            cursor.execute("DELETE FROM cart_items WHERE id = %s", (item_id,))
            conn.commit()
        else:
            if new_quantity > item["stock"]:
                return jsonify({
                    "success": False, 
                    "error": f"Cannot select more than available stock ({item['stock']} available)"
                }), 400

            cursor.execute("UPDATE cart_items SET quantity = %s WHERE id = %s", (new_quantity, item_id))
            conn.commit()

        summary = calculate_cart_summary(cursor, cart_id)
        summary["cart_id"] = cart_id
        return jsonify({"success": True, "cart": summary}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error updating cart item: {e}")
        return jsonify({"success": False, "error": "Failed to update item quantity"}), 500
    finally:
        cursor.close()
        conn.close()

@cart_bp.route("/items/<int:item_id>", methods=["DELETE"])
@jwt_required()
def remove_cart_item(item_id):
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user token"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cart_id = get_or_create_user_cart(cursor, conn, user_id)

        cursor.execute("DELETE FROM cart_items WHERE id = %s AND cart_id = %s", (item_id, cart_id))
        conn.commit()

        summary = calculate_cart_summary(cursor, cart_id)
        summary["cart_id"] = cart_id
        return jsonify({"success": True, "message": "Item removed from cart", "cart": summary}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error deleting cart item: {e}")
        return jsonify({"success": False, "error": "Failed to delete item from cart"}), 500
    finally:
        cursor.close()
        conn.close()

@cart_bp.route("/clear", methods=["DELETE"])
@jwt_required()
def clear_cart():
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user token"}), 401

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cart_id = get_or_create_user_cart(cursor, conn, user_id)
        cursor.execute("DELETE FROM cart_items WHERE cart_id = %s", (cart_id,))
        conn.commit()
        return jsonify({
            "success": True, 
            "message": "Cart cleared successfully",
            "cart": {
                "items": [],
                "total_items": 0,
                "subtotal": 0.0,
                "shipping_fee": 0.0,
                "total": 0.0
            }
        }), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error clearing cart: {e}")
        return jsonify({"success": False, "error": "Failed to clear cart"}), 500
    finally:
        cursor.close()
        conn.close()

@cart_bp.route("/sync", methods=["POST"])
@jwt_required()
def sync_guest_cart():
    """Merge guest cart items into customer's persistent database cart."""
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "Invalid user token"}), 401

    data = request.get_json(silent=True) or {}
    guest_items = data.get("items", [])

    if not isinstance(guest_items, list):
        return jsonify({"success": False, "error": "Items list expected"}), 400

    conn = connect_db()
    cursor = get_dict_cursor(conn)
    try:
        cart_id = get_or_create_user_cart(cursor, conn, user_id)

        for item in guest_items:
            product_id = item.get("product_id") or item.get("id")
            quantity = max(1, int(item.get("quantity", 1)))

            cursor.execute("SELECT id, stock, is_active FROM products WHERE id = %s", (product_id,))
            prod = cursor.fetchone()
            if not prod or not prod["is_active"] or prod["stock"] <= 0:
                continue

            cursor.execute("SELECT id, quantity FROM cart_items WHERE cart_id = %s AND product_id = %s", (cart_id, product_id))
            existing = cursor.fetchone()
            if existing:
                merged_qty = min(prod["stock"], existing["quantity"] + quantity)
                cursor.execute("UPDATE cart_items SET quantity = %s WHERE id = %s", (merged_qty, existing["id"]))
            else:
                initial_qty = min(prod["stock"], quantity)
                cursor.execute("INSERT INTO cart_items (cart_id, product_id, quantity) VALUES (%s, %s, %s)", 
                               (cart_id, product_id, initial_qty))

        conn.commit()
        summary = calculate_cart_summary(cursor, cart_id)
        summary["cart_id"] = cart_id
        return jsonify({"success": True, "cart": summary}), 200
    except Exception as e:
        conn.rollback()
        logging.error(f"Error syncing guest cart: {e}")
        return jsonify({"success": False, "error": "Failed to sync cart"}), 500
    finally:
        cursor.close()
        conn.close()
